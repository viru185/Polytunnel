//! `cargo xtask lint-fixtures`: keeps real network identifiers out of this public repository.
//!
//! Test data must only use names and addresses reserved for documentation, so nothing from a
//! real VPN deployment can slip into a fixture, a snapshot or a doc. This check works from an
//! allowlist, so the repository never has to contain the identifiers it guards against:
//!
//! * **Every tracked text file:** IPv4 addresses must be private, loopback, link-local,
//!   multicast, netmasks or in the documentation ranges 192.0.2.0/24, 198.51.100.0/24 and
//!   203.0.113.0/24.
//! * **Test data** (any path with a `tests`, `fixtures` or `testdata` directory): hostnames
//!   must end in `example.com`/`.net`/`.org`, `.example`, `.test`, `.invalid` or `.localhost`,
//!   and IPv6 addresses must be in 2001:db8::/32 (or loopback, link-local, unique-local,
//!   multicast). In `.rs` files only string literals are checked for hostnames, so field
//!   access like `self.state.width` is not mistaken for one.
//!
//! A line containing `lint-fixtures: allow` is skipped.

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::{Command, ExitCode};

const ALLOW_MARKER: &str = "lint-fixtures: allow";

/// Top-level domains that mark a token as a hostname even with only two labels. Includes the
/// private suffixes companies use internally, which must never appear in fixtures either.
const HOST_TLDS: &[&str] = &[
    "com",
    "net",
    "org",
    "io",
    "co",
    "in",
    "us",
    "uk",
    "de",
    "fr",
    "nl",
    "au",
    "ca",
    "jp",
    "cn",
    "ru",
    "br",
    "it",
    "es",
    "se",
    "ch",
    "eu",
    "gov",
    "edu",
    "mil",
    "int",
    "info",
    "biz",
    "app",
    "dev",
    "cloud",
    "ai",
    "me",
    "tv",
    "xyz",
    "site",
    "online",
    "tech",
    "corp",
    "local",
    "lan",
    "internal",
    "home",
    "intranet",
    "example",
    "test",
    "invalid",
    "localhost",
];

#[derive(Debug, PartialEq, Eq)]
struct Finding {
    line: usize,
    kind: &'static str,
    value: String,
}

pub fn run() -> ExitCode {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives inside the repository");
    let files = match repo_files(root) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("lint-fixtures: {e}");
            return ExitCode::from(2);
        }
    };

    let mut total = 0;
    for rel in &files {
        if rel == "Cargo.lock" {
            continue;
        }
        let Ok(bytes) = fs::read(root.join(rel)) else {
            continue; // deleted in the working tree but still in the index
        };
        if bytes.contains(&0) {
            continue; // binary
        }
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        for f in check_file(rel, &text) {
            println!(
                "{rel}:{}: {} `{}` is not a documentation value",
                f.line, f.kind, f.value
            );
            total += 1;
        }
    }

    if total == 0 {
        println!("lint-fixtures: {} files clean", files.len());
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "\nlint-fixtures: {total} finding(s). Use example.com hosts and 192.0.2.0/24, \
             198.51.100.0/24, 203.0.113.0/24 or 2001:db8::/32 addresses in test data \
             (or add `{ALLOW_MARKER}` to a line that really needs a public value)."
        );
        ExitCode::FAILURE
    }
}

/// Tracked files plus new files that are not ignored, relative to `root`.
fn repo_files(root: &Path) -> Result<Vec<String>, String> {
    let out = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let mut files: Vec<String> = out
        .stdout
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    files.sort();
    files.dedup();
    Ok(files)
}

fn is_test_data(rel: &str) -> bool {
    rel.split('/')
        .any(|part| matches!(part, "tests" | "fixtures" | "testdata"))
}

fn check_file(rel: &str, text: &str) -> Vec<Finding> {
    let test_data = is_test_data(rel);
    let rust = rel.ends_with(".rs");
    let mut findings = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.contains(ALLOW_MARKER) {
            continue;
        }
        let number = index + 1;
        for ip in ipv4_candidates(line) {
            if !ipv4_allowed(ip) {
                findings.push(Finding {
                    line: number,
                    kind: "IPv4 address",
                    value: ip.to_string(),
                });
            }
        }
        if !test_data {
            continue;
        }
        let host_text: Vec<String> = if rust {
            string_literals(line)
        } else {
            vec![line.to_string()]
        };
        for chunk in &host_text {
            for host in hostname_candidates(chunk) {
                if !host_allowed(&host) {
                    findings.push(Finding {
                        line: number,
                        kind: "hostname",
                        value: host,
                    });
                }
            }
            if !rust {
                for ip in ipv6_candidates(chunk) {
                    if !ipv6_allowed(ip) {
                        findings.push(Finding {
                            line: number,
                            kind: "IPv6 address",
                            value: ip.to_string(),
                        });
                    }
                }
            }
        }
    }
    findings
}

// ------------------------------------------------------------------------------ IPv4

fn ipv4_candidates(line: &str) -> Vec<Ipv4Addr> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        let mut run = &line[start..i];
        while run.ends_with('.') {
            run = &run[..run.len() - 1];
        }
        let before = start.checked_sub(1).map(|b| bytes[b]);
        let after = bytes.get(start + run.len()).copied();
        let glued = |c: Option<u8>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_');
        if glued(before) || before == Some(b'.') || glued(after) {
            continue; // part of a version, identifier or longer dotted sequence
        }
        let parts: Vec<&str> = run.split('.').collect();
        if parts.len() == 4
            && parts.iter().all(|p| (1..=3).contains(&p.len()))
            && let Ok(ip) = run.parse::<Ipv4Addr>()
        {
            out.push(ip);
        }
    }
    out
}

fn in_v4(ip: Ipv4Addr, net: [u8; 4], prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

fn ipv4_allowed(ip: Ipv4Addr) -> bool {
    let bits = u32::from(ip);
    let netmask = bits.leading_ones() + bits.trailing_zeros() == 32;
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 240
        || netmask
        || in_v4(ip, [100, 64, 0, 0], 10) // carrier-grade NAT
        || in_v4(ip, [192, 0, 2, 0], 24) // TEST-NET-1
        || in_v4(ip, [198, 51, 100, 0], 24) // TEST-NET-2
        || in_v4(ip, [203, 0, 113, 0], 24) // TEST-NET-3
        || in_v4(ip, [198, 18, 0, 0], 15) // benchmarking
}

// ------------------------------------------------------------------------------ IPv6

fn ipv6_candidates(text: &str) -> Vec<Ipv6Addr> {
    text.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.'))
        .map(|token| token.trim_matches('.'))
        .filter(|token| token.matches(':').count() >= 2)
        .filter_map(|token| token.parse::<Ipv6Addr>().ok())
        .collect()
}

fn ipv6_allowed(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    if let Some(v4) = ip.to_ipv4_mapped() {
        return ipv4_allowed(v4);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (seg[0] & 0xfe00) == 0xfc00 // unique local
        || (seg[0] & 0xffc0) == 0xfe80 // link-local
        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // documentation
}

// ------------------------------------------------------------------------------ hostnames

/// The contents of `"..."` literals on one line of Rust (escapes are skipped, not decoded).
fn string_literals(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut literal = String::new();
        let mut escaped = false;
        for c in chars.by_ref() {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                break;
            } else {
                literal.push(c);
            }
        }
        out.push(literal);
    }
    out
}

fn hostname_candidates(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        .map(|token| token.trim_matches(|c| c == '.' || c == '-'))
        .filter(|token| looks_like_host(token))
        .map(str::to_ascii_lowercase)
        .collect()
}

fn looks_like_host(token: &str) -> bool {
    let labels: Vec<&str> = token.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty() || l.len() > 63) {
        return false;
    }
    let tld = labels[labels.len() - 1].to_ascii_lowercase();
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    labels.len() >= 3 || HOST_TLDS.contains(&tld.as_str())
}

fn host_allowed(host: &str) -> bool {
    const SUFFIXES: &[&str] = &[".example", ".test", ".invalid", ".localhost"];
    const DOMAINS: &[&str] = &["example.com", "example.net", "example.org", "localhost"];
    SUFFIXES.iter().any(|s| host.ends_with(s))
        || DOMAINS
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a public address at run time, so this file never contains one literally.
    fn public_v4() -> String {
        format!("{}.{}.{}.{}", 8, 8, 4, 4)
    }

    /// A made-up corporate host, also built at run time.
    fn corp_host() -> String {
        ["vpn", "acme", "corp"].join(".")
    }

    #[test]
    fn documentation_and_private_ipv4_are_allowed() {
        for ip in [
            "192.0.2.10",
            "198.51.100.1",
            "203.0.113.254",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.0",
            "169.254.1.1",
            "224.0.0.1",
            "100.64.0.1",
        ] {
            assert!(ipv4_allowed(ip.parse().unwrap()), "{ip}");
        }
        assert!(!ipv4_allowed(public_v4().parse().unwrap()));
    }

    #[test]
    fn ipv4_candidates_skip_versions_and_identifiers() {
        let public = public_v4();
        assert_eq!(
            ipv4_candidates(&format!("gateway {public}, mask 255.255.255.0.")),
            vec![
                public.parse::<Ipv4Addr>().unwrap(),
                Ipv4Addr::new(255, 255, 255, 0)
            ]
        );
        assert!(ipv4_candidates("version 10.0.26300.1 and v1.2.3.4 and x1.2.3.4").is_empty());
        assert!(ipv4_candidates("999.1.1.1 1.2.3").is_empty());
    }

    #[test]
    fn public_ipv4_is_flagged_everywhere() {
        let text = format!("server = {}", public_v4());
        let findings = check_file("README.md", &text);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "IPv4 address");
        assert!(check_file("README.md", &format!("{text}  # {ALLOW_MARKER}")).is_empty());
    }

    #[test]
    fn hostnames_are_checked_only_in_test_data() {
        let line = format!("<entry name=\"{}\"/>", corp_host());
        assert!(check_file("docs/notes.md", &line).is_empty());
        let findings = check_file("crates/polytunnel-gp/tests/fixtures/portal.xml", &line);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "hostname");
        assert_eq!(findings[0].value, corp_host());
    }

    #[test]
    fn example_hosts_and_file_names_pass() {
        let text = "gw1.example.com portal.example.net vpn.test login.esp Cargo.toml \
                    polytunnel.service a.invalid localhost";
        assert!(check_file("tests/data.txt", text).is_empty());
    }

    #[test]
    fn rust_files_check_only_string_literals() {
        let code = "let w = self.state.width; let h = \"gw.example.com\";";
        assert!(check_file("crates/x/tests/t.rs", code).is_empty());
        let bad = format!("let h = \"{}\";", corp_host());
        assert_eq!(check_file("crates/x/tests/t.rs", &bad).len(), 1);
    }

    #[test]
    fn ipv6_documentation_prefix_is_required_in_test_data() {
        assert!(check_file("tests/a.xml", "addr 2001:db8::1 fe80::1 ::1").is_empty());
        let public = format!("{}:{}::{}", "2a00", "1450", "1");
        assert_eq!(check_file("tests/a.xml", &public).len(), 1);
        assert!(check_file("tests/a.xml", "time 12:30:45 mac aa:bb:cc:dd:ee:ff").is_empty());
    }

    #[test]
    fn string_literals_skip_escaped_quotes() {
        // An escaped quote does not end the literal; the escape itself is dropped.
        assert_eq!(
            string_literals(r#"f("a\"b", "c")"#),
            vec!["ab".to_string(), "c".to_string()]
        );
    }
}
