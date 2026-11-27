//! Repository tasks: `cargo xtask <task>` (the alias lives in `.cargo/config.toml`).
//!
//! Standard library only, so the tasks build fast and need nothing extra in CI.

mod lint_fixtures;

use std::process::ExitCode;

const USAGE: &str = "\
Usage: cargo xtask <task>

Tasks:
  lint-fixtures   Fail if test data contains real hostnames or IP addresses
";

fn main() -> ExitCode {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        Some("lint-fixtures") => lint_fixtures::run(),
        Some("-h" | "--help") | None => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("xtask: unknown task '{other}'\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
