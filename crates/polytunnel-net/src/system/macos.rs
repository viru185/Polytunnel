//! macOS: `route` for routes, `scutil` for DNS resolvers (beta).

use std::io::{self, Write};
use std::net::IpAddr;
use std::process::{Command, Stdio};

use super::{System, args, if_index, if_name, route_already_gone, run};
use crate::plan::{Change, Via};

pub struct MacOs;

fn route_args(add: bool, change: &Change) -> io::Result<Option<Vec<String>>> {
    let Change::Route { prefix, via } = change else {
        return Ok(None);
    };
    let index = match *via {
        Via::Tunnel { if_index } | Via::Gateway { if_index, .. } => if_index,
    };
    Ok(Some(args::macos_route(add, prefix, via, &if_name(index)?)))
}

fn scutil(script: &str) -> io::Result<()> {
    let mut child = Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("no stdin"))?
        .write_all(script.as_bytes())?;
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("scutil failed"))
    }
}

fn dns_key(if_index: u32) -> String {
    format!("Polytunnel-{if_index}")
}

impl System for MacOs {
    fn apply(&mut self, change: &Change) -> io::Result<bool> {
        if let Some(args) = route_args(true, change)? {
            return match run("route", &args) {
                Ok(_) => Ok(true),
                Err(e) if e.to_string().contains("File exists") => Ok(false),
                Err(e) => Err(e),
            };
        }
        if let Change::Dns {
            if_index,
            servers,
            domains,
        } = change
        {
            scutil(&args::macos_dns_script(
                &dns_key(*if_index),
                servers,
                domains,
            ))?;
        }
        Ok(true)
    }

    fn revert(&mut self, change: &Change) -> io::Result<()> {
        if route_already_gone(change) {
            return Ok(());
        }
        if let Some(args) = route_args(false, change)? {
            return match run("route", &args) {
                Ok(_) => Ok(()),
                Err(e) if e.to_string().contains("not in table") => Ok(()),
                Err(e) => Err(e),
            };
        }
        if let Change::Dns { if_index, .. } = change {
            scutil(&format!(
                "remove State:/Network/Service/{}/DNS\nquit\n",
                dns_key(*if_index)
            ))?;
        }
        Ok(())
    }

    fn route_to(&self, dest: IpAddr) -> io::Result<(Option<IpAddr>, u32)> {
        let family = if dest.is_ipv4() { "-inet" } else { "-inet6" };
        let output = run(
            "route",
            &["-n".into(), "get".into(), family.into(), dest.to_string()],
        )?;
        let text = String::from_utf8_lossy(&output.stdout);
        let field = |name: &str| {
            text.lines().find_map(|line| {
                let (k, v) = line.split_once(':')?;
                (k.trim() == name).then(|| v.trim().to_string())
            })
        };
        let gateway = field("gateway").and_then(|g| g.parse().ok());
        let interface = field("interface")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no route"))?;
        Ok((gateway, if_index(&interface)?))
    }
}
