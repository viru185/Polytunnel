//! Linux: `ip` for routes, `resolvectl` (systemd-resolved) for DNS.

use std::io;
use std::net::IpAddr;

use super::{System, args, if_index, if_name, route_already_gone, run};
use crate::plan::{Change, Via};

pub struct Linux;

fn route_args(add: bool, change: &Change) -> io::Result<Option<Vec<String>>> {
    let Change::Route { prefix, via } = change else {
        return Ok(None);
    };
    let (gateway, index) = match *via {
        Via::Tunnel { if_index } => (None, if_index),
        Via::Gateway { gateway, if_index } => (gateway, if_index),
    };
    Ok(Some(args::linux_route(
        add,
        prefix,
        gateway,
        &if_name(index)?,
    )))
}

impl System for Linux {
    fn apply(&mut self, change: &Change) -> io::Result<bool> {
        if let Some(args) = route_args(true, change)? {
            return match run("ip", &args) {
                Ok(_) => Ok(true),
                Err(e) if e.to_string().contains("File exists") => Ok(false),
                Err(e) => Err(e),
            };
        }
        if let Change::Dns {
            if_index,
            servers,
            domains,
            search,
        } = change
        {
            let name = if_name(*if_index)?;
            for args in args::linux_dns(&name, servers, domains, search) {
                run("resolvectl", &args)?;
            }
        }
        Ok(true)
    }

    fn revert(&mut self, change: &Change) -> io::Result<()> {
        if route_already_gone(change) {
            return Ok(());
        }
        if let Some(args) = route_args(false, change)? {
            return match run("ip", &args) {
                Ok(_) => Ok(()),
                Err(e) if e.to_string().contains("No such process") => Ok(()),
                Err(e) => Err(e),
            };
        }
        if let Change::Dns { if_index, .. } = change {
            // The interface may already be gone with the tunnel: nothing left to undo.
            if let Ok(name) = if_name(*if_index) {
                run("resolvectl", &["revert".into(), name])?;
            }
        }
        Ok(())
    }

    fn route_to(&self, dest: IpAddr) -> io::Result<(Option<IpAddr>, u32)> {
        let output = run(
            "ip",
            &["-j".into(), "route".into(), "get".into(), dest.to_string()],
        )?;
        let routes: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let route = routes
            .get(0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no route"))?;
        let gateway = route
            .get("gateway")
            .and_then(|g| g.as_str())
            .and_then(|g| g.parse().ok());
        let dev = route
            .get("dev")
            .and_then(|d| d.as_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "route without device"))?;
        Ok((gateway, if_index(dev)?))
    }
}
