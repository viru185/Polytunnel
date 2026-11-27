//! A record of applied network changes, kept on disk so they can be undone after a crash.
//!
//! Each change is written to the journal *before* it is made, and removed after it is
//! reverted. On start, [`Journal::rollback`] reverts whatever a previous run left behind.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::plan::Change;
use crate::system::System;

pub struct Journal {
    path: PathBuf,
    applied: Vec<Change>,
}

impl Journal {
    /// Opens (or starts) the journal at `path`, keeping entries from an earlier run.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let applied = match fs::read_to_string(&path) {
            Ok(text) if !text.trim().is_empty() => serde_json::from_str(&text)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            Ok(_) => Vec::new(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(Journal { path, applied })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Changes currently recorded (oldest first).
    pub fn entries(&self) -> &[Change] {
        &self.applied
    }

    fn save(&self) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&self.applied)?)?;
        fs::rename(&tmp, &self.path)
    }

    /// Records `change`, then makes it. A change the system reports as already present is
    /// not ours to undo, so it is dropped from the journal again.
    pub fn apply(&mut self, system: &mut dyn System, change: Change) -> io::Result<()> {
        self.applied.push(change.clone());
        self.save()?;
        match system.apply(&change) {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.applied.pop();
                self.save()
            }
            Err(e) => {
                self.applied.pop();
                self.save()?;
                Err(e)
            }
        }
    }

    /// Applies every change in order; on failure, undoes what was done and returns the error.
    pub fn apply_all(&mut self, system: &mut dyn System, changes: Vec<Change>) -> io::Result<()> {
        for change in changes {
            if let Err(e) = self.apply(system, change) {
                let _ = self.rollback(system);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Reverts every recorded change, newest first. Keeps going after errors and returns
    /// the first one; changes that could not be reverted stay in the journal.
    pub fn rollback(&mut self, system: &mut dyn System) -> io::Result<()> {
        let mut first_error = None;
        let mut kept = Vec::new();
        while let Some(change) = self.applied.pop() {
            if let Err(e) = system.revert(&change) {
                first_error.get_or_insert(e);
                kept.push(change);
            }
        }
        kept.reverse();
        self.applied = kept;
        self.save()?;
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::plan::Via;

    #[derive(Default)]
    struct Fake {
        log: Vec<String>,
        fail_apply: Option<usize>,
        existing: Vec<String>,
        fail_revert: Vec<String>,
    }

    fn name(change: &Change) -> String {
        match change {
            Change::Route { prefix, .. } => prefix.to_string(),
            Change::Dns { .. } => "dns".into(),
        }
    }

    impl System for Fake {
        fn apply(&mut self, change: &Change) -> io::Result<bool> {
            if self.fail_apply == Some(self.log.len()) {
                return Err(io::Error::other("boom"));
            }
            if self.existing.contains(&name(change)) {
                return Ok(false);
            }
            self.log.push(format!("+{}", name(change)));
            Ok(true)
        }

        fn revert(&mut self, change: &Change) -> io::Result<()> {
            if self.fail_revert.contains(&name(change)) {
                return Err(io::Error::other("stuck"));
            }
            self.log.push(format!("-{}", name(change)));
            Ok(())
        }

        fn route_to(&self, _dest: IpAddr) -> io::Result<(Option<IpAddr>, u32)> {
            Ok((None, 1))
        }
    }

    fn route(s: &str) -> Change {
        Change::Route {
            prefix: s.parse().unwrap(),
            via: Via::Tunnel { if_index: 1 },
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("polytunnel-journal-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("journal.json")
    }

    #[test]
    fn survives_a_restart_and_rolls_back() {
        let path = temp("restart");
        let mut sys = Fake::default();
        let mut j = Journal::open(&path).unwrap();
        j.apply_all(
            &mut sys,
            vec![route("192.0.2.0/24"), route("198.51.100.0/24")],
        )
        .unwrap();
        drop(j); // "crash"

        let mut j = Journal::open(&path).unwrap();
        assert_eq!(j.entries().len(), 2);
        j.rollback(&mut sys).unwrap();
        assert!(j.entries().is_empty());
        assert_eq!(
            sys.log,
            [
                "+192.0.2.0/24",
                "+198.51.100.0/24",
                "-198.51.100.0/24",
                "-192.0.2.0/24"
            ]
        );
        assert!(Journal::open(&path).unwrap().entries().is_empty());
    }

    #[test]
    fn a_failure_undoes_the_earlier_changes() {
        let path = temp("failure");
        let mut sys = Fake {
            fail_apply: Some(1),
            ..Default::default()
        };
        let mut j = Journal::open(&path).unwrap();
        assert!(
            j.apply_all(
                &mut sys,
                vec![route("192.0.2.0/24"), route("198.51.100.0/24")]
            )
            .is_err()
        );
        assert_eq!(sys.log, ["+192.0.2.0/24", "-192.0.2.0/24"]);
        assert!(j.entries().is_empty());
    }

    #[test]
    fn pre_existing_routes_are_never_removed() {
        let path = temp("existing");
        let mut sys = Fake {
            existing: vec!["192.0.2.0/24".into()],
            ..Default::default()
        };
        let mut j = Journal::open(&path).unwrap();
        j.apply_all(
            &mut sys,
            vec![route("192.0.2.0/24"), route("198.51.100.0/24")],
        )
        .unwrap();
        assert_eq!(j.entries().len(), 1);
        j.rollback(&mut sys).unwrap();
        assert_eq!(sys.log, ["+198.51.100.0/24", "-198.51.100.0/24"]);
    }

    #[test]
    fn unrevertable_changes_stay_recorded() {
        let path = temp("stuck");
        let mut sys = Fake {
            fail_revert: vec!["192.0.2.0/24".into()],
            ..Default::default()
        };
        let mut j = Journal::open(&path).unwrap();
        j.apply_all(
            &mut sys,
            vec![route("192.0.2.0/24"), route("198.51.100.0/24")],
        )
        .unwrap();
        assert!(j.rollback(&mut sys).is_err());
        assert_eq!(j.entries(), &[route("192.0.2.0/24")]);
    }
}
