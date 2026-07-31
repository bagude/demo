//! The Ledger: append-only evidence in state.
//!
//! Once a packet passes its Guard Laws, the Intake workflow appends it here as
//! a single JSON line. *Historical evidence is append-only* — the file is only
//! ever extended, never rewritten, so the record of what work was admitted and
//! when is durable. A status change is a new appended record, not an edit to an
//! old one.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::packet::IntakeRecord;

/// A handle to an append-only ledger file on disk.
pub struct Ledger {
    path: PathBuf,
}

impl Ledger {
    /// Open (without creating) a ledger at `path`.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Ledger { path: path.into() }
    }

    /// The default ledger location relative to the working directory.
    pub fn default_path() -> PathBuf {
        PathBuf::from(".intake").join("ledger.jsonl")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record as a JSON line, creating the file and any parent
    /// directory if needed. Opened strictly in append mode: existing evidence
    /// can never be overwritten through this handle.
    pub fn append(&self, record: &IntakeRecord) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut line = serde_json::to_string(record)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.flush()
    }

    /// Read every record in insertion order. A missing ledger reads as empty.
    pub fn read_all(&self) -> io::Result<Vec<IntakeRecord>> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut records = Vec::new();
        for (i, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: IntakeRecord = serde_json::from_str(&line).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: line {}: {}", self.path.display(), i + 1, e),
                )
            })?;
            records.push(record);
        }
        Ok(records)
    }

    /// Find the single record whose `task_id` begins with `prefix`.
    ///
    /// Returns `Err` on an ambiguous prefix so a short id can never silently
    /// resolve to the wrong packet.
    pub fn find(&self, prefix: &str) -> io::Result<Option<IntakeRecord>> {
        let mut matches: Vec<IntakeRecord> = self
            .read_all()?
            .into_iter()
            .filter(|r| r.task_id.starts_with(prefix))
            .collect();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(Some(matches.remove(0))),
            n => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("task id prefix '{prefix}' is ambiguous ({n} matches)"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{FileScope, Priority, TaskPacket};

    fn sample(objective: &str) -> IntakeRecord {
        let packet = TaskPacket {
            title: "t".into(),
            objective: objective.into(),
            constraints: vec![],
            files: vec![FileScope::write("a.rs")],
            acceptance_criteria: vec!["done".into()],
            submitted_by: "me".into(),
            priority: Priority::Medium,
        };
        IntakeRecord::new(packet, "2026-07-31T00:00:00Z".into())
    }

    #[test]
    fn append_then_read_roundtrips_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::at(dir.path().join("sub").join("ledger.jsonl"));
        let a = sample("first objective here");
        let b = sample("second objective here");
        ledger.append(&a).unwrap();
        ledger.append(&b).unwrap();

        let all = ledger.read_all().unwrap();
        assert_eq!(all, vec![a, b]);
    }

    #[test]
    fn missing_ledger_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::at(dir.path().join("nope.jsonl"));
        assert!(ledger.read_all().unwrap().is_empty());
    }

    #[test]
    fn find_by_unique_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::at(dir.path().join("ledger.jsonl"));
        let a = sample("first objective here");
        ledger.append(&a).unwrap();
        let found = ledger.find(&a.task_id[..6]).unwrap().unwrap();
        assert_eq!(found.task_id, a.task_id);
    }
}
