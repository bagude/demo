//! The Ledger: an append-only log of governed actions and externally relevant
//! decisions.
//!
//! Distinct from [`crate::ledger`], which stores admitted task packets. This is
//! the fine-grained execution history — tool calls, denials, approvals — that
//! no diff captures. It follows the spec's **minimum event envelope** so
//! records join across nested executors and resumptions, and the **secrecy
//! rule**: the envelope carries *references and hashes*, never raw payloads, so
//! an append-only log can never become a durable credential leak.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The outcome recorded for a governed transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// A Guard Law permitted the proposed transition.
    Allowed,
    /// A Guard Law rejected the proposed transition.
    Denied,
    /// A Gate approval was granted.
    Approved,
    /// A Gate approval was refused or invalidated.
    Rejected,
    /// Evidence was recorded (no allow/deny semantics).
    Recorded,
}

/// One entry in the Ledger. Fields mirror the spec's minimum event envelope.
///
/// Note what is *absent*: there is no field for raw tool input or model
/// context. Inputs and outputs are named by reference or hash only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Correlates every event in a single run.
    pub run_id: String,
    /// The task packet this action serves, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// The parent task, for events emitted inside a nested executor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_task_id: Option<String>,
    /// Unique id for this action within the run.
    pub action_id: String,
    /// Who or what took the action (e.g. `model`, `kernel`, an approver).
    pub actor: String,
    /// RFC 3339 UTC timestamp.
    pub timestamp: String,
    /// The kind of transition, e.g. `pre_tool.edit`, `gate.approve`.
    pub transition: String,
    /// References or hashes of inputs — never the inputs themselves.
    #[serde(default)]
    pub input_refs: Vec<String>,
    /// References or hashes of outputs.
    #[serde(default)]
    pub output_refs: Vec<String>,
    /// The decision recorded for this transition.
    pub decision: Decision,
    /// References to supporting evidence artifacts.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// The Playbook (spec) content digest that governed this run — the run
    /// binding. Lets the log prove which constitutional version was in force
    /// for each event, essential for overnight Gates and historical replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub playbook_ref: Option<String>,
    /// One execution *attempt* of a logical action, distinct from `action_id`,
    /// for replay safety across retries and resumption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
}

impl Event {
    /// Set the run-binding digest (fluent; used by the CLI after construction).
    pub fn with_playbook_ref(mut self, playbook_ref: Option<String>) -> Self {
        self.playbook_ref = playbook_ref;
        self
    }
}

/// A handle to an append-only event log file (JSON lines).
pub struct EventLog {
    path: PathBuf,
}

impl EventLog {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        EventLog { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one event as a JSON line, creating the file and parent directory
    /// if needed. Opened strictly in append mode.
    pub fn append(&self, event: &Event) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut line = serde_json::to_string(event)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.flush()?;
        // Durably persist the appended record so a host failure cannot lose an
        // already-acknowledged governed event.
        file.sync_all()
    }

    /// Read every event in insertion order. A missing log reads as empty.
    pub fn read_all(&self) -> io::Result<Vec<Event>> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut events = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event: Event = serde_json::from_str(&line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            events.push(event);
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(decision: Decision) -> Event {
        Event {
            run_id: "run-1".into(),
            task_id: Some("72912a5ae0e8".into()),
            parent_task_id: None,
            action_id: "a1".into(),
            actor: "kernel".into(),
            timestamp: "2026-07-31T00:00:00Z".into(),
            transition: "pre_tool.edit".into(),
            input_refs: vec!["sha256:abc".into()],
            output_refs: vec![],
            decision,
            evidence_refs: vec![],
            playbook_ref: Some("sha256:spec".into()),
            attempt_id: None,
        }
    }

    #[test]
    fn append_then_read_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let log = EventLog::at(dir.path().join("events.jsonl"));
        log.append(&event(Decision::Allowed)).unwrap();
        log.append(&event(Decision::Denied)).unwrap();
        let all = log.read_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].decision, Decision::Denied);
    }

    #[test]
    fn playbook_ref_roundtrips_as_run_binding() {
        let e = event(Decision::Allowed);
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"playbook_ref\":\"sha256:spec\""));
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back.playbook_ref.as_deref(), Some("sha256:spec"));
    }

    #[test]
    fn envelope_has_no_raw_payload_field() {
        // Guard against regression: serialize and confirm the shape only ever
        // carries refs/hashes, matching the secrecy rule.
        let json = serde_json::to_string(&event(Decision::Allowed)).unwrap();
        assert!(json.contains("input_refs"));
        assert!(!json.contains("raw_input"));
        assert!(!json.contains("payload"));
    }
}
