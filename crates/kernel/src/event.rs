//! The Ledger: an append-only log of governed actions and externally relevant
//! decisions.
//!
//! Distinct from [`crate::ledger`], which stores admitted task packets. This is
//! the fine-grained execution history — tool calls, denials, approvals — that
//! no diff captures. It follows the spec's **minimum event envelope** so
//! records join across nested executors and resumptions, and the **secrecy
//! rule**: the envelope carries *references and hashes*, never raw payloads, so
//! an append-only log can never become a durable credential leak.
//!
//! **Tamper evidence.** "Append-only" was a posture (the file is opened in
//! append mode); the hash chain makes it a *property*. Every appended line is
//! a [`Record`]: the event plus a contiguous `seq` and a `prev` digest of the
//! previous line's exact bytes ([`CHAIN_GENESIS`] for the first).
//! [`EventLog::verify_chain`] then detects mutation, insertion, mid-deletion,
//! and reordering anywhere in the history — including a legacy prefix of
//! unchained records, which the first chained record's `prev` freezes. The one
//! thing a chain cannot prove is **tail truncation**: deleting the newest
//! records leaves a shorter but internally consistent chain. That requires
//! anchoring the chain *head* (the digest of the last line, reported by
//! `verify_chain`) somewhere outside the file. Gate checkpoints are the
//! first-class anchor: `kernel gate request --ledger` pins the head into the
//! durable checkpoint, and [`EventLog::verify_anchor`] is what `gate verify`
//! runs to refuse a log whose history no longer contains it. Any other
//! out-of-band home (a push, a signed note) works the same way.
//!
//! Concurrent appenders are not serialized by this handle; racing writers
//! produce a visible fork (duplicate `seq`, dangling `prev`) that
//! `verify_chain` reports rather than a silently merged history.

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
    /// The Playbook content digest that governed this run — the run binding.
    /// This is the *compiled interpretation* digest (source + compiler + IR +
    /// target), not merely the spec bytes, so the log proves which constitutional
    /// version was in force for each event: essential for overnight Gates and
    /// historical replay. Mandatory on every governed event this kernel writes
    /// (the generated hooks bake the digest in); an empty value is explicit
    /// historical/foreign state — a record written before run binding existed,
    /// or outside a compiled harness — never an ordinary governed event.
    #[serde(default)]
    pub playbook_ref: String,
    /// Content digest of the kernel implementation that *executed* this
    /// transition. A compiled harness identity (`playbook_ref`) is not a runtime
    /// identity: the same Playbook enforced by a different kernel binary is a
    /// different governed system. Every event this kernel writes carries its own
    /// identity, so the log records not just which spec governed but which
    /// enforcement binary ran. An empty value is explicit historical/foreign
    /// state — a record this kernel did not write.
    #[serde(default)]
    pub kernel_ref: String,
    /// One execution *attempt* of a logical action, distinct from `action_id`,
    /// for replay safety across retries and resumption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
}

/// The `prev` value of the first record in a chain — a sentinel, distinct
/// from every possible `sha256:` digest.
pub const CHAIN_GENESIS: &str = "genesis";

/// Digest of one serialized Ledger line — the unit the hash chain links.
pub fn line_digest(line: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(line.as_bytes());
    let mut s = String::from("sha256:");
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// One serialized Ledger line: an [`Event`] under the hash chain. `seq` and
/// `prev` are properties of the *log*, not of the event — they are assigned
/// at append time, and their integrity is what [`EventLog::verify_chain`]
/// proves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Position in the chain, contiguous from 0.
    pub seq: u64,
    /// Digest of the previous line's exact bytes; [`CHAIN_GENESIS`] for the
    /// first record.
    pub prev: String,
    #[serde(flatten)]
    pub event: Event,
}

/// Why a Ledger hash chain failed verification, and where.
#[derive(Debug)]
pub enum ChainError {
    Io(io::Error),
    Broken {
        line: usize,
        reason: String,
    },
    /// An externally anchored head names history the log no longer contains:
    /// the tail was truncated (or the whole log rewritten) past the anchor.
    /// This is the failure the chain alone cannot see — it exists only
    /// because something outside the file (a Gate checkpoint) kept the head.
    AnchorMissing {
        head: String,
    },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::Io(e) => write!(f, "io: {e}"),
            ChainError::Broken { line, reason } => write!(f, "line {line}: {reason}"),
            ChainError::AnchorMissing { head } => write!(
                f,
                "anchored head {head} is not in the ledger's history — the tail was truncated \
                 or the log rewritten since the anchor was taken"
            ),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<io::Error> for ChainError {
    fn from(e: io::Error) -> Self {
        ChainError::Io(e)
    }
}

/// The result of a successful chain walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    /// Total records in the log.
    pub records: usize,
    /// How many carry chain fields — the suffix after any legacy prefix.
    pub chained: usize,
    /// Digest of the final line — the chain **head**. Anchor it outside the
    /// file (a checkpoint, a push, a signed note): the chain proves everything
    /// except tail truncation, which only an out-of-band head can catch.
    pub head: Option<String>,
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

    /// Append one event as a chained [`Record`] line, creating the file and
    /// parent directory if needed. Opened strictly in append mode. The record
    /// carries the next contiguous `seq` and a `prev` digest of the last line
    /// — whatever kind of line that is, so a pre-chain (legacy) history is
    /// frozen under the chain the moment the first chained record lands.
    pub fn append(&self, event: &Event) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let (seq, prev) = self.chain_tail()?;
        let record = Record {
            seq,
            prev,
            event: event.clone(),
        };
        let mut line = serde_json::to_string(&record)
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

    /// The chain state the next record must carry: its `seq` and the digest of
    /// the current last line. An empty or missing log starts the chain at
    /// (0, [`CHAIN_GENESIS`]); a legacy (unchained) tail also restarts `seq`
    /// at 0 while `prev` commits to that tail's bytes.
    fn chain_tail(&self) -> io::Result<(u64, String)> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok((0, CHAIN_GENESIS.to_string()))
            }
            Err(e) => return Err(e),
        };
        let Some(last) = text.lines().rev().find(|l| !l.trim().is_empty()) else {
            return Ok((0, CHAIN_GENESIS.to_string()));
        };
        let seq = serde_json::from_str::<serde_json::Value>(last)
            .ok()
            .and_then(|v| v.get("seq").and_then(|s| s.as_u64()))
            .map(|s| s + 1)
            .unwrap_or(0);
        Ok((seq, line_digest(last)))
    }

    /// Walk the whole log and prove the chain: every chained record's `prev`
    /// must hash the exact line before it, and `seq` must be contiguous from
    /// 0. A legacy prefix of unchained records is admitted — and frozen, since
    /// the first chained record's `prev` commits to it — but an unchained
    /// record *after* chained history is a break. Returns the [`ChainReport`]
    /// whose `head` is what tail-truncation detection must anchor externally.
    pub fn verify_chain(&self) -> Result<ChainReport, ChainError> {
        self.walk().map(|(report, _)| report)
    }

    /// Verify the chain AND that `head` still names a line in history — the
    /// anchor check that closes the tail-truncation gap. Every line's bytes
    /// include its `prev`, so a line's digest transitively commits to the
    /// entire prefix before it: finding the anchored head among the line
    /// digests proves the history up to the anchor is byte-identical to when
    /// the anchor was taken. A missing head means the tail was truncated past
    /// it, or the log rewritten — refused either way.
    pub fn verify_anchor(&self, head: &str) -> Result<ChainReport, ChainError> {
        let (report, digests) = self.walk()?;
        if digests.iter().any(|d| d == head) {
            Ok(report)
        } else {
            Err(ChainError::AnchorMissing {
                head: head.to_string(),
            })
        }
    }

    /// The shared chain walk: proves the chain and collects every line's
    /// digest (for anchor membership checks).
    fn walk(&self) -> Result<(ChainReport, Vec<String>), ChainError> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok((
                    ChainReport {
                        records: 0,
                        chained: 0,
                        head: None,
                    },
                    Vec::new(),
                ))
            }
            Err(e) => return Err(ChainError::Io(e)),
        };
        let mut records = 0usize;
        let mut chained = 0usize;
        let mut prev_hash: Option<String> = None;
        let mut next_seq: Option<u64> = None;
        let mut digests: Vec<String> = Vec::new();
        for (i, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            let n = i + 1;
            records += 1;
            let v: serde_json::Value =
                serde_json::from_str(line).map_err(|e| ChainError::Broken {
                    line: n,
                    reason: format!("not valid JSON: {e}"),
                })?;
            let has_chain = v.get("seq").is_some() || v.get("prev").is_some();
            if !has_chain {
                if next_seq.is_some() {
                    return Err(ChainError::Broken {
                        line: n,
                        reason: "unchained record after chained history (insertion or rewrite)"
                            .into(),
                    });
                }
                // Legacy prefix: not self-verifying, but frozen — the first
                // chained record's prev commits to the last legacy line.
            } else {
                let seq =
                    v.get("seq")
                        .and_then(|s| s.as_u64())
                        .ok_or_else(|| ChainError::Broken {
                            line: n,
                            reason: "chained record has no valid seq".into(),
                        })?;
                let prev =
                    v.get("prev")
                        .and_then(|p| p.as_str())
                        .ok_or_else(|| ChainError::Broken {
                            line: n,
                            reason: "chained record has no prev digest".into(),
                        })?;
                let want_prev = prev_hash
                    .clone()
                    .unwrap_or_else(|| CHAIN_GENESIS.to_string());
                if prev != want_prev {
                    return Err(ChainError::Broken {
                        line: n,
                        reason: format!(
                            "prev-link mismatch: record claims {prev}, history hashes to \
                             {want_prev} (a preceding record was altered, removed, or reordered)"
                        ),
                    });
                }
                let want_seq = next_seq.unwrap_or(0);
                if seq != want_seq {
                    return Err(ChainError::Broken {
                        line: n,
                        reason: format!(
                            "sequence break: expected seq {want_seq}, found {seq} (a fork or \
                             splice)"
                        ),
                    });
                }
                next_seq = Some(seq + 1);
                chained += 1;
            }
            let digest = line_digest(line);
            digests.push(digest.clone());
            prev_hash = Some(digest);
        }
        Ok((
            ChainReport {
                records,
                chained,
                head: prev_hash,
            },
            digests,
        ))
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
            playbook_ref: "sha256:spec".into(),
            kernel_ref: "sha256:kernel".into(),
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
        assert_eq!(back.playbook_ref, "sha256:spec");
    }

    #[test]
    fn kernel_ref_binds_the_executing_binary_into_every_event() {
        // Runtime identity, not just compiled identity: the event records which
        // kernel executed it, and that field survives a serialization round-trip.
        let e = event(Decision::Allowed);
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"kernel_ref\":\"sha256:kernel\""));
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kernel_ref, "sha256:kernel");
    }

    #[test]
    fn a_legacy_record_without_run_binding_reads_as_explicit_empty() {
        // Absence is explicit historical state (a record written before run
        // binding existed, or by a foreign writer), not a deserialization
        // failure — both identity fields default to empty rather than hiding
        // behind an Option that reads like an ordinary governed event.
        let legacy = r#"{"run_id":"r","action_id":"a","actor":"kernel","timestamp":"t","transition":"pre_tool.edit","decision":"allowed"}"#;
        let back: Event = serde_json::from_str(legacy).unwrap();
        assert!(back.kernel_ref.is_empty());
        assert!(back.playbook_ref.is_empty());
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

    // ---- hash chain ---------------------------------------------------------

    fn chained_log(dir: &std::path::Path, n: usize) -> EventLog {
        let log = EventLog::at(dir.join("events.jsonl"));
        for _ in 0..n {
            log.append(&event(Decision::Allowed)).unwrap();
        }
        log
    }

    #[test]
    fn appended_records_form_a_verifiable_chain() {
        let dir = tempfile::tempdir().unwrap();
        let log = chained_log(dir.path(), 3);
        let report = log.verify_chain().unwrap();
        assert_eq!((report.records, report.chained), (3, 3));
        assert!(report.head.is_some(), "the head exists to be anchored");

        let text = std::fs::read_to_string(log.path()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].contains("\"seq\":0"));
        assert!(lines[0].contains(&format!("\"prev\":\"{CHAIN_GENESIS}\"")));
        assert!(lines[2].contains("\"seq\":2"));
        // read_all still consumes the events, chain fields and all.
        assert_eq!(log.read_all().unwrap().len(), 3);
    }

    #[test]
    fn tampering_a_middle_record_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let log = chained_log(dir.path(), 3);
        let text = std::fs::read_to_string(log.path()).unwrap();
        // Flip one decision in the middle record: same shape, different bytes.
        let lines: Vec<String> = text
            .lines()
            .enumerate()
            .map(|(i, l)| {
                if i == 1 {
                    l.replace("\"allowed\"", "\"denied\"")
                } else {
                    l.to_string()
                }
            })
            .collect();
        std::fs::write(log.path(), lines.join("\n") + "\n").unwrap();
        let err = log.verify_chain().unwrap_err();
        assert!(
            err.to_string().contains("line 3") && err.to_string().contains("prev-link"),
            "the record AFTER the tampered one exposes it: {err}"
        );
    }

    #[test]
    fn deleting_or_reordering_a_middle_record_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let log = chained_log(dir.path(), 3);
        let text = std::fs::read_to_string(log.path()).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        // Mid-deletion: splice out record 1.
        std::fs::write(log.path(), format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(log.verify_chain().is_err(), "mid-deletion is detected");

        // Reordering: swap records 0 and 1.
        std::fs::write(
            log.path(),
            format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]),
        )
        .unwrap();
        assert!(log.verify_chain().is_err(), "reordering is detected");
    }

    #[test]
    fn a_legacy_prefix_is_frozen_under_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let log = EventLog::at(dir.path().join("events.jsonl"));
        // A pre-chain record, written by an older kernel: a bare Event line.
        let legacy = serde_json::to_string(&event(Decision::Recorded)).unwrap();
        std::fs::write(log.path(), format!("{legacy}\n")).unwrap();

        log.append(&event(Decision::Allowed)).unwrap();
        log.append(&event(Decision::Denied)).unwrap();
        let report = log.verify_chain().unwrap();
        assert_eq!((report.records, report.chained), (3, 2));

        // The first chained record committed to the legacy line's bytes, so
        // even the pre-chain history cannot be silently rewritten.
        let text = std::fs::read_to_string(log.path()).unwrap();
        let tampered = text.replacen("\"recorded\"", "\"approved\"", 1);
        std::fs::write(log.path(), tampered).unwrap();
        let err = log.verify_chain().unwrap_err();
        assert!(
            err.to_string().contains("prev-link"),
            "legacy tampering surfaces at the first chained record: {err}"
        );
    }

    #[test]
    fn an_unchained_record_after_chained_history_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let log = chained_log(dir.path(), 1);
        // An appender that bypasses the chain (or a hand-inserted line).
        let bare = serde_json::to_string(&event(Decision::Allowed)).unwrap();
        let mut text = std::fs::read_to_string(log.path()).unwrap();
        text.push_str(&format!("{bare}\n"));
        std::fs::write(log.path(), text).unwrap();
        let err = log.verify_chain().unwrap_err();
        assert!(err.to_string().contains("unchained record"), "{err}");
    }

    #[test]
    fn verify_anchor_accepts_any_head_still_in_history() {
        let dir = tempfile::tempdir().unwrap();
        let log = chained_log(dir.path(), 2);
        let anchor = log.verify_chain().unwrap().head.unwrap();

        // The anchor holds at the moment it was taken...
        assert!(log.verify_anchor(&anchor).is_ok());
        // ...and stays valid as the log grows: a line's digest commits to the
        // whole prefix, so an older head is proof the history beneath it is
        // byte-identical.
        log.append(&event(Decision::Denied)).unwrap();
        assert!(log.verify_anchor(&anchor).is_ok());
    }

    #[test]
    fn verify_anchor_refuses_truncation_past_the_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let log = chained_log(dir.path(), 3);
        let anchor = log.verify_chain().unwrap().head.unwrap();

        // Truncate below the anchor: the remaining chain is internally
        // consistent — exactly the blind spot — but the anchor is gone.
        let text = std::fs::read_to_string(log.path()).unwrap();
        let truncated: Vec<&str> = text.lines().take(2).collect();
        std::fs::write(log.path(), truncated.join("\n") + "\n").unwrap();
        assert!(log.verify_chain().is_ok(), "the chain alone cannot see it");
        let err = log.verify_anchor(&anchor).unwrap_err();
        assert!(
            matches!(err, ChainError::AnchorMissing { .. }),
            "the anchor can: {err}"
        );
    }

    #[test]
    fn verify_anchor_still_reports_a_broken_chain_first() {
        let dir = tempfile::tempdir().unwrap();
        let log = chained_log(dir.path(), 3);
        let anchor = log.verify_chain().unwrap().head.unwrap();
        let text = std::fs::read_to_string(log.path()).unwrap();
        std::fs::write(log.path(), text.replacen("\"allowed\"", "\"denied\"", 1)).unwrap();
        let err = log.verify_anchor(&anchor).unwrap_err();
        assert!(matches!(err, ChainError::Broken { .. }), "{err}");
    }

    #[test]
    fn tail_truncation_is_visible_only_through_the_anchored_head() {
        // The chain's honest limitation, pinned as a test so it stays stated:
        // dropping the newest records leaves an internally consistent chain,
        // and only comparing heads against an external anchor exposes it.
        let dir = tempfile::tempdir().unwrap();
        let log = chained_log(dir.path(), 3);
        let full_head = log.verify_chain().unwrap().head.unwrap();

        let text = std::fs::read_to_string(log.path()).unwrap();
        let truncated: Vec<&str> = text.lines().take(2).collect();
        std::fs::write(log.path(), truncated.join("\n") + "\n").unwrap();

        let report = log.verify_chain().unwrap();
        assert_eq!(report.records, 2, "the chain itself still verifies");
        assert_ne!(
            report.head.unwrap(),
            full_head,
            "but the head no longer matches the anchored one"
        );
    }
}
