//! The typed task packet — the only shape in which work is allowed to enter
//! the system.
//!
//! Per the Intake pattern: *"Work enters the system only as a typed artifact —
//! objective, constraints, files, acceptance criteria — never as loose
//! conversation."* This module defines that artifact and the metadata the
//! Intake workflow stamps onto it when it becomes evidence in state.

use serde::{Deserialize, Serialize};

/// Whether the workflow is authorized to read a scoped file or also to write
/// it. The set of `Write` paths is the contract a Guard Law enforces against
/// (*"only files listed in the task packet may be edited"*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    #[default]
    Read,
    Write,
}

/// A single file (or path prefix) brought into scope by the packet, together
/// with the authority granted over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileScope {
    pub path: String,
    #[serde(default)]
    pub access: Access,
}

impl FileScope {
    pub fn read(path: impl Into<String>) -> Self {
        FileScope {
            path: path.into(),
            access: Access::Read,
        }
    }

    pub fn write(path: impl Into<String>) -> Self {
        FileScope {
            path: path.into(),
            access: Access::Write,
        }
    }
}

/// Relative urgency of the work. Carried on the packet so that downstream
/// routing and scheduling can order work without re-reading the objective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

/// Lifecycle status of a recorded packet. The Intake workflow only ever
/// *records* a packet (`Open`); later transitions are made by whoever works
/// the packet and are appended as new evidence, never edited in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    Open,
    InProgress,
    Done,
    Rejected,
}

/// The typed task packet as authored by a submitter.
///
/// This is the intake *input*: the four named fields of the pattern
/// (objective, constraints, files, acceptance criteria) plus the minimal
/// provenance needed to hold someone accountable for the work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskPacket {
    /// A short human-readable name for the work.
    pub title: String,
    /// What done looks like, in prose. Must be specific enough to act on —
    /// this is the field that stops a packet from being "loose conversation".
    pub objective: String,
    /// Boundaries the work must respect. May be empty when a task genuinely
    /// has no special constraints.
    #[serde(default)]
    pub constraints: Vec<String>,
    /// The files brought into scope, with per-file authority. This list is the
    /// contract that Guard Laws enforce against.
    #[serde(default)]
    pub files: Vec<FileScope>,
    /// Mechanically checkable statements that must hold before the work is
    /// accepted. At least one is required.
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
    /// Who is handing this work in.
    pub submitted_by: String,
    #[serde(default)]
    pub priority: Priority,
    /// Explicit, auditable grant to amend enforcement artifacts (hooks,
    /// settings, kernel, the spec). A packet must set this *and* list the
    /// protected path in its write scope before the Guard will allow such an
    /// edit — enforcement is never an ambient capability. Default: false.
    #[serde(default)]
    pub amends_enforcement: bool,
}

impl TaskPacket {
    /// The paths this packet authorizes for writing.
    pub fn writable_paths(&self) -> impl Iterator<Item = &str> {
        self.files
            .iter()
            .filter(|f| f.access == Access::Write)
            .map(|f| f.path.as_str())
    }

    /// Whether `path` is authorized for writing by this packet.
    ///
    /// A scope entry authorizes `path` when it matches exactly, or when the
    /// scope entry ends in `/` and is a prefix of `path` (a directory grant).
    /// This is the primitive a Guard Law calls to decide whether an edit is
    /// inside the packet's contract.
    pub fn authorizes_write(&self, path: &str) -> bool {
        self.writable_paths().any(|scope| path_matches(scope, path))
    }
}

/// Returns true when `scope` grants authority over `path`: an exact match, or
/// a directory grant (`scope` ends in `/` and is a prefix of `path`).
pub(crate) fn path_matches(scope: &str, path: &str) -> bool {
    if scope == path {
        return true;
    }
    scope.ends_with('/') && path.starts_with(scope)
}

/// A validated task packet that has been admitted into state.
///
/// The Intake workflow produces exactly one of these per accepted submission
/// and appends it to the Ledger. `task_id` and `content_hash` bind the
/// evidence to the exact bytes that were validated, so a later reader can
/// prove nothing was substituted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntakeRecord {
    /// Short, stable identifier derived from `content_hash`.
    pub task_id: String,
    /// SHA-256 over the canonical bytes of `packet`.
    pub content_hash: String,
    /// When the packet was admitted, as an RFC 3339 UTC timestamp.
    pub recorded_at: String,
    #[serde(default)]
    pub status: Status,
    pub packet: TaskPacket,
}

impl IntakeRecord {
    /// Build a record for `packet`, computing its content hash and task id.
    /// `recorded_at` is injected so callers control the clock (and tests stay
    /// deterministic).
    pub fn new(packet: TaskPacket, recorded_at: String) -> Self {
        let content_hash = content_hash(&packet);
        let task_id = content_hash[..12].to_string();
        IntakeRecord {
            task_id,
            content_hash,
            recorded_at,
            status: Status::Open,
            packet,
        }
    }
}

/// SHA-256 over the packet's canonical JSON encoding.
///
/// Field order is fixed by the struct definition, so the same packet always
/// hashes to the same digest across runs and machines.
pub fn content_hash(packet: &TaskPacket) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(packet).expect("TaskPacket is always serializable");
    let digest = Sha256::digest(&bytes);
    hex(&digest)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_authority_matches_exact_and_directory() {
        let packet = TaskPacket {
            title: "t".into(),
            objective: "o".into(),
            constraints: vec![],
            files: vec![FileScope::write("src/lib.rs"), FileScope::write("docs/")],
            acceptance_criteria: vec!["x".into()],
            submitted_by: "me".into(),
            priority: Priority::Medium,
            amends_enforcement: false,
        };
        assert!(packet.authorizes_write("src/lib.rs"));
        assert!(packet.authorizes_write("docs/guide.md"));
        assert!(!packet.authorizes_write("src/main.rs"));
        assert!(!packet.authorizes_write("docs")); // not a directory grant match
    }

    #[test]
    fn read_scope_does_not_grant_write() {
        let packet = TaskPacket {
            title: "t".into(),
            objective: "o".into(),
            constraints: vec![],
            files: vec![FileScope::read("src/lib.rs")],
            acceptance_criteria: vec!["x".into()],
            submitted_by: "me".into(),
            priority: Priority::Medium,
            amends_enforcement: false,
        };
        assert!(!packet.authorizes_write("src/lib.rs"));
    }

    #[test]
    fn hash_is_stable_and_content_addressed() {
        let mk = || TaskPacket {
            title: "t".into(),
            objective: "o".into(),
            constraints: vec![],
            files: vec![],
            acceptance_criteria: vec!["x".into()],
            submitted_by: "me".into(),
            priority: Priority::Medium,
            amends_enforcement: false,
        };
        assert_eq!(content_hash(&mk()), content_hash(&mk()));

        let mut other = mk();
        other.objective = "different".into();
        assert_ne!(content_hash(&mk()), content_hash(&other));
    }
}
