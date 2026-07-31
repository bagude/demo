//! Guard Law evaluation.
//!
//! A Guard Law rejects an invalid proposed transition *before* execution. The
//! canonical example from the spec is *"only files listed in the task packet
//! may be edited"* — the packet's write-scope is the contract, and this module
//! is the deterministic code that enforces it. The model proposes; the kernel
//! disposes.

use crate::packet::TaskPacket;

/// The verdict of a Guard Law on a proposed transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LawDecision {
    /// The transition is within contract and may proceed.
    Allow,
    /// The transition is rejected, with a human-readable reason.
    Deny(String),
}

impl LawDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, LawDecision::Allow)
    }

    /// The rejection reason, if this is a denial.
    pub fn reason(&self) -> Option<&str> {
        match self {
            LawDecision::Allow => None,
            LawDecision::Deny(r) => Some(r),
        }
    }
}

/// `enforce-file-scope`: a write to `path` is allowed only if the active task
/// packet lists `path` with write authority. This is the Guard Law that makes
/// "Verb within Law" real — the Verb runs, but every edit it proposes is
/// checked against the packet it was handed.
pub fn enforce_file_scope(packet: &TaskPacket, path: &str) -> LawDecision {
    if packet.authorizes_write(path) {
        LawDecision::Allow
    } else {
        LawDecision::Deny(format!(
            "'{path}' is not in the write scope of task packet '{}'; \
             only files the packet lists with access = \"write\" may be edited",
            packet.title
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{FileScope, Priority};

    fn packet() -> TaskPacket {
        TaskPacket {
            title: "scoped".into(),
            objective: "do the scoped thing".into(),
            constraints: vec![],
            files: vec![
                FileScope::write("src/lib.rs"),
                FileScope::read("src/other.rs"),
            ],
            acceptance_criteria: vec!["ok".into()],
            submitted_by: "me".into(),
            priority: Priority::Medium,
        }
    }

    #[test]
    fn allows_a_write_scoped_path() {
        assert!(enforce_file_scope(&packet(), "src/lib.rs").is_allowed());
    }

    #[test]
    fn denies_a_read_only_path() {
        let d = enforce_file_scope(&packet(), "src/other.rs");
        assert!(!d.is_allowed());
        assert!(d.reason().unwrap().contains("write scope"));
    }

    #[test]
    fn denies_an_unlisted_path() {
        assert!(!enforce_file_scope(&packet(), "src/secret.rs").is_allowed());
    }
}
