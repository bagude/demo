//! Guard Laws for intake.
//!
//! These are the deterministic checks that decide whether a submission is a
//! real task packet or just loose conversation wearing a struct. They run
//! *before* a packet is admitted to state, and they surface every problem at
//! once so a submitter can fix them in one pass rather than one at a time.
//!
//! Interpretation belongs in the model; mechanically decidable constraints
//! belong here, in code.

use std::fmt;

use crate::packet::TaskPacket;

/// The minimum length an objective must reach before it counts as a specific
/// statement of work rather than a placeholder.
const MIN_OBJECTIVE_LEN: usize = 12;

/// A single failed Guard Law, with a stable machine code and a human message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub code: &'static str,
    pub message: String,
}

impl Violation {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Violation {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// The outcome of validating a packet: either it is admissible, or it carries
/// a non-empty list of violations explaining why it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub violations: Vec<Violation>,
}

impl Report {
    pub fn is_ok(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Run every Guard Law against `packet` and collect all violations.
pub fn validate(packet: &TaskPacket) -> Report {
    let mut v = Vec::new();

    if packet.title.trim().is_empty() {
        v.push(Violation::new("title.empty", "title must not be empty"));
    }

    let objective = packet.objective.trim();
    if objective.is_empty() {
        v.push(Violation::new(
            "objective.empty",
            "objective must not be empty",
        ));
    } else if objective.chars().count() < MIN_OBJECTIVE_LEN {
        v.push(Violation::new(
            "objective.too_vague",
            format!(
                "objective must be at least {MIN_OBJECTIVE_LEN} characters; \
                 state specifically what done looks like"
            ),
        ));
    }

    if packet.submitted_by.trim().is_empty() {
        v.push(Violation::new(
            "submitted_by.empty",
            "submitted_by must name who is handing in the work",
        ));
    }

    if packet.acceptance_criteria.is_empty() {
        v.push(Violation::new(
            "acceptance_criteria.missing",
            "at least one acceptance criterion is required",
        ));
    }
    for (i, c) in packet.acceptance_criteria.iter().enumerate() {
        if c.trim().is_empty() {
            v.push(Violation::new(
                "acceptance_criteria.blank",
                format!("acceptance criterion #{} is blank", i + 1),
            ));
        }
    }

    if packet.files.is_empty() {
        v.push(Violation::new(
            "files.missing",
            "at least one file scope is required so Laws have a contract to enforce",
        ));
    }
    for (i, f) in packet.files.iter().enumerate() {
        if f.path.trim().is_empty() {
            v.push(Violation::new(
                "files.blank_path",
                format!("file scope #{} has an empty path", i + 1),
            ));
        }
    }
    if let Some(dup) = first_duplicate(packet.files.iter().map(|f| f.path.as_str())) {
        v.push(Violation::new(
            "files.duplicate_path",
            format!("file scope path '{dup}' is listed more than once"),
        ));
    }

    for (i, c) in packet.constraints.iter().enumerate() {
        if c.trim().is_empty() {
            v.push(Violation::new(
                "constraints.blank",
                format!("constraint #{} is blank", i + 1),
            ));
        }
    }

    Report { violations: v }
}

/// Return the first value that appears more than once, in first-seen order.
fn first_duplicate<'a>(items: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let mut seen = Vec::new();
    for item in items {
        if seen.contains(&item) {
            return Some(item);
        }
        seen.push(item);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{FileScope, Priority};

    fn valid() -> TaskPacket {
        TaskPacket {
            title: "Fix null id migration".into(),
            objective: "Ensure the 0007 migration does not drop rows with null ids".into(),
            constraints: vec!["No schema changes outside migrations/".into()],
            files: vec![FileScope::write("migrations/0007.sql")],
            acceptance_criteria: vec!["Row count is preserved after migrating".into()],
            submitted_by: "alice".into(),
            priority: Priority::High,
            amends_enforcement: false,
        }
    }

    #[test]
    fn a_complete_packet_passes() {
        assert!(validate(&valid()).is_ok());
    }

    #[test]
    fn vague_objective_is_rejected() {
        let mut p = valid();
        p.objective = "fix it".into();
        let report = validate(&p);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == "objective.too_vague"));
    }

    #[test]
    fn missing_acceptance_criteria_is_rejected() {
        let mut p = valid();
        p.acceptance_criteria.clear();
        let report = validate(&p);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == "acceptance_criteria.missing"));
    }

    #[test]
    fn missing_files_is_rejected() {
        let mut p = valid();
        p.files.clear();
        let report = validate(&p);
        assert!(report.violations.iter().any(|v| v.code == "files.missing"));
    }

    #[test]
    fn duplicate_file_paths_are_rejected() {
        let mut p = valid();
        p.files = vec![FileScope::write("a.rs"), FileScope::read("a.rs")];
        let report = validate(&p);
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == "files.duplicate_path"));
    }

    #[test]
    fn all_violations_surface_at_once() {
        let empty = TaskPacket {
            title: String::new(),
            objective: String::new(),
            constraints: vec![],
            files: vec![],
            acceptance_criteria: vec![],
            submitted_by: String::new(),
            priority: Priority::Medium,
            amends_enforcement: false,
        };
        let report = validate(&empty);
        // title, objective, submitted_by, acceptance_criteria, files
        assert!(report.violations.len() >= 5);
    }
}
