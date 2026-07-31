//! The Intake workflow: the one door through which work is allowed to enter.
//!
//! `admit` is the whole pattern in one function — run the Guard Laws over a
//! typed packet, and only if they all pass turn it into an [`IntakeRecord`]
//! that can be appended to the Ledger. There is deliberately no path that
//! records an unvalidated packet.

use crate::packet::{IntakeRecord, TaskPacket};
use crate::validate::{validate, Report};

/// Why a packet was refused admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitError {
    /// The packet failed one or more Guard Laws.
    Invalid(Report),
}

impl std::fmt::Display for AdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmitError::Invalid(report) => {
                writeln!(
                    f,
                    "packet rejected: {} violation(s)",
                    report.violations.len()
                )?;
                for v in &report.violations {
                    writeln!(f, "  - {v}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for AdmitError {}

/// Validate `packet` and, if it is admissible, produce the record to record.
///
/// This does not touch the Ledger; the caller decides where the returned
/// record is appended. Keeping admission and persistence separate lets the
/// same logic serve a dry-run `validate` command and a real `submit` command.
pub fn admit(packet: &TaskPacket, recorded_at: String) -> Result<IntakeRecord, AdmitError> {
    let report = validate(packet);
    if !report.is_ok() {
        return Err(AdmitError::Invalid(report));
    }
    Ok(IntakeRecord::new(packet.clone(), recorded_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{FileScope, Priority};

    fn valid() -> TaskPacket {
        TaskPacket {
            title: "Fix null id migration".into(),
            objective: "Ensure migration 0007 does not drop rows with null ids".into(),
            constraints: vec![],
            files: vec![FileScope::write("migrations/0007.sql")],
            acceptance_criteria: vec!["Row count is preserved".into()],
            submitted_by: "alice".into(),
            priority: Priority::High,
        }
    }

    #[test]
    fn admits_a_valid_packet() {
        let record = admit(&valid(), "2026-07-31T00:00:00Z".into()).unwrap();
        assert_eq!(record.recorded_at, "2026-07-31T00:00:00Z");
        assert_eq!(record.task_id.len(), 12);
    }

    #[test]
    fn refuses_an_invalid_packet() {
        let mut p = valid();
        p.acceptance_criteria.clear();
        let err = admit(&p, "2026-07-31T00:00:00Z".into()).unwrap_err();
        let AdmitError::Invalid(report) = err;
        assert!(report
            .violations
            .iter()
            .any(|v| v.code == "acceptance_criteria.missing"));
    }
}
