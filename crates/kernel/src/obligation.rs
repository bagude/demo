//! Obligation tracking derived from the Ledger.
//!
//! An Obligation Law ("every edit is followed by the test suite") records that
//! something is *owed*. On its own that is just a note. It becomes enforcement
//! only when a Gate refuses to proceed while the obligation is open. This module
//! computes, from the append-only event stream, which obligations are currently
//! outstanding — the input the Gate consults before it will approve or resume.
//!
//! The state machine per obligation id is deliberately simple and matches the
//! pattern's promise: an edit *opens* the obligation, a validation *discharges*
//! it, and any edit after the last validation re-opens it.

use crate::event::Event;

/// The transition string recorded when an obligation is opened after an edit.
pub fn open_transition(id: &str) -> String {
    format!("post_tool.obligation.{id}")
}

/// The transition string recorded when an obligation is discharged.
pub fn discharge_transition(id: &str) -> String {
    format!("obligation.discharge.{id}")
}

/// Whether obligation `id` is currently open **within run `run_id`**.
///
/// Obligations are scoped to a run: an edit in run A opening an obligation is
/// not discharged by a validation in run B. Only events whose `run_id` matches
/// are considered, so concurrent or historical runs cannot satisfy each other's
/// obligations.
pub fn is_open(events: &[Event], id: &str, run_id: &str) -> bool {
    let open_t = open_transition(id);
    let close_t = discharge_transition(id);
    let mut open = false;
    for ev in events {
        if ev.run_id != run_id {
            continue;
        }
        if ev.transition == open_t {
            open = true;
        } else if ev.transition == close_t {
            open = false;
        }
    }
    open
}

/// Of the `required` obligation ids, those still outstanding within `run_id`.
pub fn outstanding(events: &[Event], required: &[String], run_id: &str) -> Vec<String> {
    required
        .iter()
        .filter(|id| is_open(events, id, run_id))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Decision;

    fn ev_run(transition: &str, run_id: &str) -> Event {
        Event {
            run_id: run_id.into(),
            task_id: None,
            parent_task_id: None,
            action_id: "a".into(),
            actor: "kernel".into(),
            timestamp: "2026-07-31T00:00:00Z".into(),
            transition: transition.into(),
            input_refs: vec![],
            output_refs: vec![],
            decision: Decision::Recorded,
            evidence_refs: vec![],
            playbook_ref: String::new(),
            kernel_ref: String::new(),
            attempt_id: None,
        }
    }

    fn ev(transition: &str) -> Event {
        ev_run(transition, "r")
    }

    #[test]
    fn edit_opens_then_validation_discharges() {
        let id = "require-validation";
        let mut events = vec![ev(&open_transition(id))];
        assert!(is_open(&events, id, "r"));
        events.push(ev(&discharge_transition(id)));
        assert!(!is_open(&events, id, "r"));
    }

    #[test]
    fn an_edit_after_validation_reopens() {
        let id = "require-validation";
        let events = vec![
            ev(&open_transition(id)),
            ev(&discharge_transition(id)),
            ev(&open_transition(id)),
        ];
        assert!(is_open(&events, id, "r"));
    }

    #[test]
    fn outstanding_filters_to_open_only() {
        let events = vec![ev(&open_transition("require-validation"))];
        let required = vec!["require-validation".to_string(), "other".to_string()];
        assert_eq!(
            outstanding(&events, &required, "r"),
            vec!["require-validation".to_string()]
        );
    }

    #[test]
    fn one_runs_discharge_does_not_clear_anothers_obligation() {
        let id = "require-validation";
        // Run A opens the obligation; run B discharges its own.
        let events = vec![
            ev_run(&open_transition(id), "run-A"),
            ev_run(&discharge_transition(id), "run-B"),
        ];
        // Run A is still on the hook; run B has nothing outstanding.
        assert!(is_open(&events, id, "run-A"));
        assert!(!is_open(&events, id, "run-B"));
    }
}
