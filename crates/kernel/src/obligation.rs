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

/// Whether obligation `id` is currently open, given the full event stream.
pub fn is_open(events: &[Event], id: &str) -> bool {
    let open_t = open_transition(id);
    let close_t = discharge_transition(id);
    let mut open = false;
    for ev in events {
        if ev.transition == open_t {
            open = true;
        } else if ev.transition == close_t {
            open = false;
        }
    }
    open
}

/// Of the `required` obligation ids, those still outstanding.
pub fn outstanding(events: &[Event], required: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|id| is_open(events, id))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Decision;

    fn ev(transition: &str) -> Event {
        Event {
            run_id: "r".into(),
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
            playbook_ref: None,
            attempt_id: None,
        }
    }

    #[test]
    fn edit_opens_then_validation_discharges() {
        let id = "require-validation";
        let mut events = vec![ev(&open_transition(id))];
        assert!(is_open(&events, id));
        events.push(ev(&discharge_transition(id)));
        assert!(!is_open(&events, id));
    }

    #[test]
    fn an_edit_after_validation_reopens() {
        let id = "require-validation";
        let events = vec![
            ev(&open_transition(id)),
            ev(&discharge_transition(id)),
            ev(&open_transition(id)),
        ];
        assert!(is_open(&events, id));
    }

    #[test]
    fn outstanding_filters_to_open_only() {
        let events = vec![ev(&open_transition("require-validation"))];
        let required = vec!["require-validation".to_string(), "other".to_string()];
        assert_eq!(
            outstanding(&events, &required),
            vec!["require-validation".to_string()]
        );
    }
}
