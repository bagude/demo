//! Obligation tracking derived from the Ledger, at a **declared scope**.
//!
//! An Obligation Law ("every edit is followed by the test suite") records that
//! something is *owed*. On its own that is just a note. It becomes enforcement
//! only when a Gate refuses to proceed while the obligation is open. This
//! module computes, from the append-only event stream, which obligations are
//! currently outstanding — the input the Gate consults before it will approve
//! or resume.
//!
//! The state machine per obligation is deliberately simple: an edit *opens*
//! it, a validation *discharges* it, an edit after the last validation
//! re-opens it. What the spec now **declares** — instead of the kernel
//! assuming — is the scope that debt lives at:
//!
//! - `run` — opened and discharged within one run (the default, and the old
//!   behavior); run A's edit is never cleared by run B's validation.
//! - `task` — follows the task packet across runs, keyed by the packet's
//!   content digest.
//! - `branch` — follows the git branch the work happened on.
//! - `workspace` — global: any open debt blocks everyone until discharged.
//! - `action` — per edited path: every touched file owes its own validation.
//!
//! **Fail-safe rule:** a debt that cannot be *proven* discharged for the
//! current context blocks. If the evaluating context lacks the key a scope
//! needs (no task packet at hand, no branch), or an event lacks the key its
//! scope reads (a legacy record), the obligation counts as outstanding rather
//! than silently passing.

use std::collections::{BTreeMap, BTreeSet};

use crate::event::Event;

/// The transition string recorded when an obligation is opened after an edit.
pub fn open_transition(id: &str) -> String {
    format!("post_tool.obligation.{id}")
}

/// The transition string recorded when an obligation is discharged.
pub fn discharge_transition(id: &str) -> String {
    format!("obligation.discharge.{id}")
}

/// The scope an obligation's debt lives at. Mirrors the spec's declared
/// `scope` on an Obligation Law; the kernel cannot depend on the spec crate,
/// so the vocabulary is duplicated here and joined by the generated hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Run,
    Task,
    Branch,
    Workspace,
    Action,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Scope> {
        match s {
            "run" => Some(Scope::Run),
            "task" => Some(Scope::Task),
            "branch" => Some(Scope::Branch),
            "workspace" => Some(Scope::Workspace),
            "action" => Some(Scope::Action),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Run => "run",
            Scope::Task => "task",
            Scope::Branch => "branch",
            Scope::Workspace => "workspace",
            Scope::Action => "action",
        }
    }
}

/// The evaluating side's identity: which run, task, and branch is asking
/// "am I clear to proceed?". Fields the caller cannot produce stay `None`,
/// and the fail-safe rule makes their absence block rather than pass.
#[derive(Debug, Clone, Default)]
pub struct ScopeContext {
    pub run_id: String,
    /// The active task packet's content digest, when a packet is at hand.
    pub task_key: Option<String>,
    /// The current git branch, when one can be determined.
    pub branch: Option<String>,
}

/// Parse a Gate requirement as the generated hooks encode it: `id` (run
/// scope) or `id:scope`. An unknown scope suffix is an error the caller must
/// surface — a misconfigured requirement must never silently pass.
pub fn parse_requirement(s: &str) -> Result<(&str, Scope), String> {
    match s.split_once(':') {
        None => Ok((s, Scope::Run)),
        Some((id, scope)) => Scope::parse(scope)
            .map(|sc| (id, sc))
            .ok_or_else(|| format!("requirement '{s}' names unknown scope '{scope}'")),
    }
}

/// The sentinel bucket for events that lack the key their scope reads. Only a
/// similarly unkeyed discharge clears it — fail-safe by construction.
const UNKEYED: &str = "(unkeyed)";

/// The scope key an event contributes under `scope`, read from the envelope:
/// `run_id` for run, `task_id` for task, a `branch:` input ref for branch, a
/// `path:` input ref for action, a constant for workspace.
fn event_scope_key(ev: &Event, scope: Scope) -> Option<String> {
    match scope {
        Scope::Run => Some(ev.run_id.clone()),
        Scope::Workspace => Some("workspace".to_string()),
        Scope::Task => ev.task_id.clone(),
        Scope::Branch => ev
            .input_refs
            .iter()
            .find_map(|r| r.strip_prefix("branch:").map(String::from)),
        Scope::Action => ev
            .input_refs
            .iter()
            .find_map(|r| r.strip_prefix("path:").map(String::from)),
    }
}

/// The scope keys of `id`'s obligation that remain open under `scope`.
fn open_keys(events: &[Event], id: &str, scope: Scope) -> BTreeSet<String> {
    let open_t = open_transition(id);
    let close_t = discharge_transition(id);
    let mut state: BTreeMap<String, bool> = BTreeMap::new();
    for ev in events {
        let opens = if ev.transition == open_t {
            true
        } else if ev.transition == close_t {
            false
        } else {
            continue;
        };
        let key = event_scope_key(ev, scope).unwrap_or_else(|| UNKEYED.to_string());
        state.insert(key, opens);
    }
    state
        .into_iter()
        .filter_map(|(k, open)| open.then_some(k))
        .collect()
}

/// Whether obligation `id` is outstanding for `ctx` under `scope`.
pub fn is_outstanding(events: &[Event], id: &str, scope: Scope, ctx: &ScopeContext) -> bool {
    let open = open_keys(events, id, scope);
    if open.is_empty() {
        return false;
    }
    // An unkeyed open debt blocks every context: it cannot be attributed, so
    // it cannot be proven to be someone else's.
    if open.contains(UNKEYED) {
        return true;
    }
    match scope {
        Scope::Run => open.contains(&ctx.run_id),
        // Global and per-path debts block regardless of who is asking.
        Scope::Workspace | Scope::Action => true,
        Scope::Task => ctx.task_key.as_ref().is_none_or(|k| open.contains(k)),
        Scope::Branch => ctx.branch.as_ref().is_none_or(|b| open.contains(b)),
    }
}

/// Back-compat convenience: run-scoped openness for a bare run id.
pub fn is_open(events: &[Event], id: &str, run_id: &str) -> bool {
    is_outstanding(
        events,
        id,
        Scope::Run,
        &ScopeContext {
            run_id: run_id.to_string(),
            ..Default::default()
        },
    )
}

/// Of the `required` entries (each `id` or `id:scope`), those still
/// outstanding for `ctx`. An entry whose scope fails to parse is reported
/// outstanding — a misconfigured requirement never silently passes.
pub fn outstanding(events: &[Event], required: &[String], ctx: &ScopeContext) -> Vec<String> {
    required
        .iter()
        .filter(|entry| match parse_requirement(entry) {
            Ok((id, scope)) => is_outstanding(events, id, scope, ctx),
            Err(_) => true,
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Decision;

    fn ev_full(
        transition: &str,
        run_id: &str,
        task_id: Option<&str>,
        input_refs: Vec<String>,
    ) -> Event {
        Event {
            run_id: run_id.into(),
            task_id: task_id.map(String::from),
            parent_task_id: None,
            action_id: "a".into(),
            actor: "kernel".into(),
            timestamp: "2026-07-31T00:00:00Z".into(),
            transition: transition.into(),
            input_refs,
            output_refs: vec![],
            decision: Decision::Recorded,
            evidence_refs: vec![],
            playbook_ref: String::new(),
            kernel_ref: String::new(),
            attempt_id: None,
        }
    }

    fn ev_run(transition: &str, run_id: &str) -> Event {
        ev_full(transition, run_id, None, vec![])
    }

    fn ev(transition: &str) -> Event {
        ev_run(transition, "r")
    }

    fn ctx(run_id: &str) -> ScopeContext {
        ScopeContext {
            run_id: run_id.into(),
            ..Default::default()
        }
    }

    const ID: &str = "require-validation";

    #[test]
    fn edit_opens_then_validation_discharges() {
        let mut events = vec![ev(&open_transition(ID))];
        assert!(is_open(&events, ID, "r"));
        events.push(ev(&discharge_transition(ID)));
        assert!(!is_open(&events, ID, "r"));
    }

    #[test]
    fn an_edit_after_validation_reopens() {
        let events = vec![
            ev(&open_transition(ID)),
            ev(&discharge_transition(ID)),
            ev(&open_transition(ID)),
        ];
        assert!(is_open(&events, ID, "r"));
    }

    #[test]
    fn outstanding_filters_to_open_only() {
        let events = vec![ev(&open_transition(ID))];
        let required = vec![ID.to_string(), "other".to_string()];
        assert_eq!(outstanding(&events, &required, &ctx("r")), vec![ID]);
    }

    #[test]
    fn one_runs_discharge_does_not_clear_anothers_obligation() {
        // Run scope, the default: run A opens; run B discharges its own.
        let events = vec![
            ev_run(&open_transition(ID), "run-A"),
            ev_run(&discharge_transition(ID), "run-B"),
        ];
        assert!(is_open(&events, ID, "run-A"));
        assert!(!is_open(&events, ID, "run-B"));
    }

    #[test]
    fn workspace_scope_blocks_and_clears_across_runs() {
        // Run A's edit blocks run B...
        let mut events = vec![ev_run(&open_transition(ID), "run-A")];
        assert!(is_outstanding(&events, ID, Scope::Workspace, &ctx("run-B")));
        // ...and run B's validation clears it for everyone.
        events.push(ev_run(&discharge_transition(ID), "run-B"));
        assert!(!is_outstanding(
            &events,
            ID,
            Scope::Workspace,
            &ctx("run-A")
        ));
    }

    #[test]
    fn task_scope_follows_the_packet_not_the_run() {
        let open = ev_full(&open_transition(ID), "run-A", Some("sha256:taskX"), vec![]);
        let close = ev_full(
            &discharge_transition(ID),
            "run-B",
            Some("sha256:taskX"),
            vec![],
        );
        let mut c = ctx("run-C");
        c.task_key = Some("sha256:taskX".into());
        // Same task discharged in a different run: clear.
        assert!(!is_outstanding(&[open.clone(), close], ID, Scope::Task, &c));
        // A different task's context is unaffected by X's debt...
        let mut other = ctx("run-C");
        other.task_key = Some("sha256:taskY".into());
        assert!(!is_outstanding(
            std::slice::from_ref(&open),
            ID,
            Scope::Task,
            &other
        ));
        // ...but a context that cannot name its task fails safe.
        assert!(is_outstanding(&[open], ID, Scope::Task, &ctx("run-C")));
    }

    #[test]
    fn branch_scope_keys_on_the_recorded_branch() {
        let open = ev_full(
            &open_transition(ID),
            "run-A",
            None,
            vec!["branch:feature/x".into()],
        );
        let mut on_x = ctx("run-B");
        on_x.branch = Some("feature/x".into());
        let mut on_main = ctx("run-B");
        on_main.branch = Some("main".into());
        assert!(is_outstanding(
            std::slice::from_ref(&open),
            ID,
            Scope::Branch,
            &on_x
        ));
        assert!(!is_outstanding(
            std::slice::from_ref(&open),
            ID,
            Scope::Branch,
            &on_main
        ));
        // No branch determinable: fail safe.
        assert!(is_outstanding(&[open], ID, Scope::Branch, &ctx("run-B")));
    }

    #[test]
    fn action_scope_owes_per_edited_path() {
        let open_a = ev_full(
            &open_transition(ID),
            "r",
            None,
            vec!["path:src/a.rs".into()],
        );
        let open_b = ev_full(
            &open_transition(ID),
            "r",
            None,
            vec!["path:src/b.rs".into()],
        );
        let close_a = ev_full(
            &discharge_transition(ID),
            "r",
            None,
            vec!["path:src/a.rs".into()],
        );
        let events = vec![open_a, open_b, close_a];
        // b is still owed: one path's validation does not clear another's.
        assert!(is_outstanding(&events, ID, Scope::Action, &ctx("r")));
        let close_b = ev_full(
            &discharge_transition(ID),
            "r",
            None,
            vec!["path:src/b.rs".into()],
        );
        let mut all = events;
        all.push(close_b);
        assert!(!is_outstanding(&all, ID, Scope::Action, &ctx("r")));
    }

    #[test]
    fn an_unkeyed_open_debt_blocks_every_context() {
        // A legacy or misrecorded open event with no task key under task
        // scope: it cannot be attributed, so it cannot be proven to be
        // someone else's — outstanding for everyone until an unkeyed
        // discharge clears it.
        let open = ev_full(&open_transition(ID), "run-A", None, vec![]);
        let mut c = ctx("run-B");
        c.task_key = Some("sha256:mine".into());
        assert!(is_outstanding(
            std::slice::from_ref(&open),
            ID,
            Scope::Task,
            &c
        ));
        let close = ev_full(&discharge_transition(ID), "run-B", None, vec![]);
        assert!(!is_outstanding(&[open, close], ID, Scope::Task, &c));
    }

    #[test]
    fn requirements_parse_with_and_without_scope() {
        assert_eq!(parse_requirement("x").unwrap(), ("x", Scope::Run));
        assert_eq!(
            parse_requirement("x:workspace").unwrap(),
            ("x", Scope::Workspace)
        );
        assert!(parse_requirement("x:bogus").is_err());
        // A misconfigured requirement never silently passes.
        assert_eq!(
            outstanding(&[], &["x:bogus".to_string()], &ctx("r")),
            vec!["x:bogus"]
        );
    }
}
