//! Constitutional succession: the governed replacement of the governor.
//!
//! The first self-hosting trial ended with a kernel repaired *outside* every
//! rule the system had — detect defect, patch, restart, resume — leaving a
//! runtime boundary in the Ledger that nothing attests. This module is the
//! protocol from `docs/SUCCESSION.md` that makes such a transition a governed
//! act: **disarm** marks the start of the ungoverned window under the old
//! runtime; a **manifest** binds everything the transition claims (which
//! constitution retires, which history the successor inherits, which packet
//! authorized the surgery, which patch and conformance evidence justify it,
//! which kernel takes over) into one gate-approvable document; **activate**
//! is the first event the successor writes, refused unless the approved
//! manifest matches the running binary byte for byte.
//!
//! No protocol removes the residual trust — a kernel too broken to run its
//! own gate cannot mediate its replacement. The goal is narrower and honest:
//! the window of ungoverned action is explicit, bounded, evidenced, and
//! externally authorized, and the resumption of governance proves continuity
//! with the history it succeeds.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::event::Event;

/// Stable refusal codes for succession decisions, recorded as `policy:<code>`.
pub mod codes {
    /// The active packet carries no `amends_enforcement` grant — replacing
    /// the governor is the definitive enforcement amendment.
    pub const AMENDMENT_REQUIRED: &str = "succession.amendment_required";
    /// The manifest bytes no longer hash to the gate-approved action.
    pub const MANIFEST_MISMATCH: &str = "succession.manifest_mismatch";
    /// The gate refused (unapproved, action changed, drift, expired).
    pub const NOT_APPROVED: &str = "succession.not_approved";
    /// The approval is not signature-proven and `--allow-unproven` was not
    /// given — the running kernel must never approve its own successor.
    pub const APPROVAL_UNPROVEN: &str = "succession.approval_unproven";
    /// The manifest's inherited chain head is not in the ledger's history.
    pub const HEAD_MISSING: &str = "succession.head_missing";
    /// The manifest names a different successor than the binary activating.
    pub const KERNEL_MISMATCH: &str = "succession.kernel_mismatch";
    /// The manifest's successor constitution is not the one being activated.
    pub const RUNTIME_MISMATCH: &str = "succession.runtime_mismatch";
    /// Old and new runtime are identical — there is no transition to attest.
    pub const NO_TRANSITION: &str = "succession.no_transition";
    /// The conformance check command failed — the candidate is not fit.
    pub const CONFORMANCE_FAILED: &str = "succession.conformance_failed";
}

/// The transition strings the protocol writes.
pub const DISARM_TRANSITION: &str = "succession.disarm";
pub const ACTIVATE_TRANSITION: &str = "succession.activate";

/// The succession manifest: one canonical document binding everything the
/// transition claims. Its file bytes are the gate's `action_hash`, so an
/// approval covers exactly these fields and a post-approval edit is the same
/// `action changed` refusal as a substituted deploy artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessionManifest {
    /// The constitution being retired.
    pub old_runtime_ref: String,
    /// The chain head the successor inherits — anchored, so activation
    /// refuses a ledger whose history no longer contains it.
    pub old_ledger_head: String,
    /// The admitted packet that authorized the surgery.
    pub maintenance_task_id: String,
    /// The defect, in prose (and a `policy:` code where one exists).
    pub reason: String,
    /// Digest of the source change (commit hash or diff digest).
    pub patch_ref: String,
    /// Digest naming the conformance suite and its outcome.
    pub conformance_ref: String,
    /// The successor's implementation digest — must equal the activating
    /// binary's own `kernel_ref`, which is the self-attestation step.
    pub new_kernel_ref: String,
    /// The successor constitution — must equal the runtime the activating
    /// binary computes for the governing playbook.
    pub new_runtime_ref: String,
    /// Whether the old kernel managed to record the disarm event. `false` is
    /// the residual-trust case made explicit: the window's start is attested
    /// only by the successor.
    #[serde(default = "default_true")]
    pub disarm_recorded: bool,
}

fn default_true() -> bool {
    true
}

impl SuccessionManifest {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read succession manifest {}: {e}", path.display()))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("succession manifest {} is not valid: {e}", path.display()))
    }
}

/// One runtime boundary in a ledger that no `succession.activate` record
/// attests — history changed governors without a governed transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnattestedBoundary {
    /// Index (record position) of the first event under the new runtime.
    pub at: usize,
    pub old_runtime_ref: String,
    pub new_runtime_ref: String,
}

/// Scan events in order for runtime-segment boundaries and report every one
/// whose incoming segment contains no **approved** `succession.activate`
/// attesting the runtime it succeeded. The attestation may not be the
/// segment's first record — a refused activation is honestly written under
/// the successor's own runtime, so the refusal can open the segment the
/// eventual approval attests. This is a **warning** surface, not a failure:
/// history predating the protocol stays legible, but a boundary without
/// attestation is exactly what the first self-trial produced, and the
/// verifier's job is to make it loud.
pub fn unattested_boundaries(events: &[Event]) -> Vec<UnattestedBoundary> {
    // Contiguous runs of one runtime_ref, with their starting record index.
    let mut segments: Vec<(usize, &str)> = Vec::new();
    for (i, ev) in events.iter().enumerate() {
        match segments.last() {
            Some((_, r)) if *r == ev.runtime_ref.as_str() => {}
            _ => segments.push((i, ev.runtime_ref.as_str())),
        }
    }
    let mut out = Vec::new();
    for w in segments.windows(2) {
        let (_, old) = w[0];
        let (start, new) = w[1];
        let end = segments
            .iter()
            .find(|(s, _)| *s > start)
            .map(|(s, _)| *s)
            .unwrap_or(events.len());
        let attested = events[start..end].iter().any(|ev| {
            ev.transition == ACTIVATE_TRANSITION
                && ev.decision == crate::event::Decision::Approved
                && ev
                    .input_refs
                    .iter()
                    .any(|r| r == &format!("old_runtime:{old}"))
        });
        if !attested {
            out.push(UnattestedBoundary {
                at: start,
                old_runtime_ref: old.to_string(),
                new_runtime_ref: new.to_string(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Decision;

    fn ev(runtime: &str, transition: &str, input_refs: Vec<String>) -> Event {
        Event {
            run_id: "r".into(),
            task_id: None,
            parent_task_id: None,
            action_id: "a".into(),
            actor: "kernel".into(),
            timestamp: "2026-08-01T00:00:00Z".into(),
            transition: transition.into(),
            stage: "recorded".into(),
            input_refs,
            output_refs: vec![],
            decision: if transition == ACTIVATE_TRANSITION {
                Decision::Approved
            } else {
                Decision::Recorded
            },
            evidence_refs: vec![],
            playbook_ref: String::new(),
            kernel_ref: String::new(),
            runtime_ref: runtime.into(),
            attempt_id: None,
        }
    }

    #[test]
    fn an_attested_boundary_is_quiet_and_an_unattested_one_is_loud() {
        // The self-trial's shape: governance changed hands silently.
        let silent = vec![
            ev("sha256:old", "pre_tool.edit", vec![]),
            ev("sha256:new", "pre_tool.edit", vec![]),
        ];
        let found = unattested_boundaries(&silent);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].at, 1);
        assert_eq!(found[0].old_runtime_ref, "sha256:old");

        // The protocol's shape: the successor's first event attests exactly
        // which runtime it succeeded.
        let governed = vec![
            ev("sha256:old", "pre_tool.edit", vec![]),
            ev(
                "sha256:new",
                ACTIVATE_TRANSITION,
                vec!["old_runtime:sha256:old".into(), "old_head:sha256:h".into()],
            ),
            ev("sha256:new", "pre_tool.edit", vec![]),
        ];
        assert!(unattested_boundaries(&governed).is_empty());
    }

    #[test]
    fn an_activate_naming_the_wrong_predecessor_does_not_attest() {
        let events = vec![
            ev("sha256:old", "pre_tool.edit", vec![]),
            ev(
                "sha256:new",
                ACTIVATE_TRANSITION,
                vec!["old_runtime:sha256:someone-else".into()],
            ),
        ];
        assert_eq!(unattested_boundaries(&events).len(), 1);
    }

    #[test]
    fn a_rejected_activation_does_not_attest() {
        // A refusal is evidence of an attempt, not of a governed handover.
        let mut rejected = ev(
            "sha256:new",
            ACTIVATE_TRANSITION,
            vec!["old_runtime:sha256:old".into()],
        );
        rejected.decision = Decision::Rejected;
        let events = vec![ev("sha256:old", "pre_tool.edit", vec![]), rejected.clone()];
        assert_eq!(unattested_boundaries(&events).len(), 1);

        // But a refusal FOLLOWED by the approval within the same segment does:
        // the refused attempt is honestly written under the successor's own
        // runtime, so it may open the segment its approval then attests.
        let events = vec![
            ev("sha256:old", "pre_tool.edit", vec![]),
            rejected,
            ev(
                "sha256:new",
                ACTIVATE_TRANSITION,
                vec!["old_runtime:sha256:old".into()],
            ),
        ];
        assert!(unattested_boundaries(&events).is_empty());
    }

    #[test]
    fn multiple_boundaries_are_each_judged() {
        let events = vec![
            ev("sha256:a", "x", vec![]),
            ev(
                "sha256:b",
                ACTIVATE_TRANSITION,
                vec!["old_runtime:sha256:a".into()],
            ),
            ev("sha256:c", "x", vec![]), // silent second handover
        ];
        let found = unattested_boundaries(&events);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].old_runtime_ref, "sha256:b");
        assert_eq!(found[0].new_runtime_ref, "sha256:c");
    }

    #[test]
    fn manifest_roundtrips_and_defaults_disarm_recorded() {
        let json = serde_json::json!({
            "old_runtime_ref": "sha256:old",
            "old_ledger_head": "sha256:head",
            "maintenance_task_id": "abc123def456",
            "reason": "absolute-path binding defect blocks all platform edits",
            "patch_ref": "sha256:patch",
            "conformance_ref": "sha256:conformance",
            "new_kernel_ref": "sha256:kernel",
            "new_runtime_ref": "sha256:new",
        });
        let m: SuccessionManifest = serde_json::from_str(&json.to_string()).unwrap();
        assert!(m.disarm_recorded, "absence claims the disarm was recorded");
        let back: SuccessionManifest =
            serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(m, back);
    }
}
