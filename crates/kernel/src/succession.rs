//! Constitutional succession: the governed replacement of the governor.
//!
//! The first self-hosting trial ended with a kernel repaired *outside* every
//! rule the system had — detect defect, patch, restart, resume — leaving a
//! runtime boundary in the Ledger that nothing attests. The founding ceremony
//! (`succession-0001`) then repaired the *attestation* but not the
//! *transfer*: its manifest bound a "predecessor head" that was in fact two
//! records deep into the candidate's own governance, and the verifier of that
//! era accepted it because it never checked adjacency. This module now
//! enforces the constitutional statement directly:
//!
//! > A candidate runtime may describe and prove its proposed succession, but
//! > it may not govern until its authority is anchored to the exact final
//! > head of the predecessor and a valid activation has entered the ledger.
//!
//! Three mechanisms carry it:
//!
//! - **Boundary invariants** — for a `normal` transition, the candidate
//!   segment must begin immediately after the exact predecessor head named by
//!   the manifest; the record at that head must belong to the declared
//!   predecessor runtime; and every candidate-runtime record before
//!   activation must be **candidate-safe** (a closed allowlist, never
//!   inferred from naming).
//! - **Candidate mode** — a runtime whose identity differs from the ledger's
//!   currently active runtime, with no valid activation of its own, may not
//!   perform ordinary governance. The refusal is mechanical (kernel-side),
//!   not a prompt instruction or voluntary command ordering.
//! - **The legacy-bootstrap exception** — the founding transition is accepted
//!   only through an explicit, digest-pinned allowlist entry, reported
//!   visibly with its anomaly retained, and never treated as satisfying the
//!   normal invariant. No later transition may self-declare a bootstrap.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::event::{Decision, Event, LedgerLine};

/// Stable refusal codes, recorded/reported as `policy:<code>`. The founding
/// era's dot-style codes remain below; the boundary-repair codes follow the
/// packet that specified them.
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

    // ---- boundary-repair codes ------------------------------------------

    /// The declared predecessor head is not the exact final predecessor
    /// record adjacent to the candidate boundary.
    pub const BOUNDARY_HEAD_MISMATCH: &str = "succession-boundary-head-mismatch";
    /// The record at the declared head belongs to the wrong runtime.
    pub const PREDECESSOR_RUNTIME_MISMATCH: &str = "succession-predecessor-runtime-mismatch";
    /// The candidate emitted ordinary governance before activation.
    pub const CANDIDATE_GOVERNANCE: &str = "succession-candidate-governance-before-activation";
    /// A candidate-mode append that is not on the closed allowlist.
    pub const CANDIDATE_EVENT_NOT_ALLOWED: &str = "succession-candidate-event-not-allowed";
    /// A bootstrap transition without an exact allowlist authorization.
    pub const BOOTSTRAP_NOT_AUTHORIZED: &str = "succession-bootstrap-not-authorized";
    /// A bootstrap allowlist entry matched more than one boundary.
    pub const BOOTSTRAP_REUSED: &str = "succession-bootstrap-reused";
    /// A structurally invalid activation (missing mode, missing refs,
    /// missing disarm, missing ceremony identity).
    pub const ACTIVATION_INVALID: &str = "succession-activation-invalid";
    /// The runtime asked to govern without being the active runtime.
    pub const RUNTIME_NOT_ACTIVE: &str = "succession-runtime-not-active";
}

/// The transition strings the protocol writes.
pub const DISARM_TRANSITION: &str = "succession.disarm";
pub const ACTIVATE_TRANSITION: &str = "succession.activate";
pub const ABORT_TRANSITION: &str = "succession.abort";

/// The **closed** candidate-safe allowlist: the only event kinds a runtime in
/// candidate mode may append. Anything not listed here is ordinary
/// governance, whatever it is named — membership is by this list, never by a
/// `succession.*` naming convention.
pub const CANDIDATE_SAFE: &[&str] = &[
    "succession.candidate_started",
    "succession.conformance_requested",
    "succession.conformance_recorded",
    "succession.approval_requested",
    "succession.approval_recorded",
    ACTIVATE_TRANSITION,
    ABORT_TRANSITION,
];

pub fn is_candidate_safe(transition: &str) -> bool {
    CANDIDATE_SAFE.contains(&transition)
}

/// The succession manifest: one canonical document binding everything the
/// transition claims. Its file bytes are the gate's `action_hash`, so an
/// approval covers exactly these fields and a post-approval edit is the same
/// `action changed` refusal as a substituted deploy artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessionManifest {
    /// `normal` or `bootstrap`. Mandatory for every new manifest; absence is
    /// legacy state acceptable only through the digest-pinned allowlist.
    #[serde(default)]
    pub transition_mode: String,
    /// The constitution being retired.
    pub old_runtime_ref: String,
    /// The **exact final** chain head of the predecessor — for a `normal`
    /// transition the candidate boundary must descend from it directly.
    pub old_ledger_head: String,
    /// The admitted packet that authorized building the candidate.
    pub maintenance_task_id: String,
    /// The admitted packet authorizing the live transition ceremony itself.
    /// Mandatory for `normal` transitions: who built the candidate and who
    /// is seating it are different authorities.
    #[serde(default)]
    pub ceremony_task_id: String,
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
    /// Whether the predecessor recorded the disarm. Must be `true` for
    /// `normal` transitions; `false` was the founding bootstrap's
    /// residual-trust case and is unavailable outside the legacy exception.
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

/// One entry of the founding-transition allowlist: a bootstrap (or legacy,
/// mode-absent) activation is accepted only when its manifest digest matches
/// an entry **exactly**, and each entry authorizes at most one boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapException {
    pub transition_id: String,
    pub manifest_digest: String,
    pub exception: String,
}

/// Load a bootstrap-exception allowlist (a JSON array). Missing file → empty.
pub fn load_exceptions(path: &Path) -> Result<Vec<BootstrapException>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    serde_json::from_str(&text).map_err(|e| format!("{} is not a valid allowlist: {e}", path.display()))
}

/// Where a runtime stands relative to the ledger's succession regime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeStatus {
    /// No approved activation exists anywhere: no succession regime has been
    /// established, and every runtime governs as before. A fresh workspace
    /// starts here; its first activation founds the regime.
    Ungoverned,
    /// The computed runtime IS the ledger's active runtime.
    Active,
    /// A regime exists and this runtime is not its active one: candidate
    /// mode — only candidate-safe actions until a valid activation.
    Candidate { active_runtime: String },
}

/// The ledger's currently active runtime: the runtime of the last approved
/// `succession.activate`, if any.
pub fn active_runtime(events: &[Event]) -> Option<String> {
    events
        .iter()
        .rev()
        .find(|e| e.transition == ACTIVATE_TRANSITION && e.decision == Decision::Approved)
        .map(|e| e.runtime_ref.clone())
}

pub fn runtime_status(events: &[Event], computed_runtime: &str) -> RuntimeStatus {
    match active_runtime(events) {
        None => RuntimeStatus::Ungoverned,
        Some(a) if a == computed_runtime => RuntimeStatus::Active,
        Some(a) => RuntimeStatus::Candidate { active_runtime: a },
    }
}

/// The boundary invariant, over a slice of ledger lines whose last element is
/// the prospective (or actual) activation position:
///
/// - the declared head names a record in the slice;
/// - that record belongs to the declared predecessor runtime;
/// - every record after it belongs to the candidate runtime AND is
///   candidate-safe;
/// - the candidate boundary record's `prev` is exactly the declared head.
///
/// Used identically at activation time (over the whole current ledger, before
/// the activate event is appended) and at verification time (over the prefix
/// ending at the activation event).
pub fn validate_boundary(
    lines: &[LedgerLine],
    old_runtime: &str,
    new_runtime: &str,
    head: &str,
) -> Result<(), (&'static str, String)> {
    let Some(idx) = lines.iter().position(|l| l.digest == head) else {
        return Err((
            codes::BOUNDARY_HEAD_MISMATCH,
            format!(
                "declared predecessor head {head} names no record in the ledger \
                 (declared predecessor {old_runtime}, candidate {new_runtime})"
            ),
        ));
    };
    let at = &lines[idx];
    if at.event.runtime_ref != old_runtime {
        let hint = if at.event.runtime_ref == new_runtime {
            " — the declared head lies inside the candidate's own governance"
        } else {
            ""
        };
        return Err((
            codes::PREDECESSOR_RUNTIME_MISMATCH,
            format!(
                "declared predecessor head {head} (record {idx}) was emitted under runtime {}, \
                 not declared predecessor {old_runtime}{hint}",
                at.event.runtime_ref
            ),
        ));
    }
    if let Some(b) = lines.get(idx + 1) {
        if b.prev.as_deref() != Some(head) {
            return Err((
                codes::BOUNDARY_HEAD_MISMATCH,
                format!(
                    "candidate boundary record {} carries prev {}, not the declared predecessor \
                     head {head}",
                    idx + 1,
                    b.prev.as_deref().unwrap_or("(unchained)")
                ),
            ));
        }
    }
    for (off, l) in lines[idx + 1..].iter().enumerate() {
        let n = idx + 1 + off;
        if l.event.runtime_ref != new_runtime {
            return Err((
                codes::BOUNDARY_HEAD_MISMATCH,
                format!(
                    "record {n} under runtime {} follows the declared predecessor head — \
                     {head} was not the predecessor's final record",
                    l.event.runtime_ref
                ),
            ));
        }
        if !is_candidate_safe(&l.event.transition) {
            return Err((
                codes::CANDIDATE_GOVERNANCE,
                format!(
                    "record {n} ('{}') is ordinary governance emitted by candidate runtime \
                     {new_runtime} before activation (declared predecessor {old_runtime}, \
                     head {head})",
                    l.event.transition
                ),
            ));
        }
    }
    Ok(())
}

/// The verifier's judgment of one runtime boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessionFinding {
    /// A `normal` transition satisfying the full boundary invariant.
    ValidNormal {
        at: usize,
        old_runtime_ref: String,
        new_runtime_ref: String,
    },
    /// Accepted ONLY via the digest-pinned allowlist; never described as
    /// satisfying the normal invariant, and its anomaly is retained.
    LegacyBootstrap {
        at: usize,
        transition_id: String,
        manifest_digest: String,
        anomaly: String,
    },
    /// No approved activation names this handover at all — the original
    /// self-trial shape. A warning, not a failure: history predating the
    /// protocol stays legible, but never quiet.
    Unattested {
        at: usize,
        old_runtime_ref: String,
        new_runtime_ref: String,
    },
    /// An activation exists but the transition violates the invariants.
    Violation {
        at: usize,
        code: &'static str,
        reason: String,
    },
}

fn ref_value<'a>(ev: &'a Event, prefix: &str) -> Option<&'a str> {
    ev.input_refs
        .iter()
        .find_map(|r| r.strip_prefix(prefix))
}

/// Judge every runtime boundary in the ledger. `exceptions` is the
/// founding-transition allowlist; each entry authorizes at most one boundary
/// (a second match is `succession-bootstrap-reused`).
pub fn verify_successions(
    lines: &[LedgerLine],
    exceptions: &[BootstrapException],
) -> Vec<SuccessionFinding> {
    // Contiguous runtime segments as (start index, runtime).
    let mut segments: Vec<(usize, String)> = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        match segments.last() {
            Some((_, r)) if *r == l.event.runtime_ref => {}
            _ => segments.push((i, l.event.runtime_ref.clone())),
        }
    }
    let mut findings = Vec::new();
    let mut used_exceptions: Vec<&str> = Vec::new();
    for w in 0..segments.len().saturating_sub(1) {
        let (_, ref old_rt) = segments[w];
        let (start, ref new_rt) = segments[w + 1];
        let end = segments
            .get(w + 2)
            .map(|(s, _)| *s)
            .unwrap_or(lines.len());
        let activation = lines[start..end].iter().enumerate().find(|(_, l)| {
            l.event.transition == ACTIVATE_TRANSITION
                && l.event.decision == Decision::Approved
                && ref_value(&l.event, "old_runtime:") == Some(old_rt.as_str())
        });
        let Some((a_off, a)) = activation else {
            findings.push(SuccessionFinding::Unattested {
                at: start,
                old_runtime_ref: old_rt.clone(),
                new_runtime_ref: new_rt.clone(),
            });
            continue;
        };
        let a_idx = start + a_off;
        let mode = ref_value(&a.event, "mode:");
        let declared_head = ref_value(&a.event, "old_head:");
        let manifest_digest = ref_value(&a.event, "manifest:").unwrap_or("");
        match mode {
            Some("normal") => {
                let Some(head) = declared_head else {
                    findings.push(SuccessionFinding::Violation {
                        at: start,
                        code: codes::ACTIVATION_INVALID,
                        reason: "normal activation names no old_head".into(),
                    });
                    continue;
                };
                match validate_boundary(&lines[..=a_idx], old_rt, new_rt, head) {
                    Ok(()) => findings.push(SuccessionFinding::ValidNormal {
                        at: start,
                        old_runtime_ref: old_rt.clone(),
                        new_runtime_ref: new_rt.clone(),
                    }),
                    Err((code, reason)) => {
                        findings.push(SuccessionFinding::Violation {
                            at: start,
                            code,
                            reason,
                        })
                    }
                }
            }
            // A bootstrap claim — explicit or legacy (mode absent) — is
            // accepted only through the exact allowlist, once each.
            mode_claim @ (Some("bootstrap") | None) => {
                let matched = exceptions
                    .iter()
                    .find(|x| x.manifest_digest == manifest_digest && !manifest_digest.is_empty());
                match matched {
                    Some(x) if used_exceptions.contains(&x.manifest_digest.as_str()) => {
                        findings.push(SuccessionFinding::Violation {
                            at: start,
                            code: codes::BOOTSTRAP_REUSED,
                            reason: format!(
                                "allowlist entry '{}' ({}) already authorized an earlier \
                                 boundary; a founding exception is single-use",
                                x.transition_id, x.manifest_digest
                            ),
                        });
                    }
                    Some(x) => {
                        used_exceptions.push(x.manifest_digest.as_str());
                        // Retain the specific anomaly: compare the declared
                        // head against the predecessor's true final record.
                        let true_head = &lines[start - 1].digest;
                        let anomaly = match declared_head {
                            Some(h) if h == true_head => {
                                "declared head matches the predecessor's final record; \
                                 exception needed only for the missing transition_mode"
                                    .to_string()
                            }
                            Some(h) => format!(
                                "manifest-bound head {h} is NOT the predecessor's final record \
                                 {true_head}; records between were emitted by the candidate \
                                 runtime before formal activation"
                            ),
                            None => "activation names no old_head".to_string(),
                        };
                        findings.push(SuccessionFinding::LegacyBootstrap {
                            at: start,
                            transition_id: x.transition_id.clone(),
                            manifest_digest: x.manifest_digest.clone(),
                            anomaly,
                        });
                    }
                    None => {
                        let (code, what) = if mode_claim.is_some() {
                            (codes::BOOTSTRAP_NOT_AUTHORIZED, "declares transition_mode bootstrap")
                        } else {
                            (codes::ACTIVATION_INVALID, "declares no transition_mode")
                        };
                        findings.push(SuccessionFinding::Violation {
                            at: start,
                            code,
                            reason: format!(
                                "activation at record {a_idx} {what} and its manifest digest \
                                 '{manifest_digest}' matches no allowlist entry; a bootstrap is \
                                 never self-declared"
                            ),
                        });
                    }
                }
            }
            Some(other) => findings.push(SuccessionFinding::Violation {
                at: start,
                code: codes::ACTIVATION_INVALID,
                reason: format!("activation declares unknown transition_mode '{other}'"),
            }),
        }
    }
    findings
}

/// Boundaries with no approved activation at all — retained for callers that
/// only need the warning surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnattestedBoundary {
    pub at: usize,
    pub old_runtime_ref: String,
    pub new_runtime_ref: String,
}

pub fn unattested_boundaries(events: &[Event]) -> Vec<UnattestedBoundary> {
    let lines: Vec<LedgerLine> = events
        .iter()
        .enumerate()
        .map(|(i, e)| LedgerLine {
            seq: Some(i as u64),
            prev: None,
            digest: format!("synthetic:{i}"),
            event: e.clone(),
        })
        .collect();
    verify_successions(&lines, &[])
        .into_iter()
        .filter_map(|f| match f {
            SuccessionFinding::Unattested {
                at,
                old_runtime_ref,
                new_runtime_ref,
            } => Some(UnattestedBoundary {
                at,
                old_runtime_ref,
                new_runtime_ref,
            }),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(i: usize, runtime: &str, transition: &str, decision: Decision, input_refs: Vec<String>) -> LedgerLine {
        LedgerLine {
            seq: Some(i as u64),
            prev: if i == 0 { None } else { Some(format!("d{}", i - 1)) },
            digest: format!("d{i}"),
            event: Event {
                run_id: "r".into(),
                task_id: None,
                parent_task_id: None,
                action_id: format!("a{i}"),
                actor: "kernel".into(),
                timestamp: "2026-08-02T00:00:00Z".into(),
                transition: transition.into(),
                stage: "recorded".into(),
                input_refs,
                output_refs: vec![],
                decision,
                evidence_refs: vec![],
                playbook_ref: String::new(),
                kernel_ref: String::new(),
                runtime_ref: runtime.into(),
                attempt_id: None,
            },
        }
    }

    fn activate_refs(old: &str, head: &str, mode: &str) -> Vec<String> {
        vec![
            format!("old_runtime:{old}"),
            format!("old_head:{head}"),
            "manifest:sha256:m1".into(),
            format!("mode:{mode}"),
        ]
    }

    #[test]
    fn a_normal_succession_adjacent_to_the_true_head_is_valid() {
        let lines = vec![
            line(0, "rt-old", "pre_tool.edit", Decision::Allowed, vec![]),
            line(1, "rt-old", DISARM_TRANSITION, Decision::Recorded, vec![]),
            line(2, "rt-new", ACTIVATE_TRANSITION, Decision::Approved, activate_refs("rt-old", "d1", "normal")),
            line(3, "rt-new", "pre_tool.edit", Decision::Allowed, vec![]),
        ];
        let f = verify_successions(&lines, &[]);
        assert_eq!(
            f,
            vec![SuccessionFinding::ValidNormal {
                at: 2,
                old_runtime_ref: "rt-old".into(),
                new_runtime_ref: "rt-new".into()
            }]
        );
    }

    #[test]
    fn a_head_inside_the_candidates_own_governance_is_rejected() {
        // The succession-0001 defect, replayed under mode:normal — the
        // declared head names a candidate-runtime record.
        let lines = vec![
            line(0, "rt-old", "pre_tool.edit", Decision::Allowed, vec![]),
            line(1, "rt-new", "obligation.discharge.require-validation", Decision::Recorded, vec![]),
            line(2, "rt-new", ACTIVATE_TRANSITION, Decision::Approved, activate_refs("rt-old", "d1", "normal")),
        ];
        let f = verify_successions(&lines, &[]);
        assert!(matches!(
            &f[0],
            SuccessionFinding::Violation { code, reason, .. }
                if *code == codes::PREDECESSOR_RUNTIME_MISMATCH
                    && reason.contains("candidate's own governance")
        ));
    }

    #[test]
    fn candidate_governance_before_activation_is_rejected_even_with_a_true_head() {
        let lines = vec![
            line(0, "rt-old", "pre_tool.edit", Decision::Allowed, vec![]),
            line(1, "rt-new", "pre_tool.edit", Decision::Allowed, vec![]),
            line(2, "rt-new", ACTIVATE_TRANSITION, Decision::Approved, activate_refs("rt-old", "d0", "normal")),
        ];
        let f = verify_successions(&lines, &[]);
        assert!(matches!(
            &f[0],
            SuccessionFinding::Violation { code, .. } if *code == codes::CANDIDATE_GOVERNANCE
        ));
    }

    #[test]
    fn a_head_naming_no_record_is_rejected() {
        let lines = vec![
            line(0, "rt-old", "pre_tool.edit", Decision::Allowed, vec![]),
            line(1, "rt-new", ACTIVATE_TRANSITION, Decision::Approved, activate_refs("rt-old", "sha256:nowhere", "normal")),
        ];
        let f = verify_successions(&lines, &[]);
        assert!(matches!(
            &f[0],
            SuccessionFinding::Violation { code, .. } if *code == codes::BOUNDARY_HEAD_MISMATCH
        ));
    }

    #[test]
    fn candidate_safe_refusals_may_precede_the_activation() {
        // A rejected activation and an abort are candidate-safe; the eventual
        // approval still satisfies the invariant.
        let lines = vec![
            line(0, "rt-old", DISARM_TRANSITION, Decision::Recorded, vec![]),
            line(1, "rt-new", ACTIVATE_TRANSITION, Decision::Rejected, activate_refs("rt-old", "d0", "normal")),
            line(2, "rt-new", ABORT_TRANSITION, Decision::Recorded, vec![]),
            line(3, "rt-new", ACTIVATE_TRANSITION, Decision::Approved, activate_refs("rt-old", "d0", "normal")),
        ];
        let f = verify_successions(&lines, &[]);
        assert!(matches!(&f[0], SuccessionFinding::ValidNormal { .. }), "{f:?}");
    }

    #[test]
    fn the_allowlist_is_closed_not_a_naming_convention() {
        assert!(is_candidate_safe("succession.abort"));
        assert!(
            !is_candidate_safe("succession.exfiltrate"),
            "an unlisted succession.* kind is ordinary governance"
        );
        let lines = vec![
            line(0, "rt-old", DISARM_TRANSITION, Decision::Recorded, vec![]),
            line(1, "rt-new", "succession.exfiltrate", Decision::Recorded, vec![]),
            line(2, "rt-new", ACTIVATE_TRANSITION, Decision::Approved, activate_refs("rt-old", "d0", "normal")),
        ];
        let f = verify_successions(&lines, &[]);
        assert!(matches!(
            &f[0],
            SuccessionFinding::Violation { code, .. } if *code == codes::CANDIDATE_GOVERNANCE
        ));
    }

    #[test]
    fn a_mode_absent_activation_needs_the_exact_allowlist_entry() {
        // Mirrors the founding defect: the declared head (d1) is a record
        // the candidate itself emitted; the true predecessor head is d0.
        let legacy_refs = vec![
            "old_runtime:rt-old".to_string(),
            "old_head:d1".to_string(),
            "manifest:sha256:founding".to_string(),
        ];
        let lines = vec![
            line(0, "rt-old", "pre_tool.edit", Decision::Allowed, vec![]),
            line(1, "rt-new", "obligation.discharge.require-validation", Decision::Recorded, vec![]),
            line(2, "rt-new", ACTIVATE_TRANSITION, Decision::Approved, legacy_refs),
        ];
        // Without the allowlist: rejected.
        let f = verify_successions(&lines, &[]);
        assert!(matches!(
            &f[0],
            SuccessionFinding::Violation { code, .. } if *code == codes::ACTIVATION_INVALID
        ));
        // With the exact digest: accepted as legacy bootstrap, anomaly kept.
        let x = vec![BootstrapException {
            transition_id: "succession-0001".into(),
            manifest_digest: "sha256:founding".into(),
            exception: "legacy-founding-bootstrap".into(),
        }];
        let f = verify_successions(&lines, &x);
        assert!(matches!(
            &f[0],
            SuccessionFinding::LegacyBootstrap { anomaly, .. }
                if anomaly.contains("NOT the predecessor's final record")
        ));
        // A different digest (a modified founding manifest): rejected.
        let wrong = vec![BootstrapException {
            transition_id: "succession-0001".into(),
            manifest_digest: "sha256:other".into(),
            exception: "legacy-founding-bootstrap".into(),
        }];
        let f = verify_successions(&lines, &wrong);
        assert!(matches!(&f[0], SuccessionFinding::Violation { .. }));
    }

    #[test]
    fn an_explicit_bootstrap_claim_without_authorization_is_rejected_and_an_entry_is_single_use() {
        let mk = |head: &str| {
            vec![
                "old_runtime:rt-old".to_string(),
                format!("old_head:{head}"),
                "manifest:sha256:founding".to_string(),
                "mode:bootstrap".to_string(),
            ]
        };
        let lines = vec![
            line(0, "rt-old", "x", Decision::Recorded, vec![]),
            line(1, "rt-mid", ACTIVATE_TRANSITION, Decision::Approved, mk("d0")),
            line(2, "rt-mid", "x", Decision::Recorded, vec![]),
            line(3, "rt-new", ACTIVATE_TRANSITION, Decision::Approved, {
                let mut r = mk("d2");
                r[0] = "old_runtime:rt-mid".into();
                r
            }),
        ];
        // No allowlist: both bootstrap claims rejected.
        let f = verify_successions(&lines, &[]);
        assert!(f.iter().all(|x| matches!(
            x,
            SuccessionFinding::Violation { code, .. } if *code == codes::BOOTSTRAP_NOT_AUTHORIZED
        )));
        // One entry: first boundary accepted, second is a REUSE violation.
        let x = vec![BootstrapException {
            transition_id: "succession-0001".into(),
            manifest_digest: "sha256:founding".into(),
            exception: "legacy-founding-bootstrap".into(),
        }];
        let f = verify_successions(&lines, &x);
        assert!(matches!(&f[0], SuccessionFinding::LegacyBootstrap { .. }));
        assert!(matches!(
            &f[1],
            SuccessionFinding::Violation { code, .. } if *code == codes::BOOTSTRAP_REUSED
        ));
    }

    #[test]
    fn a_boundary_with_no_activation_at_all_stays_a_warning() {
        let lines = vec![
            line(0, "rt-old", "pre_tool.edit", Decision::Allowed, vec![]),
            line(1, "rt-new", "pre_tool.edit", Decision::Allowed, vec![]),
        ];
        let f = verify_successions(&lines, &[]);
        assert!(matches!(&f[0], SuccessionFinding::Unattested { .. }));
    }

    #[test]
    fn runtime_status_establishes_candidate_mode_only_under_a_regime() {
        let no_regime = vec![line(0, "rt-a", "pre_tool.edit", Decision::Allowed, vec![])];
        let events: Vec<Event> = no_regime.iter().map(|l| l.event.clone()).collect();
        assert_eq!(runtime_status(&events, "rt-b"), RuntimeStatus::Ungoverned);

        let with_regime = vec![
            line(0, "rt-a", "pre_tool.edit", Decision::Allowed, vec![]),
            line(1, "rt-a", ACTIVATE_TRANSITION, Decision::Approved, vec![]),
        ];
        let events: Vec<Event> = with_regime.iter().map(|l| l.event.clone()).collect();
        assert_eq!(runtime_status(&events, "rt-a"), RuntimeStatus::Active);
        assert_eq!(
            runtime_status(&events, "rt-b"),
            RuntimeStatus::Candidate {
                active_runtime: "rt-a".into()
            }
        );
        // A rejected activation establishes nothing.
        let rejected_only = vec![line(0, "rt-a", ACTIVATE_TRANSITION, Decision::Rejected, vec![])];
        let events: Vec<Event> = rejected_only.iter().map(|l| l.event.clone()).collect();
        assert_eq!(runtime_status(&events, "rt-b"), RuntimeStatus::Ungoverned);
    }

    #[test]
    fn manifest_roundtrips_with_mode_and_ceremony_task() {
        let json = serde_json::json!({
            "transition_mode": "normal",
            "old_runtime_ref": "sha256:old",
            "old_ledger_head": "sha256:head",
            "maintenance_task_id": "abc123def456",
            "ceremony_task_id": "fed654cba321",
            "reason": "seat the boundary-enforcing kernel",
            "patch_ref": "sha256:patch",
            "conformance_ref": "sha256:conformance",
            "new_kernel_ref": "sha256:kernel",
            "new_runtime_ref": "sha256:new",
        });
        let m: SuccessionManifest = serde_json::from_str(&json.to_string()).unwrap();
        assert_eq!(m.transition_mode, "normal");
        assert_eq!(m.ceremony_task_id, "fed654cba321");
        assert!(m.disarm_recorded, "absence claims the disarm was recorded");
        // Legacy manifests (no mode) deserialize with an empty mode — the
        // activation and verifier refuse them outside the allowlist.
        let legacy: SuccessionManifest = serde_json::from_str(
            &serde_json::json!({
                "old_runtime_ref": "sha256:old",
                "old_ledger_head": "sha256:head",
                "maintenance_task_id": "abc123def456",
                "reason": "r",
                "patch_ref": "p",
                "conformance_ref": "c",
                "new_kernel_ref": "k",
                "new_runtime_ref": "n",
            })
            .to_string(),
        )
        .unwrap();
        assert!(legacy.transition_mode.is_empty());
    }
}
