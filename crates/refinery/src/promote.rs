//! Promotion: applying an **approved** proposal to the live spec.
//!
//! Promotion closes the Refinery's loop, and it is deliberately the most
//! guarded step in it. A proposal is an edit *of a particular spec*, approved
//! *as particular bytes*, by *a particular principal* — so promotion is a Gate
//! resume, not a file copy:
//!
//! - **Action binding.** The Gate checkpoint's `action_hash` must equal the
//!   digest of the proposed spec **as it is now**. Approving one set of bytes
//!   and applying another (a post-approval edit) is refused by the same
//!   revalidation that refuses a substituted deploy artifact.
//! - **Base binding.** The proposal's manifest records the digest of the spec
//!   it was analyzed against; if the live spec has since moved, the proposal
//!   is stale and refused — applying it would silently discard whatever moved
//!   the spec.
//! - **Approval policy.** By default only a **signature-authenticated**
//!   approval promotes, re-proved through the current identity registry via
//!   the same kernel composition `gate verify` uses. `Claimed` and `Token`
//!   approvals — recorded honestly by the Gate, but unprovable here — require
//!   an explicit `--allow-unproven`.
//! - **Anchor and obligations.** A checkpoint that anchors the Ledger head or
//!   requires obligations gets the same treatment as any Gate resume:
//!   truncated history and open debt are refusals.
//!
//! What promotion does **not** guarantee: that the promoted spec compiles.
//! It proves the bytes parse into the typed spec model, then applies them
//! atomically; the compile gate is `harnessc build`, whose freshness test
//! makes an unpromoted-but-uncompiled spec loud in CI.

use std::path::Path;

use serde::{Deserialize, Serialize};

use kernel::event::EventLog;
use kernel::gate::{AuthMethod, GateStore, Preconditions};

/// The machine-readable identity of a written proposal (`proposal.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalManifest {
    pub id: String,
    /// Digest of the live spec the analysis ran against.
    pub base_spec_ref: String,
    /// Digest of the proposed spec as the Refinery authored it.
    pub authored_ref: String,
}

/// The name of the proposed-spec file inside a proposal directory.
pub const PROPOSED_SPEC_FILE: &str = "harness.patterns.proposed.yaml";

/// The precondition token promotion always supplies: the digest of the live
/// spec at promote time. A requester who records it at `gate request` gets
/// TOCTOU protection from the approval binding itself, on top of the
/// manifest's base check.
pub const BASE_SPEC_TOKEN: &str = "base_spec";

/// How a promotion attempt failed.
#[derive(Debug)]
pub enum PromoteError {
    /// The environment is wrong (missing files, missing flags) — a hard error,
    /// not a governed refusal.
    Setup(String),
    /// Promotion was **refused** by policy. Refusals are evidence: the caller
    /// records them in the Ledger as rejected decisions.
    Refused(String),
}

impl std::fmt::Display for PromoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromoteError::Setup(e) => write!(f, "{e}"),
            PromoteError::Refused(e) => write!(f, "promotion refused: {e}"),
        }
    }
}

impl std::error::Error for PromoteError {}

/// Everything a promotion attempt needs.
pub struct PromoteRequest<'a> {
    pub proposal_dir: &'a Path,
    pub spec_path: &'a Path,
    pub checkpoint_path: &'a Path,
    /// Identity registry for re-proving signature approvals.
    pub trusted_keys: Option<&'a Path>,
    /// Pinned authority key for the registry document (`ed25519:<hex>` or
    /// `@file`).
    pub authority: Option<&'a str>,
    /// Accept approvals promotion cannot re-prove (`Claimed`, `Token`).
    pub allow_unproven: bool,
    /// Ledger for anchor/obligation checks (required if the checkpoint uses
    /// them).
    pub ledger: Option<&'a Path>,
    pub now: String,
}

/// What a successful promotion did — the evidence the caller records.
#[derive(Debug)]
pub struct Promotion {
    /// Digest of the bytes actually applied (equals the approved action hash).
    pub proposal_ref: String,
    /// Digest of the base spec the proposal replaced.
    pub base_spec_ref: String,
    /// True if the applied bytes differ from what the Refinery authored — a
    /// human edited the proposal before approval. Legitimate (that is how
    /// disputed changes promote) and recorded honestly.
    pub edited: bool,
    pub approver: String,
    pub gate_id: String,
    pub run_id: String,
}

/// Read a proposal directory's manifest and current proposed-spec bytes.
pub fn load_proposal(dir: &Path) -> Result<(ProposalManifest, String), PromoteError> {
    let manifest_path = dir.join("proposal.json");
    let manifest: ProposalManifest =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).map_err(|e| {
            PromoteError::Setup(format!("cannot read {}: {e}", manifest_path.display()))
        })?)
        .map_err(|e| PromoteError::Setup(format!("malformed {}: {e}", manifest_path.display())))?;
    let spec_path = dir.join(PROPOSED_SPEC_FILE);
    let proposed = std::fs::read_to_string(&spec_path)
        .map_err(|e| PromoteError::Setup(format!("cannot read {}: {e}", spec_path.display())))?;
    Ok((manifest, proposed))
}

/// Attempt a promotion. On success the live spec HAS been replaced (atomically)
/// with the proposal's bytes. On `Refused`, the live spec is untouched.
pub fn promote(req: &PromoteRequest) -> Result<Promotion, PromoteError> {
    let (manifest, proposed) = load_proposal(req.proposal_dir)?;
    let proposal_ref = crate::sha256_ref(proposed.as_bytes());

    let live = std::fs::read_to_string(req.spec_path).map_err(|e| {
        PromoteError::Setup(format!("cannot read {}: {e}", req.spec_path.display()))
    })?;
    let live_ref = crate::sha256_ref(live.as_bytes());

    // Base binding: a proposal is an edit of a particular spec.
    if live_ref != manifest.base_spec_ref {
        return Err(PromoteError::Refused(format!(
            "stale proposal: analyzed against {} but the live spec is now {}; \
             re-run the Refinery against the current spec",
            manifest.base_spec_ref, live_ref
        )));
    }

    // The bytes must at least be a spec. (Compilability is `harnessc build`'s
    // gate; parseability is the floor below which promotion will not go.)
    if let Err(e) = spec::parse_model(&proposed) {
        return Err(PromoteError::Refused(format!(
            "proposed spec does not parse: {e}"
        )));
    }

    let cp = GateStore::load(req.checkpoint_path)
        .map_err(|e| PromoteError::Setup(format!("cannot load checkpoint: {e}")))?;

    // Gate revalidation: action binding (the proposal bytes AS THEY ARE NOW),
    // precondition drift (including base_spec if the requester recorded it),
    // and expiry — the same revalidation any Gate resume runs.
    let mut current = Preconditions::new();
    current.insert(BASE_SPEC_TOKEN.into(), live_ref.clone());
    let approval = cp
        .revalidate(&proposal_ref, &current, &req.now)
        .map_err(|e| PromoteError::Refused(e.to_string()))?;

    // Approval policy: promotion re-proves what it can and refuses what it
    // cannot unless explicitly told otherwise.
    match approval.approver.auth {
        AuthMethod::Signature => {
            let trusted_keys = req.trusted_keys.ok_or_else(|| {
                PromoteError::Setup(
                    "approval is signature-authenticated; pass --trusted-keys to re-prove it"
                        .into(),
                )
            })?;
            kernel::sign::reverify_signed_approval(&cp, trusted_keys, req.authority, &req.now)
                .map_err(|e| PromoteError::Refused(e.to_string()))?;
        }
        AuthMethod::Claimed | AuthMethod::Token => {
            if !req.allow_unproven {
                return Err(PromoteError::Refused(format!(
                    "approval auth '{}' cannot be re-proved at promotion; \
                     pass --allow-unproven to accept it as recorded",
                    match approval.approver.auth {
                        AuthMethod::Claimed => "claimed",
                        AuthMethod::Token => "token",
                        AuthMethod::Signature => unreachable!(),
                    }
                )));
            }
        }
    }

    // Anchor and obligations: the same posture as `gate verify`.
    if let Some(head) = &cp.ledger_head {
        let ledger = req.ledger.ok_or_else(|| {
            PromoteError::Setup("checkpoint anchors the ledger head; pass --ledger".into())
        })?;
        EventLog::at(ledger)
            .verify_anchor(head)
            .map_err(|e| PromoteError::Refused(format!("ledger integrity: {e}")))?;
    }
    if !cp.requires_obligations.is_empty() {
        let ledger = req.ledger.ok_or_else(|| {
            PromoteError::Setup("checkpoint requires obligations; pass --ledger".into())
        })?;
        let events = EventLog::at(ledger)
            .read_all()
            .map_err(|e| PromoteError::Setup(format!("cannot read ledger: {e}")))?;
        let ctx = kernel::obligation::ScopeContext {
            run_id: cp.run_id.clone(),
            task_key: None,
            branch: None,
            instance: cp.instance.clone(),
        };
        let outstanding = kernel::obligation::outstanding(&events, &cp.requires_obligations, &ctx);
        cp.check_obligations(&outstanding)
            .map_err(|e| PromoteError::Refused(e.to_string()))?;
    }

    let approver = approval.approver.principal.clone();

    // Everything held: apply the approved bytes atomically.
    kernel::fsutil::atomic_write(req.spec_path, proposed.as_bytes())
        .map_err(|e| PromoteError::Setup(format!("cannot write spec: {e}")))?;

    Ok(Promotion {
        edited: proposal_ref != manifest.authored_ref,
        proposal_ref,
        base_spec_ref: live_ref,
        approver,
        gate_id: cp.gate_id.clone(),
        run_id: cp.run_id.clone(),
    })
}

/// The checkpoint a `gate request` for this proposal should bind: exposed so
/// `refinery propose` can print the exact command. Returned as (action_hash,
/// base_spec precondition).
pub fn approval_binding_for(dir: &Path) -> Result<(String, String), PromoteError> {
    let (manifest, proposed) = load_proposal(dir)?;
    Ok((
        crate::sha256_ref(proposed.as_bytes()),
        manifest.base_spec_ref,
    ))
}

/// Where the promoted spec digest can be double-checked from disk.
pub fn spec_ref_at(path: &Path) -> std::io::Result<String> {
    Ok(crate::sha256_ref(std::fs::read(path)?.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::gate::{Approver, Checkpoint};
    use std::path::PathBuf;

    const SPEC: &str = include_str!("../../../harness.patterns.yaml");

    struct World {
        _dir: tempfile::TempDir,
        spec_path: PathBuf,
        proposal_dir: PathBuf,
        cp_path: PathBuf,
        proposal_ref: String,
    }

    /// Build a live spec, a written proposal against it, and an approved
    /// checkpoint bound to the proposal bytes.
    fn world(auth: AuthMethod, evidence: Option<String>) -> World {
        let dir = tempfile::tempdir().unwrap();
        let spec_path = dir.path().join("harness.patterns.yaml");
        std::fs::write(&spec_path, SPEC).unwrap();

        let proposal = crate::analyze(SPEC, &[]).unwrap();
        let root = dir.path().join("proposals");
        let pdir = crate::write_proposal(&proposal, &root, &spec_path).unwrap();
        let proposal_ref = crate::sha256_ref(proposal.proposed_spec.as_bytes());

        let mut cp = Checkpoint::new(
            "promote-spec",
            "run-p",
            proposal_ref.clone(),
            "promote refinery proposal",
            "resume:promote",
            Preconditions::new(),
            "2026-08-01T00:00:00Z",
        );
        cp.approve(
            Approver {
                principal: "alice".into(),
                auth,
                evidence,
            },
            "2026-08-01T00:00:01Z",
            None,
        );
        let store = GateStore::at(dir.path().join("cp"));
        let cp_path = store.save(&cp).unwrap();

        World {
            _dir: dir,
            spec_path,
            proposal_dir: pdir,
            cp_path,
            proposal_ref,
        }
    }

    fn request<'a>(w: &'a World, now: &str) -> PromoteRequest<'a> {
        PromoteRequest {
            proposal_dir: &w.proposal_dir,
            spec_path: &w.spec_path,
            checkpoint_path: &w.cp_path,
            trusted_keys: None,
            authority: None,
            allow_unproven: true,
            ledger: None,
            now: now.into(),
        }
    }

    #[test]
    fn an_approved_proposal_promotes_and_replaces_the_live_spec() {
        let w = world(AuthMethod::Claimed, None);
        let done = promote(&request(&w, "2026-08-01T00:01:00Z")).unwrap();
        assert_eq!(done.proposal_ref, w.proposal_ref);
        assert_eq!(done.approver, "alice");
        assert!(!done.edited, "unedited proposal is applied as authored");
        // The live spec now IS the proposal (version bumped).
        let live = std::fs::read_to_string(&w.spec_path).unwrap();
        assert!(live.contains("version: 0.1.1"));
        assert_eq!(spec_ref_at(&w.spec_path).unwrap(), w.proposal_ref);
    }

    #[test]
    fn an_unapproved_checkpoint_refuses_and_leaves_the_spec_alone() {
        let w = world(AuthMethod::Claimed, None);
        // Strip the approval.
        let mut cp = GateStore::load(&w.cp_path).unwrap();
        cp.approval = None;
        std::fs::write(&w.cp_path, serde_json::to_string(&cp).unwrap()).unwrap();

        let err = promote(&request(&w, "2026-08-01T00:01:00Z")).unwrap_err();
        assert!(matches!(err, PromoteError::Refused(_)), "{err}");
        assert_eq!(std::fs::read_to_string(&w.spec_path).unwrap(), SPEC);
    }

    #[test]
    fn bytes_edited_after_approval_are_a_gate_action_change() {
        let w = world(AuthMethod::Claimed, None);
        // Tamper with the proposed spec AFTER approval was recorded.
        let f = w.proposal_dir.join(PROPOSED_SPEC_FILE);
        let mut text = std::fs::read_to_string(&f).unwrap();
        text.push_str("# sneaky\n");
        std::fs::write(&f, text).unwrap();

        let err = promote(&request(&w, "2026-08-01T00:01:00Z")).unwrap_err();
        match err {
            PromoteError::Refused(msg) => assert!(msg.contains("action changed"), "{msg}"),
            other => panic!("expected refusal, got {other}"),
        }
        assert_eq!(std::fs::read_to_string(&w.spec_path).unwrap(), SPEC);
    }

    #[test]
    fn a_moved_base_spec_makes_the_proposal_stale() {
        let w = world(AuthMethod::Claimed, None);
        let mut live = std::fs::read_to_string(&w.spec_path).unwrap();
        live.push_str("# the world moved\n");
        std::fs::write(&w.spec_path, &live).unwrap();

        let err = promote(&request(&w, "2026-08-01T00:01:00Z")).unwrap_err();
        match err {
            PromoteError::Refused(msg) => assert!(msg.contains("stale proposal"), "{msg}"),
            other => panic!("expected refusal, got {other}"),
        }
        assert_eq!(std::fs::read_to_string(&w.spec_path).unwrap(), live);
    }

    #[test]
    fn unproven_approvals_need_the_explicit_flag() {
        let w = world(AuthMethod::Claimed, None);
        let mut req = request(&w, "2026-08-01T00:01:00Z");
        req.allow_unproven = false;
        let err = promote(&req).unwrap_err();
        match err {
            PromoteError::Refused(msg) => assert!(msg.contains("allow-unproven"), "{msg}"),
            other => panic!("expected refusal, got {other}"),
        }
    }

    #[test]
    fn a_signature_approval_is_reproved_through_the_registry() {
        // Sign the canonical approval message with a real key, register it,
        // and promotion verifies; a stripped registry refuses.
        let kp = kernel::sign::Keypair::generate().unwrap();
        let w = world(AuthMethod::Signature, None);
        let mut cp = GateStore::load(&w.cp_path).unwrap();
        let msg = kernel::sign::approval_message(
            &cp,
            &cp.approval.as_ref().unwrap().preconditions.clone(),
            None,
        );
        let sig = kp.sign(&msg);
        cp.approval.as_mut().unwrap().approver.evidence = Some(sig);
        std::fs::write(&w.cp_path, serde_json::to_string(&cp).unwrap()).unwrap();

        let keys_path = w.spec_path.parent().unwrap().join("approvers.toml");
        std::fs::write(
            &keys_path,
            format!("[approvers]\nalice = \"{}\"\n", kp.public_string()),
        )
        .unwrap();

        let mut req = request(&w, "2026-08-01T00:01:00Z");
        req.allow_unproven = false;
        req.trusted_keys = Some(&keys_path);
        promote(&req).unwrap();

        // Wrong key in the registry: refused, even though the file says approved.
        std::fs::write(&w.spec_path, SPEC).unwrap(); // restore base
        let other = kernel::sign::Keypair::generate().unwrap();
        std::fs::write(
            &keys_path,
            format!("[approvers]\nalice = \"{}\"\n", other.public_string()),
        )
        .unwrap();
        let err = promote(&req).unwrap_err();
        assert!(matches!(err, PromoteError::Refused(_)), "{err}");
    }

    #[test]
    fn an_unparseable_proposal_never_lands() {
        let w = world(AuthMethod::Claimed, None);
        std::fs::write(
            w.proposal_dir.join(PROPOSED_SPEC_FILE),
            ": not : valid : yaml : [",
        )
        .unwrap();
        let err = promote(&request(&w, "2026-08-01T00:01:00Z")).unwrap_err();
        assert!(matches!(err, PromoteError::Refused(_)), "{err}");
        assert_eq!(std::fs::read_to_string(&w.spec_path).unwrap(), SPEC);
    }
}
