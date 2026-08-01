//! Gates: execution halts at a boundary and persists a durable checkpoint.
//!
//! The spec is emphatic that a Gate is *not* a confirmation prompt. Approval
//! attaches to **an action hash, the relevant precondition snapshot, the
//! approver identity, and optionally an expiry**. If the action or any material
//! precondition changes, approval is invalidated and must be renewed. The
//! checkpoint is durable, so resumption can happen in a different process — a
//! cron job, CI, or a fresh container — and it *revalidates* before proceeding.
//!
//! Binding the artifact alone prevents substitution; binding preconditions
//! prevents time-of-check/time-of-use errors.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A precondition snapshot: concurrency tokens whose values must be unchanged
/// for an approval to remain valid (e.g. `repository_revision -> "abc123"`,
/// `working_tree_hash -> "sha256:..."`).
pub type Preconditions = BTreeMap<String, String>;

/// How an approver's identity was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// The caller merely asserted the name — no proof. The honest default; not
    /// to be mistaken for authentication.
    Claimed,
    /// Established by a bearer token/credential (reference kept as evidence).
    Token,
    /// Established by a verified signature (reference kept as evidence).
    Signature,
}

/// An approver identity that separates a display label from *how* — and
/// whether — the identity was authenticated. Recording `Claimed` keeps the log
/// honest: it says "the caller said this was the approver", not "this approver
/// was authenticated".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approver {
    /// The principal's display name or id.
    pub principal: String,
    /// How the identity was established.
    pub auth: AuthMethod,
    /// Reference to the authentication evidence — never the secret itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

impl Approver {
    /// An unauthenticated, caller-asserted identity.
    pub fn claimed(principal: impl Into<String>) -> Self {
        Approver {
            principal: principal.into(),
            auth: AuthMethod::Claimed,
            evidence: None,
        }
    }

    /// Whether the identity was authenticated (anything other than `Claimed`).
    pub fn is_authenticated(&self) -> bool {
        !matches!(self.auth, AuthMethod::Claimed)
    }
}

/// An approval bound to a specific action and precondition snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalBinding {
    pub approver: Approver,
    /// Must equal the checkpoint's `action_hash`.
    pub action_hash: String,
    /// The precondition values the approver signed off against.
    pub preconditions: Preconditions,
    pub approved_at: String,
    /// Optional RFC 3339 expiry. Compared lexicographically, which is correct
    /// for zero-padded UTC timestamps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
}

/// A durable record of a halted transition awaiting (or carrying) approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub gate_id: String,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Hash of the proposed action — binding the artifact prevents substitution.
    pub action_hash: String,
    /// Human-readable summary of what would execute.
    pub action_summary: String,
    /// The expected precondition values at the time the checkpoint was taken.
    #[serde(default)]
    pub preconditions: Preconditions,
    /// Where execution resumes once approved.
    pub continuation: String,
    pub created_at: String,
    /// Obligation ids that must be discharged before this Gate will resume.
    #[serde(default)]
    pub requires_obligations: Vec<String>,
    /// The Ledger chain head at checkpoint time — the external anchor that
    /// closes the chain's one blind spot. A hash chain proves everything
    /// except tail truncation; a checkpoint that survives process death is
    /// exactly the durable out-of-band place to pin the head, so at resume
    /// the Gate can refuse a log whose history no longer contains it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger_head: Option<String>,
    /// Present once a decision has been recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalBinding>,
}

/// Why a Gate refused to let execution resume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    /// No approval has been recorded yet.
    NotApproved,
    /// The proposed action differs from the approved one.
    ActionChanged { approved: String, current: String },
    /// A material precondition moved since approval (TOCTOU guard).
    PreconditionDrift {
        token: String,
        approved: String,
        current: String,
    },
    /// The approval has expired.
    Expired { expiry: String, now: String },
    /// A required obligation is still outstanding.
    ObligationOutstanding { obligation: String },
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::NotApproved => write!(f, "no approval recorded for this checkpoint"),
            GateError::ActionChanged { approved, current } => write!(
                f,
                "action changed since approval (approved {approved}, now {current}); \
                 approval invalidated"
            ),
            GateError::PreconditionDrift {
                token,
                approved,
                current,
            } => write!(
                f,
                "precondition '{token}' drifted since approval (approved '{approved}', \
                 now '{current}'); approval invalidated"
            ),
            GateError::Expired { expiry, now } => {
                write!(f, "approval expired at {expiry} (now {now})")
            }
            GateError::ObligationOutstanding { obligation } => {
                write!(
                    f,
                    "obligation '{obligation}' is still outstanding; discharge it first"
                )
            }
        }
    }
}

impl std::error::Error for GateError {}

impl Checkpoint {
    /// Create a fresh, unapproved checkpoint.
    pub fn new(
        gate_id: impl Into<String>,
        run_id: impl Into<String>,
        action_hash: impl Into<String>,
        action_summary: impl Into<String>,
        continuation: impl Into<String>,
        preconditions: Preconditions,
        created_at: impl Into<String>,
    ) -> Self {
        Checkpoint {
            gate_id: gate_id.into(),
            run_id: run_id.into(),
            task_id: None,
            action_hash: action_hash.into(),
            action_summary: action_summary.into(),
            preconditions,
            continuation: continuation.into(),
            created_at: created_at.into(),
            requires_obligations: Vec::new(),
            ledger_head: None,
            approval: None,
        }
    }

    /// Declare obligations that must be discharged before this Gate resumes.
    pub fn requiring_obligations(mut self, obligations: Vec<String>) -> Self {
        self.requires_obligations = obligations;
        self
    }

    /// Anchor the Ledger chain head this checkpoint was taken against. At
    /// resume, a log whose history no longer contains this head — truncated or
    /// rewritten — is refused (see `EventLog::verify_anchor`).
    pub fn anchoring_ledger_head(mut self, head: Option<String>) -> Self {
        self.ledger_head = head;
        self
    }

    /// Refuse to resume while any required obligation is still in `outstanding`.
    /// The caller computes `outstanding` from the Ledger (see
    /// [`crate::obligation::outstanding`]); the Gate stays the policy point.
    pub fn check_obligations(&self, outstanding: &[String]) -> Result<(), GateError> {
        for required in &self.requires_obligations {
            if outstanding.iter().any(|o| o == required) {
                return Err(GateError::ObligationOutstanding {
                    obligation: required.clone(),
                });
            }
        }
        Ok(())
    }

    /// Record an approval against this checkpoint's current action and
    /// preconditions. The `approver` carries how the identity was established;
    /// an unauthenticated approval is recorded honestly as `Claimed`.
    pub fn approve(
        &mut self,
        approver: Approver,
        approved_at: impl Into<String>,
        expiry: Option<String>,
    ) {
        self.approval = Some(ApprovalBinding {
            approver,
            action_hash: self.action_hash.clone(),
            preconditions: self.preconditions.clone(),
            approved_at: approved_at.into(),
            expiry,
        });
    }

    /// Revalidate the approval against the *current* action hash and
    /// precondition values, at time `now`. This is what resumption calls before
    /// executing — approval passing at checkpoint time proves nothing about a
    /// world that has since moved.
    pub fn revalidate(
        &self,
        current_action_hash: &str,
        current_preconditions: &Preconditions,
        now: &str,
    ) -> Result<&ApprovalBinding, GateError> {
        let approval = self.approval.as_ref().ok_or(GateError::NotApproved)?;

        if approval.action_hash != current_action_hash {
            return Err(GateError::ActionChanged {
                approved: approval.action_hash.clone(),
                current: current_action_hash.to_string(),
            });
        }

        for (token, approved_val) in &approval.preconditions {
            let current_val = current_preconditions
                .get(token)
                .map(String::as_str)
                .unwrap_or("");
            if current_val != approved_val {
                return Err(GateError::PreconditionDrift {
                    token: token.clone(),
                    approved: approved_val.clone(),
                    current: current_val.to_string(),
                });
            }
        }

        if let Some(expiry) = &approval.expiry {
            if now > expiry.as_str() {
                return Err(GateError::Expired {
                    expiry: expiry.clone(),
                    now: now.to_string(),
                });
            }
        }

        Ok(approval)
    }
}

/// A durable, file-backed store of checkpoints under a directory. Durability is
/// what lets a Gate suspend across process death (the Night Shift requirement).
pub struct GateStore {
    dir: PathBuf,
}

impl GateStore {
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        GateStore { dir: dir.into() }
    }

    fn checkpoint_path(&self, gate_id: &str, action_hash: &str) -> PathBuf {
        // Derive the filename from a hash of the identifiers rather than
        // interpolating them: a gate_id or action_hash containing '/' or '..'
        // must never be able to escape the checkpoint directory. The
        // human-readable values live inside the JSON body. NUL-separated so
        // ("a", "bc") and ("ab", "c") cannot collide.
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(gate_id.as_bytes());
        h.update([0u8]);
        h.update(action_hash.as_bytes());
        let digest = h.finalize();
        let mut name = String::with_capacity(64);
        for b in digest {
            name.push_str(&format!("{b:02x}"));
        }
        self.dir.join(format!("{name}.json"))
    }

    /// Persist a checkpoint durably and atomically (pretty JSON for human
    /// inspection). A crash mid-save can never leave a truncated checkpoint.
    pub fn save(&self, checkpoint: &Checkpoint) -> io::Result<PathBuf> {
        let path = self.checkpoint_path(&checkpoint.gate_id, &checkpoint.action_hash);
        let json = serde_json::to_string_pretty(checkpoint)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        crate::fsutil::atomic_write(&path, json.as_bytes())?;
        Ok(path)
    }

    /// Load a checkpoint from an explicit path.
    pub fn load(path: &Path) -> io::Result<Checkpoint> {
        let text = fs::read_to_string(path)?;
        serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preconds(rev: &str) -> Preconditions {
        let mut p = Preconditions::new();
        p.insert("repository_revision".into(), rev.into());
        p
    }

    fn checkpoint() -> Checkpoint {
        Checkpoint::new(
            "approve-commit",
            "run-1",
            "sha256:action-aaaa",
            "commit 3 files",
            "resume:commit",
            preconds("rev-1"),
            "2026-07-31T00:00:00Z",
        )
    }

    #[test]
    fn unapproved_checkpoint_cannot_resume() {
        let cp = checkpoint();
        let err = cp.revalidate(
            "sha256:action-aaaa",
            &preconds("rev-1"),
            "2026-07-31T00:00:01Z",
        );
        assert_eq!(err.unwrap_err(), GateError::NotApproved);
    }

    #[test]
    fn approval_revalidates_when_nothing_moved() {
        let mut cp = checkpoint();
        cp.approve(Approver::claimed("alice"), "2026-07-31T00:00:05Z", None);
        assert!(cp
            .revalidate(
                "sha256:action-aaaa",
                &preconds("rev-1"),
                "2026-07-31T00:00:06Z"
            )
            .is_ok());
    }

    #[test]
    fn changed_action_invalidates_approval() {
        let mut cp = checkpoint();
        cp.approve(Approver::claimed("alice"), "2026-07-31T00:00:05Z", None);
        let err = cp
            .revalidate(
                "sha256:action-DIFFERENT",
                &preconds("rev-1"),
                "2026-07-31T00:00:06Z",
            )
            .unwrap_err();
        assert!(matches!(err, GateError::ActionChanged { .. }));
    }

    #[test]
    fn precondition_drift_invalidates_approval() {
        let mut cp = checkpoint();
        cp.approve(Approver::claimed("alice"), "2026-07-31T00:00:05Z", None);
        // The repository advanced between approval and resume: TOCTOU guard.
        let err = cp
            .revalidate(
                "sha256:action-aaaa",
                &preconds("rev-2"),
                "2026-07-31T00:00:06Z",
            )
            .unwrap_err();
        assert!(matches!(err, GateError::PreconditionDrift { .. }));
    }

    #[test]
    fn expired_approval_is_refused() {
        let mut cp = checkpoint();
        cp.approve(
            Approver::claimed("alice"),
            "2026-07-31T00:00:05Z",
            Some("2026-07-31T01:00:00Z".into()),
        );
        let err = cp
            .revalidate(
                "sha256:action-aaaa",
                &preconds("rev-1"),
                "2026-07-31T02:00:00Z",
            )
            .unwrap_err();
        assert!(matches!(err, GateError::Expired { .. }));
    }

    #[test]
    fn outstanding_obligation_blocks_the_gate() {
        let cp = checkpoint().requiring_obligations(vec!["require-validation".into()]);
        // Open obligation: refused.
        let err = cp
            .check_obligations(&["require-validation".to_string()])
            .unwrap_err();
        assert!(matches!(err, GateError::ObligationOutstanding { .. }));
        // Discharged (nothing outstanding): allowed.
        assert!(cp.check_obligations(&[]).is_ok());
    }

    #[test]
    fn save_then_load_roundtrips_durably() {
        let dir = tempfile::tempdir().unwrap();
        let store = GateStore::at(dir.path());
        let mut cp = checkpoint();
        cp.approve(Approver::claimed("alice"), "2026-07-31T00:00:05Z", None);
        let path = store.save(&cp).unwrap();
        // A different process could load this: durable suspension.
        let loaded = GateStore::load(&path).unwrap();
        assert_eq!(loaded, cp);
    }

    #[test]
    fn claimed_identity_is_not_treated_as_authenticated() {
        let mut cp = checkpoint();
        cp.approve(Approver::claimed("alice"), "2026-07-31T00:00:05Z", None);
        let approver = &cp.approval.as_ref().unwrap().approver;
        assert_eq!(approver.principal, "alice");
        assert!(
            !approver.is_authenticated(),
            "a caller-asserted name is not authentication"
        );

        let authed = Approver {
            principal: "ci-bot".into(),
            auth: AuthMethod::Token,
            evidence: Some("oidc:sub=...".into()),
        };
        assert!(authed.is_authenticated());
    }
}
