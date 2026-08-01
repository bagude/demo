//! Signature-authenticated Gate approvals — the custody edge made
//! cryptographic.
//!
//! The Ledger chain proves its own history and the Gate checkpoint anchors the
//! chain head, but both live on the same disk: a party who can rewrite the
//! ledger *and* every checkpoint anchoring it defeats file-level custody. A
//! signed approval moves that boundary to key custody: the approver signs the
//! **canonical approval message** — gate, run, action hash, the precondition
//! snapshot, the anchored ledger head, and the expiry — with an Ed25519 key
//! the kernel never holds. `gate approve --auth signature` refuses to record
//! an approval whose signature does not verify against the trusted-keys
//! registry, and `gate verify` re-verifies the stored signature at resume, so
//! a rewritten checkpoint (a different action, a different ledger head, a
//! stretched expiry) invalidates the approval no matter what the file claims.
//!
//! What this does NOT provide: key distribution or revocation (the
//! trusted-keys file is host configuration, held to the same custody standard
//! as the kernel binary itself) and online identity (an IdP integration would
//! bind principals to organizational identity; this binds them to keys).

use std::fmt;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::gate::{Checkpoint, Preconditions};

/// Prefix for every serialized key and signature, so the artifact names its
/// own algorithm.
const SCHEME: &str = "ed25519";

/// Why signing or verification failed.
#[derive(Debug)]
pub enum SignError {
    /// A key or signature string was not in the expected `ed25519:<hex>` form.
    Format(String),
    /// The signature did not verify over the canonical message.
    Verification,
    /// The trusted-keys registry has no entry for this principal.
    UnknownPrincipal(String),
    Io(std::io::Error),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::Format(what) => write!(f, "malformed key or signature: {what}"),
            SignError::Verification => write!(
                f,
                "signature does not verify over the canonical approval message"
            ),
            SignError::UnknownPrincipal(p) => {
                write!(f, "no trusted key registered for principal '{p}'")
            }
            SignError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for SignError {}

impl From<std::io::Error> for SignError {
    fn from(e: std::io::Error) -> Self {
        SignError::Io(e)
    }
}

/// The canonical, versioned serialization of what an approver approves. The
/// signature covers the *world-state binding*, not a bare "yes": the action
/// hash (substitution), the precondition snapshot (TOCTOU), the anchored
/// ledger head (history custody), the runtime instance (a per-worker approval
/// is that worker's alone), and the expiry (validity stretching).
/// Preconditions are a `BTreeMap`, so their order is canonical by
/// construction. v2 added the `instance` line; v1 signatures do not verify
/// against v2 messages — deliberately, since the binding they attested to
/// said nothing about instances.
pub fn approval_message(
    cp: &Checkpoint,
    preconditions: &Preconditions,
    expiry: Option<&str>,
) -> String {
    let mut msg = String::from("harness-approval-v2\n");
    msg.push_str(&format!("gate: {}\n", cp.gate_id));
    msg.push_str(&format!("run: {}\n", cp.run_id));
    msg.push_str(&format!(
        "instance: {}\n",
        cp.instance.as_deref().unwrap_or("-")
    ));
    msg.push_str(&format!("action: {}\n", cp.action_hash));
    for (k, v) in preconditions {
        msg.push_str(&format!("precondition: {k}={v}\n"));
    }
    msg.push_str(&format!(
        "ledger_head: {}\n",
        cp.ledger_head.as_deref().unwrap_or("-")
    ));
    msg.push_str(&format!("expiry: {}\n", expiry.unwrap_or("-")));
    msg
}

/// An approver's Ed25519 keypair, held only where approvals are minted —
/// never by the kernel enforcing them.
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Generate from the OS entropy source.
    pub fn generate() -> Result<Keypair, SignError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| SignError::Format(format!("entropy source unavailable: {e}")))?;
        Ok(Keypair {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Parse from the serialized private form (`ed25519:<64 hex>` seed).
    pub fn from_seed_str(s: &str) -> Result<Keypair, SignError> {
        let bytes = decode(s, 32)?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Keypair {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// The serialized private seed. A secret: written mode 0600, never logged,
    /// never placed in the Ledger.
    pub fn seed_string(&self) -> String {
        encode(&self.signing.to_bytes())
    }

    /// The serialized public key — the value the trusted-keys registry holds.
    pub fn public_string(&self) -> String {
        encode(self.signing.verifying_key().as_bytes())
    }

    /// Sign a canonical message; the signature is evidence, not a secret.
    pub fn sign(&self, message: &str) -> String {
        self.sign_bytes(message.as_bytes())
    }

    /// Sign raw bytes — e.g. an identity registry's exact file contents, so a
    /// detached signature needs no canonicalization at all.
    pub fn sign_bytes(&self, bytes: &[u8]) -> String {
        encode(&self.signing.sign(bytes).to_bytes())
    }
}

/// Verify `signature` over `message` against a serialized public key.
pub fn verify(public: &str, message: &str, signature: &str) -> Result<(), SignError> {
    verify_bytes(public, message.as_bytes(), signature)
}

/// Verify `signature` over raw bytes against a serialized public key.
pub fn verify_bytes(public: &str, bytes: &[u8], signature: &str) -> Result<(), SignError> {
    let key_bytes = decode(public, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    let key = VerifyingKey::from_bytes(&key)
        .map_err(|_| SignError::Format("public key is not a valid ed25519 point".into()))?;
    let sig_bytes = decode(signature, 64)?;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    key.verify(bytes, &Signature::from_bytes(&sig))
        .map_err(|_| SignError::Verification)
}

/// Why re-proving a stored signature-authenticated approval failed.
#[derive(Debug)]
pub enum ReverifyError {
    /// The checkpoint carries no approval at all.
    NotApproved,
    /// The approval is not signature-authenticated — there is no signature to
    /// re-prove. Callers enforcing a signature policy refuse on this.
    NotSignatureAuthenticated,
    /// The approval claims signature auth but carries no signature evidence.
    NoEvidence,
    /// The approver could not be resolved through the current registry
    /// (unknown, revoked, or the registry document itself was refused).
    Identity(crate::identity::IdentityError),
    /// The stored signature does not verify over the checkpoint's current
    /// contents.
    Signature(SignError),
}

impl fmt::Display for ReverifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReverifyError::NotApproved => write!(f, "no approval recorded for this checkpoint"),
            ReverifyError::NotSignatureAuthenticated => {
                write!(f, "approval is not signature-authenticated")
            }
            ReverifyError::NoEvidence => write!(
                f,
                "signature-authenticated approval carries no signature evidence"
            ),
            ReverifyError::Identity(e) => write!(f, "{e}"),
            ReverifyError::Signature(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ReverifyError {}

/// Re-prove a stored signature-authenticated approval from the checkpoint's
/// **current** contents. The canonical message is rebuilt from what the file
/// says *now* — action, precondition snapshot, anchored ledger head, instance,
/// expiry — so a rewrite of any covered field invalidates the signature no
/// matter what the file claims. The approver's key is resolved through the
/// **current** registry (with a pinned `authority`, a verified, unexpired,
/// non-rolled-back signed document), so a principal revoked since approval is
/// refused — which is exactly what revocation means.
///
/// This is the single canonical composition of that check: `gate verify` and
/// the Refinery's promotion both call it, so the two resume paths cannot
/// drift apart.
pub fn reverify_signed_approval(
    cp: &Checkpoint,
    trusted_keys: &Path,
    authority: Option<&str>,
    now: &str,
) -> Result<(), ReverifyError> {
    let approval = cp.approval.as_ref().ok_or(ReverifyError::NotApproved)?;
    if !matches!(approval.approver.auth, crate::gate::AuthMethod::Signature) {
        return Err(ReverifyError::NotSignatureAuthenticated);
    }
    let evidence = approval
        .approver
        .evidence
        .as_ref()
        .ok_or(ReverifyError::NoEvidence)?;
    let authority = authority
        .map(crate::identity::resolve_authority)
        .transpose()
        .map_err(ReverifyError::Identity)?;
    let registry = crate::identity::Registry::load(trusted_keys, authority.as_deref(), now)
        .map_err(ReverifyError::Identity)?;
    let public = registry
        .key_for(&approval.approver.principal)
        .map_err(ReverifyError::Identity)?;
    let message = approval_message(cp, &approval.preconditions, approval.expiry.as_deref());
    verify(public, &message, evidence).map_err(ReverifyError::Signature)
}

/// Look up a principal's public key in the trusted-keys registry — a TOML file
/// with an `[approvers]` table mapping principal to `ed25519:<hex>`:
///
/// ```toml
/// [approvers]
/// alice = "ed25519:9d61b19d..."
/// ```
///
/// The registry is host configuration with the same custody standard as the
/// kernel binary: whoever can edit it can add approvers.
pub fn trusted_key_for(path: &Path, principal: &str) -> Result<String, SignError> {
    let text = std::fs::read_to_string(path)?;
    let value: toml::Value = text
        .parse()
        .map_err(|e| SignError::Format(format!("trusted-keys file is not valid TOML: {e}")))?;
    value
        .get("approvers")
        .and_then(|a| a.get(principal))
        .and_then(|k| k.as_str())
        .map(String::from)
        .ok_or_else(|| SignError::UnknownPrincipal(principal.to_string()))
}

fn encode(bytes: &[u8]) -> String {
    let mut s = format!("{SCHEME}:");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn decode(s: &str, expect_len: usize) -> Result<Vec<u8>, SignError> {
    let hex = s
        .strip_prefix(&format!("{SCHEME}:"))
        .ok_or_else(|| SignError::Format(format!("expected '{SCHEME}:<hex>', got '{s}'")))?;
    if hex.len() != expect_len * 2 {
        return Err(SignError::Format(format!(
            "expected {} hex chars, got {}",
            expect_len * 2,
            hex.len()
        )));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| SignError::Format("non-hex characters".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn checkpoint() -> Checkpoint {
        Checkpoint::new(
            "approve-commit",
            "run-1",
            "sha256:action",
            "ship it",
            "resume",
            BTreeMap::from([("repository_revision".into(), "abc123".into())]),
            "2026-08-01T00:00:00Z",
        )
        .anchoring_ledger_head(Some("sha256:head".into()))
        .for_instance(Some("run-1/deployer/1".into()))
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = Keypair::generate().unwrap();
        let cp = checkpoint();
        let msg = approval_message(&cp, &cp.preconditions.clone(), Some("2026-09-01T00:00:00Z"));
        let sig = kp.sign(&msg);
        assert!(verify(&kp.public_string(), &msg, &sig).is_ok());
    }

    #[test]
    fn a_different_key_or_message_fails() {
        let kp = Keypair::generate().unwrap();
        let other = Keypair::generate().unwrap();
        let cp = checkpoint();
        let msg = approval_message(&cp, &cp.preconditions.clone(), None);
        let sig = kp.sign(&msg);
        assert!(matches!(
            verify(&other.public_string(), &msg, &sig),
            Err(SignError::Verification)
        ));
        // Any covered field moving invalidates: here, the anchored head.
        let moved = checkpoint().anchoring_ledger_head(Some("sha256:other".into()));
        let msg2 = approval_message(&moved, &moved.preconditions.clone(), None);
        assert!(verify(&kp.public_string(), &msg2, &sig).is_err());
    }

    #[test]
    fn the_message_covers_the_whole_world_state_binding() {
        let cp = checkpoint();
        let msg = approval_message(&cp, &cp.preconditions.clone(), Some("2026-09-01T00:00:00Z"));
        for needle in [
            "harness-approval-v2",
            "gate: approve-commit",
            "run: run-1",
            "instance: run-1/deployer/1",
            "action: sha256:action",
            "precondition: repository_revision=abc123",
            "ledger_head: sha256:head",
            "expiry: 2026-09-01T00:00:00Z",
        ] {
            assert!(msg.contains(needle), "missing {needle} in:\n{msg}");
        }
    }

    #[test]
    fn seed_roundtrips_and_keys_are_distinct() {
        let kp = Keypair::generate().unwrap();
        let again = Keypair::from_seed_str(&kp.seed_string()).unwrap();
        assert_eq!(kp.public_string(), again.public_string());
        assert_ne!(
            Keypair::generate().unwrap().public_string(),
            kp.public_string()
        );
    }

    #[test]
    fn trusted_registry_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvers.toml");
        let kp = Keypair::generate().unwrap();
        std::fs::write(
            &path,
            format!("[approvers]\nalice = \"{}\"\n", kp.public_string()),
        )
        .unwrap();
        assert_eq!(trusted_key_for(&path, "alice").unwrap(), kp.public_string());
        assert!(matches!(
            trusted_key_for(&path, "mallory"),
            Err(SignError::UnknownPrincipal(_))
        ));
    }
}
