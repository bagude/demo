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
/// ledger head (history custody), and the expiry (validity stretching).
/// Preconditions are a `BTreeMap`, so their order is canonical by
/// construction.
pub fn approval_message(
    cp: &Checkpoint,
    preconditions: &Preconditions,
    expiry: Option<&str>,
) -> String {
    let mut msg = String::from("harness-approval-v1\n");
    msg.push_str(&format!("gate: {}\n", cp.gate_id));
    msg.push_str(&format!("run: {}\n", cp.run_id));
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
        encode(&self.signing.sign(message.as_bytes()).to_bytes())
    }
}

/// Verify `signature` over `message` against a serialized public key.
pub fn verify(public: &str, message: &str, signature: &str) -> Result<(), SignError> {
    let key_bytes = decode(public, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    let key = VerifyingKey::from_bytes(&key)
        .map_err(|_| SignError::Format("public key is not a valid ed25519 point".into()))?;
    let sig_bytes = decode(signature, 64)?;
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    key.verify(message.as_bytes(), &Signature::from_bytes(&sig))
        .map_err(|_| SignError::Verification)
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
            "harness-approval-v1",
            "gate: approve-commit",
            "run: run-1",
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
