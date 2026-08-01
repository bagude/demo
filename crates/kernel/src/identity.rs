//! The identity registry: approver keys bound to organizational identity by a
//! signing **authority** — the offline trust core of an IdP integration.
//!
//! PR-of-record boundary from the signature layer: the trusted-keys file was
//! host configuration, so whoever could edit it could add approvers. This
//! module closes that. The registry becomes an **identity document**:
//!
//! ```toml
//! [registry]
//! issuer = "acme-security"
//! serial = 7                       # monotonic; replays of older documents refused
//! expires_at = "2026-11-01T00:00:00Z"
//!
//! [approvers]
//! alice = "ed25519:9d61b19d..."
//!
//! [revoked]
//! carol = "2026-07-15T00:00:00Z key compromise"
//! ```
//!
//! signed by the authority as a **detached signature over the file's exact
//! bytes** (`<registry>.sig`) — no canonicalization, no ambiguity: edit one
//! byte and verification fails. The kernel pins only the authority's public
//! key; every approver key, revocation, and validity window flows from
//! documents that key signed. Custody moves again: from registry-file custody
//! to **authority-key custody**.
//!
//! Revocation is retroactive at the Gate: `gate verify --authority` resolves
//! the approver through the current registry, so a checkpoint approved by a
//! since-revoked key stops resuming — the approval was valid when minted and
//! is refused now, which is exactly what revocation means.
//!
//! Stated boundaries, plainly: the rollback high-water mark (`<registry>.hwm`)
//! is same-disk state, so the *hard* bound on replaying an old signed
//! document is its `expires_at` — issuers must roll documents, and short
//! validity windows are the real defense. And this binds principals to keys
//! under an authority; binding the authority itself to an online IdP (OIDC
//! issuance, directory sync) is a protocol adapter this module deliberately
//! does not fake.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use crate::sign::{self, SignError};

/// Why an identity registry, or a lookup in it, was refused.
#[derive(Debug)]
pub enum IdentityError {
    /// The registry file or its detached signature failed cryptographically.
    Sign(SignError),
    /// The registry document is malformed or missing required fields.
    Registry(String),
    /// The document's validity window has closed.
    Expired {
        expires_at: String,
        now: String,
    },
    /// The document is older than one this kernel has already accepted.
    Rollback {
        serial: u64,
        seen: u64,
    },
    /// The principal's key has been explicitly withdrawn.
    Revoked {
        principal: String,
        note: String,
    },
    /// No key is registered for this principal.
    UnknownPrincipal(String),
    Io(std::io::Error),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::Sign(e) => write!(f, "registry signature: {e}"),
            IdentityError::Registry(what) => write!(f, "registry: {what}"),
            IdentityError::Expired { expires_at, now } => write!(
                f,
                "registry expired at {expires_at} (now {now}); obtain a current signed registry"
            ),
            IdentityError::Rollback { serial, seen } => write!(
                f,
                "registry serial {serial} is older than the highest accepted ({seen}); \
                 refusing a rolled-back identity document"
            ),
            IdentityError::Revoked { principal, note } => {
                write!(f, "principal '{principal}' is revoked ({note})")
            }
            IdentityError::UnknownPrincipal(p) => {
                write!(f, "no key registered for principal '{p}'")
            }
            IdentityError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<SignError> for IdentityError {
    fn from(e: SignError) -> Self {
        IdentityError::Sign(e)
    }
}

impl From<std::io::Error> for IdentityError {
    fn from(e: std::io::Error) -> Self {
        IdentityError::Io(e)
    }
}

/// A loaded (and, when an authority is pinned, verified) identity registry.
#[derive(Debug)]
pub struct Registry {
    pub issuer: Option<String>,
    pub serial: Option<u64>,
    pub expires_at: Option<String>,
    /// Whether this registry was authority-verified, or merely read as plain
    /// host configuration (no authority pinned).
    pub verified: bool,
    approvers: BTreeMap<String, String>,
    revoked: BTreeMap<String, String>,
}

impl Registry {
    /// Load the registry at `path`. With an `authority` public key pinned, the
    /// detached `<path>.sig` must verify over the file's exact bytes, the
    /// `[registry]` table must carry `serial` and `expires_at`, the document
    /// must be unexpired at `now`, and its serial must not roll back behind
    /// the high-water mark. Without an authority the file is read as plain
    /// host configuration — custody of the file is custody of the approvers,
    /// and `verified` stays false so callers can say which they got.
    pub fn load(
        path: &Path,
        authority: Option<&str>,
        now: &str,
    ) -> Result<Registry, IdentityError> {
        let bytes = std::fs::read(path)?;
        let text = String::from_utf8(bytes.clone())
            .map_err(|_| IdentityError::Registry("registry is not UTF-8".into()))?;
        let value: toml::Value = text
            .parse()
            .map_err(|e| IdentityError::Registry(format!("not valid TOML: {e}")))?;

        let table = |name: &str| -> BTreeMap<String, String> {
            value
                .get(name)
                .and_then(|t| t.as_table())
                .map(|t| {
                    t.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut registry = Registry {
            issuer: value
                .get("registry")
                .and_then(|r| r.get("issuer"))
                .and_then(|i| i.as_str())
                .map(String::from),
            serial: value
                .get("registry")
                .and_then(|r| r.get("serial"))
                .and_then(|s| s.as_integer())
                .and_then(|s| u64::try_from(s).ok()),
            expires_at: value
                .get("registry")
                .and_then(|r| r.get("expires_at"))
                .and_then(|e| e.as_str())
                .map(String::from),
            verified: false,
            approvers: table("approvers"),
            revoked: table("revoked"),
        };

        let Some(authority) = authority else {
            return Ok(registry);
        };

        // Authority pinned: the document must prove itself before any key in
        // it is trusted. Signature first — nothing else in the file means
        // anything until the bytes are the authority's bytes.
        let sig_path = signature_path(path);
        let signature = std::fs::read_to_string(&sig_path).map_err(|e| {
            IdentityError::Registry(format!(
                "authority pinned but no detached signature at {}: {e}",
                sig_path.display()
            ))
        })?;
        sign::verify_bytes(authority, &bytes, signature.trim())?;

        // A signed document must bound its own validity: an issuer that never
        // expires its registries makes every replay permanent.
        let serial = registry.serial.ok_or_else(|| {
            IdentityError::Registry("signed registry must carry [registry] serial".into())
        })?;
        let expires_at = registry.expires_at.clone().ok_or_else(|| {
            IdentityError::Registry("signed registry must carry [registry] expires_at".into())
        })?;
        // Lexicographic compare is correct for zero-padded UTC RFC 3339, the
        // same convention the Gate's expiry uses.
        if now >= expires_at.as_str() {
            return Err(IdentityError::Expired {
                expires_at,
                now: now.to_string(),
            });
        }

        // Best-effort rollback defense: remember the highest serial accepted.
        // Same-disk state, stated as such — expiry is the hard bound.
        let hwm_path = {
            let mut name = path
                .file_name()
                .map(|n| n.to_os_string())
                .unwrap_or_default();
            name.push(".hwm");
            path.with_file_name(name)
        };
        let seen = std::fs::read_to_string(&hwm_path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok());
        if let Some(seen) = seen {
            if serial < seen {
                return Err(IdentityError::Rollback { serial, seen });
            }
        }
        if seen != Some(serial) {
            if let Err(e) = std::fs::write(&hwm_path, format!("{serial}\n")) {
                eprintln!(
                    "warning: could not persist registry high-water mark {}: {e}",
                    hwm_path.display()
                );
            }
        }

        registry.verified = true;
        Ok(registry)
    }

    /// The public key for `principal`. Revocation wins over registration —
    /// a principal listed in both is refused with the revocation note.
    pub fn key_for(&self, principal: &str) -> Result<&str, IdentityError> {
        if let Some(note) = self.revoked.get(principal) {
            return Err(IdentityError::Revoked {
                principal: principal.to_string(),
                note: note.clone(),
            });
        }
        self.approvers
            .get(principal)
            .map(String::as_str)
            .ok_or_else(|| IdentityError::UnknownPrincipal(principal.to_string()))
    }

    pub fn approver_count(&self) -> usize {
        self.approvers.len()
    }

    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }
}

/// Where a registry's detached signature lives: `<registry>.sig`.
pub fn signature_path(registry: &Path) -> std::path::PathBuf {
    let mut name = registry
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".sig");
    registry.with_file_name(name)
}

/// Resolve an `--authority` argument: a literal `ed25519:<hex>` public key,
/// or a path to a file whose first line is one.
pub fn resolve_authority(spec: &str) -> Result<String, IdentityError> {
    if spec.starts_with("ed25519:") {
        return Ok(spec.to_string());
    }
    let text = std::fs::read_to_string(spec)?;
    let line = text.trim();
    if line.starts_with("ed25519:") {
        Ok(line.to_string())
    } else {
        Err(IdentityError::Registry(format!(
            "authority file {spec} does not contain an ed25519 public key"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Keypair;

    const NOW: &str = "2026-08-01T00:00:00Z";

    fn write_signed(
        dir: &Path,
        authority: &Keypair,
        serial: u64,
        expires_at: &str,
        body: &str,
    ) -> std::path::PathBuf {
        let path = dir.join("approvers.toml");
        let text = format!(
            "[registry]\nissuer = \"acme\"\nserial = {serial}\nexpires_at = \"{expires_at}\"\n\n{body}"
        );
        std::fs::write(&path, &text).unwrap();
        let sig = authority.sign_bytes(text.as_bytes());
        std::fs::write(signature_path(&path), format!("{sig}\n")).unwrap();
        path
    }

    #[test]
    fn a_signed_registry_verifies_and_resolves_keys() {
        let dir = tempfile::tempdir().unwrap();
        let authority = Keypair::generate().unwrap();
        let alice = Keypair::generate().unwrap();
        let path = write_signed(
            dir.path(),
            &authority,
            1,
            "2027-01-01T00:00:00Z",
            &format!("[approvers]\nalice = \"{}\"\n", alice.public_string()),
        );
        let reg = Registry::load(&path, Some(&authority.public_string()), NOW).unwrap();
        assert!(reg.verified);
        assert_eq!(reg.issuer.as_deref(), Some("acme"));
        assert_eq!(reg.key_for("alice").unwrap(), alice.public_string());
    }

    #[test]
    fn one_edited_byte_refuses_the_whole_document() {
        let dir = tempfile::tempdir().unwrap();
        let authority = Keypair::generate().unwrap();
        let mallory = Keypair::generate().unwrap();
        let path = write_signed(
            dir.path(),
            &authority,
            1,
            "2027-01-01T00:00:00Z",
            "[approvers]\n",
        );
        // The attack the signature exists for: adding an approver to the file.
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str(&format!("mallory = \"{}\"\n", mallory.public_string()));
        std::fs::write(&path, text).unwrap();
        assert!(matches!(
            Registry::load(&path, Some(&authority.public_string()), NOW),
            Err(IdentityError::Sign(_))
        ));
    }

    #[test]
    fn the_wrong_authority_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let authority = Keypair::generate().unwrap();
        let other = Keypair::generate().unwrap();
        let path = write_signed(
            dir.path(),
            &authority,
            1,
            "2027-01-01T00:00:00Z",
            "[approvers]\n",
        );
        assert!(Registry::load(&path, Some(&other.public_string()), NOW).is_err());
    }

    #[test]
    fn expiry_and_missing_metadata_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let authority = Keypair::generate().unwrap();
        let path = write_signed(
            dir.path(),
            &authority,
            1,
            "2026-07-01T00:00:00Z", // already past NOW
            "[approvers]\n",
        );
        assert!(matches!(
            Registry::load(&path, Some(&authority.public_string()), NOW),
            Err(IdentityError::Expired { .. })
        ));

        // A signed registry without validity metadata is refused: an issuer
        // that never expires documents makes every replay permanent.
        let bare = dir.path().join("bare.toml");
        let text = "[approvers]\n";
        std::fs::write(&bare, text).unwrap();
        let sig = authority.sign_bytes(text.as_bytes());
        std::fs::write(signature_path(&bare), sig).unwrap();
        assert!(matches!(
            Registry::load(&bare, Some(&authority.public_string()), NOW),
            Err(IdentityError::Registry(_))
        ));
    }

    #[test]
    fn an_older_serial_is_refused_after_a_newer_one_was_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let authority = Keypair::generate().unwrap();
        let pk = authority.public_string();
        let path = write_signed(
            dir.path(),
            &authority,
            5,
            "2027-01-01T00:00:00Z",
            "[approvers]\n",
        );
        assert!(Registry::load(&path, Some(&pk), NOW).is_ok());
        // The issuer rolls serial 4 back onto disk (a replayed old document).
        write_signed(
            dir.path(),
            &authority,
            4,
            "2027-01-01T00:00:00Z",
            "[approvers]\n",
        );
        assert!(matches!(
            Registry::load(&path, Some(&pk), NOW),
            Err(IdentityError::Rollback { serial: 4, seen: 5 })
        ));
    }

    #[test]
    fn revocation_wins_over_registration() {
        let dir = tempfile::tempdir().unwrap();
        let authority = Keypair::generate().unwrap();
        let alice = Keypair::generate().unwrap();
        let path = write_signed(
            dir.path(),
            &authority,
            1,
            "2027-01-01T00:00:00Z",
            &format!(
                "[approvers]\nalice = \"{}\"\n\n[revoked]\nalice = \"2026-07-15 key compromise\"\n",
                alice.public_string()
            ),
        );
        let reg = Registry::load(&path, Some(&authority.public_string()), NOW).unwrap();
        assert!(matches!(
            reg.key_for("alice"),
            Err(IdentityError::Revoked { .. })
        ));
    }

    #[test]
    fn without_an_authority_the_file_is_plain_host_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let alice = Keypair::generate().unwrap();
        let path = dir.path().join("approvers.toml");
        std::fs::write(
            &path,
            format!(
                "[approvers]\nalice = \"{}\"\n[revoked]\nbob = \"gone\"\n",
                alice.public_string()
            ),
        )
        .unwrap();
        let reg = Registry::load(&path, None, NOW).unwrap();
        assert!(!reg.verified, "unverified is said plainly");
        assert_eq!(reg.key_for("alice").unwrap(), alice.public_string());
        // Revocation is honored even in unsigned mode.
        assert!(matches!(
            reg.key_for("bob"),
            Err(IdentityError::Revoked { .. })
        ));
    }
}
