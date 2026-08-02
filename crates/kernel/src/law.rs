//! Guard Law evaluation.
//!
//! A Guard Law rejects an invalid proposed transition *before* execution. The
//! canonical example from the spec is *"only files listed in the task packet
//! may be edited"* — the packet's write-scope is the contract, and this module
//! is the deterministic code that enforces it. The model proposes; the kernel
//! disposes.

use crate::packet::TaskPacket;

/// Stable machine-readable denial codes, recorded to the Ledger as
/// `policy:<code>` on every denial. Human prose explains a refusal to a
/// person; the code is what lets an analyzer classify a thousand of them
/// without parsing sentences. Path-shape codes live in
/// [`crate::fsutil::codes`]; these are the policy-layer ones.
pub mod codes {
    /// No admitted packet is active — work has no authorization to be judged
    /// against.
    pub const NO_ACTIVE_PACKET: &str = "intake.no_active_packet";
    /// The target is not in the active packet's write scope.
    pub const FILE_SCOPE_OUTSIDE: &str = "file_scope.outside";
    /// The target is a protected enforcement artifact and the packet carries
    /// no `amends_enforcement` grant.
    pub const AMENDMENT_REQUIRED: &str = "enforcement.amendment_required";
    /// The target is a protected enforcement artifact outside the packet's
    /// write scope entirely.
    pub const PROTECTED_OUT_OF_SCOPE: &str = "enforcement.protected_out_of_scope";
    /// A destructive command would touch a protected enforcement artifact.
    pub const PROTECTED_DESTRUCTIVE: &str = "enforcement.protected_destructive";
    /// A required obligation is still outstanding at a gate.
    pub const OBLIGATION_OUTSTANDING: &str = "obligation.outstanding";
    /// The evaluating run carries no real identity (the legacy `unknown`
    /// fallback); run-scoped debt cannot be attributed, so the gate fails
    /// closed.
    pub const RUN_UNBOUND: &str = "identity.run_unbound";
    /// A Hive spawn was refused (depth, budget, contract, or conflict).
    pub const HIVE_REFUSED: &str = "hive.refused";
    /// A Hive settlement was refused (unknown reservation or overspend).
    pub const HIVE_SETTLEMENT_REFUSED: &str = "hive.settlement_refused";
}

/// A refusal with both faces: the stable `code` an analyzer matches on and
/// the human-readable `reason` a person acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    pub code: &'static str,
    pub reason: String,
}

impl Denial {
    pub fn new(code: &'static str, reason: impl Into<String>) -> Self {
        Denial {
            code,
            reason: reason.into(),
        }
    }
}

/// The verdict of a Guard Law on a proposed transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LawDecision {
    /// The transition is within contract and may proceed.
    Allow,
    /// The transition is rejected, with a human-readable reason.
    Deny(String),
}

impl LawDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, LawDecision::Allow)
    }

    /// The rejection reason, if this is a denial.
    pub fn reason(&self) -> Option<&str> {
        match self {
            LawDecision::Allow => None,
            LawDecision::Deny(r) => Some(r),
        }
    }
}

/// `enforce-file-scope`: a write to `path` is allowed only if the active task
/// packet lists `path` with write authority. This is the Guard Law that makes
/// "Verb within Law" real — the Verb runs, but every edit it proposes is
/// checked against the packet it was handed.
pub fn enforce_file_scope(packet: &TaskPacket, path: &str) -> LawDecision {
    if packet.authorizes_write(path) {
        LawDecision::Allow
    } else {
        LawDecision::Deny(format!(
            "'{path}' is not in the write scope of task packet '{}'; \
             only files the packet lists with access = \"write\" may be edited",
            packet.title
        ))
    }
}

/// The Guard verdict including the self-protection outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    /// Ordinary in-scope write.
    Allow,
    /// An in-scope write to a protected enforcement artifact, explicitly
    /// granted via `amends_enforcement` — allowed, but recorded distinctly.
    AllowAmendment,
    /// Rejected, with a stable code and a human-readable reason.
    Deny(Denial),
}

/// Whether `path` is a protected enforcement artifact.
///
/// `protected` holds path prefixes (a trailing `/` means a directory grant),
/// matched with the same semantics as a packet's write scope.
pub fn is_protected(protected: &[String], path: &str) -> bool {
    protected
        .iter()
        .any(|p| crate::packet::path_matches(p, path))
}

/// Full Guard evaluation with self-protection (constitution §4, self-protection
/// property).
///
/// Enforcement artifacts are default-deny like everything else, but editing one
/// *additionally* requires the packet to carry an explicit `amends_enforcement`
/// grant. A denylist that must remember to name protected paths is the
/// anti-pattern this replaces: here, protection rides on the same default-deny
/// allowlist, and amendment is never an ambient capability.
pub fn enforce(packet: &TaskPacket, path: &str, protected: &[String]) -> Enforcement {
    // Refuse a path that is absolute or escapes the workspace before any scope
    // reasoning — a traversal must never be able to reach a protected artifact.
    if crate::packet::normalize_components(path).is_none() {
        return Enforcement::Deny(Denial::new(
            crate::fsutil::codes::PATH_INVALID,
            format!(
                "'{path}' is absolute or escapes the workspace root; such paths are never authorized"
            ),
        ));
    }
    verdict(
        packet,
        path,
        packet.authorizes_write(path),
        is_protected(protected, path),
    )
}

/// [`enforce`], evaluated against the **canonical** target on the real
/// filesystem rooted at `root`.
///
/// Lexical checks hold on spelling; this holds on reality. Symlinks in the
/// existing portion of the path are resolved fully, so `src/link.rs` that IS
/// `harness/hooks/x.sh` is judged as the hook it is. Semantics, stated:
///
/// - **Authorization binds to the real target.** A write through a symlink is
///   in scope only if the *resolved* path is — to edit through a link,
///   scope the real target.
/// - **Protection covers both names.** The canonical target *and* the lexical
///   name written through are checked against the protected set.
/// - A path resolving outside the workspace, or through a dangling symlink,
///   is denied outright.
pub fn enforce_at(
    root: &std::path::Path,
    packet: &TaskPacket,
    path: &str,
    protected: &[String],
) -> Enforcement {
    let canonical = match crate::fsutil::canonical_workspace_rel(root, path) {
        Ok(c) => c,
        Err((code, reason)) => return Enforcement::Deny(Denial::new(code, reason)),
    };
    let lexical: String = crate::packet::normalize_components(path)
        .unwrap_or_default()
        .join("/");
    let display = if canonical == lexical {
        canonical.clone()
    } else {
        format!("{lexical}' -> '{canonical}")
    };
    verdict(
        packet,
        &display,
        packet.authorizes_write(&canonical),
        is_protected(protected, &canonical) || is_protected(protected, &lexical),
    )
}

/// The shared Guard branching over an already-resolved judgment.
fn verdict(packet: &TaskPacket, path: &str, in_scope: bool, hit_protected: bool) -> Enforcement {
    if hit_protected {
        if in_scope && packet.amends_enforcement {
            Enforcement::AllowAmendment
        } else if in_scope {
            Enforcement::Deny(Denial::new(
                codes::AMENDMENT_REQUIRED,
                format!(
                    "'{path}' is an enforcement artifact; editing it requires a task packet with \
                     amends_enforcement = true (an explicit, auditable grant at Intake)"
                ),
            ))
        } else {
            Enforcement::Deny(Denial::new(
                codes::PROTECTED_OUT_OF_SCOPE,
                format!(
                    "'{path}' is a protected enforcement artifact and is not in the packet's write scope"
                ),
            ))
        }
    } else if in_scope {
        Enforcement::Allow
    } else {
        Enforcement::Deny(Denial::new(
            codes::FILE_SCOPE_OUTSIDE,
            format!(
                "'{path}' is not in the write scope of task packet '{}'; only files the packet \
                 lists with access = \"write\" may be edited",
                packet.title
            ),
        ))
    }
}

/// If a Bash command performs a destructive operation touching a protected
/// path, return that path. Closes the hole where `rm harness/hooks/…` would
/// bypass the edit-only Guard. Heuristic (documented): a destructive verb or
/// output redirection plus a reference to a protected prefix.
pub fn bash_hits_protected(command: &str, protected: &[String]) -> Option<String> {
    const DESTRUCTIVE: &[&str] = &["rm", "rmdir", "mv", "truncate", "dd", "tee", "shred"];
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let destructive = tokens.iter().any(|t| DESTRUCTIVE.contains(t)) || command.contains('>');
    if !destructive {
        return None;
    }
    protected
        .iter()
        .find(|p| command.contains(p.trim_end_matches('/')))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{FileScope, Priority};

    fn packet() -> TaskPacket {
        TaskPacket {
            title: "scoped".into(),
            objective: "do the scoped thing".into(),
            constraints: vec![],
            files: vec![
                FileScope::write("src/lib.rs"),
                FileScope::read("src/other.rs"),
            ],
            acceptance_criteria: vec!["ok".into()],
            submitted_by: "me".into(),
            priority: Priority::Medium,
            amends_enforcement: false,
        }
    }

    #[test]
    fn allows_a_write_scoped_path() {
        assert!(enforce_file_scope(&packet(), "src/lib.rs").is_allowed());
    }

    #[test]
    fn denies_a_read_only_path() {
        let d = enforce_file_scope(&packet(), "src/other.rs");
        assert!(!d.is_allowed());
        assert!(d.reason().unwrap().contains("write scope"));
    }

    #[test]
    fn denies_an_unlisted_path() {
        assert!(!enforce_file_scope(&packet(), "src/secret.rs").is_allowed());
    }

    const PROTECTED: &[&str] = &["harness.patterns.yaml", ".claude/", "harness/"];

    fn protected() -> Vec<String> {
        PROTECTED.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn protected_artifact_denied_even_when_in_scope_without_grant() {
        // A packet that scopes an enforcement artifact but lacks the grant.
        let mut p = packet();
        p.files.push(FileScope::write(".claude/settings.json"));
        let d = enforce(&p, ".claude/settings.json", &protected());
        assert!(matches!(&d, Enforcement::Deny(den) if den.code == codes::AMENDMENT_REQUIRED));
    }

    #[test]
    fn protected_artifact_allowed_as_amendment_with_explicit_grant() {
        let mut p = packet();
        p.files.push(FileScope::write(".claude/settings.json"));
        p.amends_enforcement = true;
        assert_eq!(
            enforce(&p, ".claude/settings.json", &protected()),
            Enforcement::AllowAmendment
        );
    }

    #[test]
    fn ordinary_path_unaffected_by_protection() {
        assert_eq!(
            enforce(&packet(), "src/lib.rs", &protected()),
            Enforcement::Allow
        );
    }

    #[test]
    fn traversal_to_a_protected_artifact_is_denied() {
        // Even with a permissive scope, a `..` escape cannot reach a hook.
        let mut p = packet();
        p.files.push(FileScope::write("src/"));
        let d = enforce(
            &p,
            "src/../harness/hooks/enforce_file_scope.sh",
            &protected(),
        );
        assert!(matches!(
            &d,
            Enforcement::Deny(den)
                if den.code == crate::fsutil::codes::PATH_INVALID
                    && den.reason.contains("escapes the workspace")
        ));
    }

    #[cfg(unix)]
    mod canonical {
        use super::*;
        use std::os::unix::fs::symlink;

        fn scoped(scope: &str) -> TaskPacket {
            let mut p = packet();
            p.files = vec![FileScope::write(scope)];
            p
        }

        /// A workspace with a real hook and a src/ dir to plant links in.
        fn workspace() -> tempfile::TempDir {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("harness/hooks")).unwrap();
            std::fs::create_dir_all(dir.path().join("src")).unwrap();
            std::fs::create_dir_all(dir.path().join("docs")).unwrap();
            std::fs::write(dir.path().join("harness/hooks/guard.sh"), "#!/bin/sh\n").unwrap();
            std::fs::write(dir.path().join("docs/notes.md"), "notes").unwrap();
            dir
        }

        #[test]
        fn a_symlink_cannot_launder_a_protected_artifact_into_scope() {
            // THE bypass this exists to close: the packet scopes src/, and
            // src/guard.sh IS harness/hooks/guard.sh. Lexically in scope;
            // really a hook.
            let ws = workspace();
            symlink(
                ws.path().join("harness/hooks/guard.sh"),
                ws.path().join("src/guard.sh"),
            )
            .unwrap();
            let d = enforce_at(ws.path(), &scoped("src/"), "src/guard.sh", &protected());
            assert!(
                matches!(&d, Enforcement::Deny(r) if r.reason.contains("enforcement artifact")),
                "{d:?}"
            );
        }

        #[test]
        fn a_symlink_escaping_the_workspace_is_denied() {
            let ws = workspace();
            let outside = tempfile::tempdir().unwrap();
            symlink(outside.path(), ws.path().join("src/out")).unwrap();
            let d = enforce_at(ws.path(), &scoped("src/"), "src/out/x.rs", &protected());
            assert!(
                matches!(
                    &d,
                    Enforcement::Deny(r)
                        if r.code == crate::fsutil::codes::PATH_SYMLINK_ESCAPE
                            && r.reason.contains("outside the workspace")
                ),
                "{d:?}"
            );
        }

        #[test]
        fn authorization_binds_to_the_real_target() {
            let ws = workspace();
            symlink(ws.path().join("docs"), ws.path().join("src/d")).unwrap();
            // Scoped src/ only: the write really lands in docs/, so deny.
            let d = enforce_at(ws.path(), &scoped("src/"), "src/d/notes.md", &protected());
            assert!(
                matches!(
                    &d,
                    Enforcement::Deny(r)
                        if r.code == codes::FILE_SCOPE_OUTSIDE && r.reason.contains("write scope")
                ),
                "{d:?}"
            );
            // Scoped docs/ (the real target): the same write is allowed.
            let d = enforce_at(ws.path(), &scoped("docs/"), "src/d/notes.md", &protected());
            assert_eq!(d, Enforcement::Allow);
        }

        #[test]
        fn a_dangling_symlink_is_refused() {
            let ws = workspace();
            symlink(ws.path().join("nowhere"), ws.path().join("src/ghost")).unwrap();
            let d = enforce_at(ws.path(), &scoped("src/"), "src/ghost", &protected());
            assert!(
                matches!(
                    &d,
                    Enforcement::Deny(r)
                        if r.code == crate::fsutil::codes::PATH_DANGLING_SYMLINK
                            && r.reason.contains("dangling")
                ),
                "{d:?}"
            );
        }

        #[test]
        fn ordinary_paths_behave_exactly_as_before() {
            let ws = workspace();
            // Existing and not-yet-existing files, no links involved.
            assert_eq!(
                enforce_at(ws.path(), &scoped("docs/"), "docs/notes.md", &protected()),
                Enforcement::Allow
            );
            assert_eq!(
                enforce_at(ws.path(), &scoped("src/"), "src/new_file.rs", &protected()),
                Enforcement::Allow
            );
            assert!(matches!(
                enforce_at(ws.path(), &scoped("src/"), "docs/notes.md", &protected()),
                Enforcement::Deny(_)
            ));
            assert!(matches!(
                enforce_at(ws.path(), &scoped("src/"), "/etc/passwd", &protected()),
                Enforcement::Deny(_)
            ));
        }
    }

    #[test]
    fn bash_rm_of_a_hook_is_detected() {
        let hit = bash_hits_protected("rm -f harness/hooks/enforce_file_scope.sh", &protected());
        assert_eq!(hit.as_deref(), Some("harness/"));
    }

    #[test]
    fn innocuous_bash_is_not_flagged() {
        assert!(bash_hits_protected("ls -la src/", &protected()).is_none());
        // reading a protected file is fine; only destructive ops are flagged
        assert!(bash_hits_protected("cat harness/README.md", &protected()).is_none());
    }
}
