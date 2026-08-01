//! # kernel — the trusted runtime kernel
//!
//! The deterministic core the model operates *inside*. Compiled harnesses
//! (produced by `harnessc` from a `harness.patterns.yaml`) generate thin hook
//! shims and commands; those shims call this kernel to do the parts that must
//! not be left to model good intentions — validating packets, enforcing Guard
//! Laws, recording evidence, and holding gate checkpoints.
//!
//! Modules, grouped by the primitive they serve:
//!
//! - [`packet`] / [`validate`] / [`intake`] — **The Intake**: work enters only
//!   as a typed [`TaskPacket`], admitted by deterministic Guard Laws.
//! - [`ledger`] — the append-only task-packet store (Intake evidence).
//! - [`event`] — the append-only **Ledger** of governed actions and decisions.
//! - [`law`] — evaluation of a **Guard Law** against a proposed tool action.
//! - [`gate`] — **Gate** checkpoints with approval binding and precondition
//!   revalidation.
//!
//! ```
//! use kernel::packet::{FileScope, Priority, TaskPacket};
//! use kernel::{admit, AdmitError};
//!
//! let packet = TaskPacket {
//!     title: "Preserve rows in migration 0007".into(),
//!     objective: "Ensure migration 0007 does not drop rows with null ids".into(),
//!     constraints: vec!["No schema changes outside migrations/".into()],
//!     files: vec![FileScope::write("migrations/0007.sql")],
//!     acceptance_criteria: vec!["Row count is unchanged after migrating".into()],
//!     submitted_by: "alice".into(),
//!     priority: Priority::High,
//!     amends_enforcement: false,
//! };
//!
//! let record = admit(&packet, "2026-07-31T00:00:00Z".into())
//!     .expect("a complete packet is admissible");
//! assert!(record.packet.authorizes_write("migrations/0007.sql"));
//! ```

pub mod clock;
pub mod event;
pub mod fsutil;
pub mod gate;
pub mod hive;
pub mod intake;
pub mod law;
pub mod ledger;
pub mod obligation;
pub mod packet;
pub mod validate;

/// The kernel's own implementation source, embedded at compile time. Hashing
/// these bytes yields a content-addressed identity for the enforcement binary
/// itself — one that changes whenever the enforcement logic changes, even if no
/// version number is bumped. This is deliberately the *source* rather than the
/// built executable: the digest is reproducible for the same source, lock, and
/// toolchain without requiring bit-reproducible builds, while two different
/// source trees never collide.
const KERNEL_SOURCE: &[&str] = &[
    include_str!("lib.rs"),
    include_str!("event.rs"),
    include_str!("law.rs"),
    include_str!("gate.rs"),
    include_str!("obligation.rs"),
    include_str!("packet.rs"),
    include_str!("validate.rs"),
    include_str!("intake.rs"),
    include_str!("ledger.rs"),
    include_str!("hive.rs"),
    include_str!("clock.rs"),
    include_str!("fsutil.rs"),
    include_str!("bin/kernel.rs"),
    include_str!("bin/intake.rs"),
];

/// The workspace dependency lock, embedded at compile time. Enforcement
/// behavior is a function of dependencies too (the JSON parser, the TOML
/// parser, the hash implementation), so the lock is part of the kernel's
/// identity.
const KERNEL_LOCKFILE: &str = include_str!("../../../Cargo.lock");

/// The toolchain that built this kernel (`rustc --version --verbose`),
/// captured by `build.rs`. The same source compiled by a different rustc is a
/// different enforcement binary.
const KERNEL_TOOLCHAIN: &str = env!("KERNEL_RUSTC_VERSION");

/// Content digest of the kernel implementation that is executing — the runtime
/// identity stamped into every governed [`Event`]: implementation source,
/// dependency lock, and toolchain. Length-prefixed per unit so no
/// rearrangement of boundaries can produce a collision.
pub fn kernel_ref() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let units = KERNEL_SOURCE
        .iter()
        .copied()
        .chain([KERNEL_LOCKFILE, KERNEL_TOOLCHAIN]);
    for unit in units {
        hasher.update((unit.len() as u64).to_le_bytes());
        hasher.update(unit.as_bytes());
    }
    let digest = hasher.finalize();
    let mut s = String::from("sha256:");
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub use event::{
    line_digest, ChainError, ChainReport, Decision, Event, EventLog, Record, CHAIN_GENESIS,
};
pub use gate::{ApprovalBinding, Approver, AuthMethod, Checkpoint, GateError, GateStore};
pub use hive::{first_write_conflict, validate_spawn, HiveViolation, SpawnRequest};
pub use intake::{admit, AdmitError};
pub use law::{bash_hits_protected, enforce, enforce_file_scope, Enforcement, LawDecision};
pub use ledger::Ledger;
pub use packet::{Access, FileScope, IntakeRecord, Priority, Status, TaskPacket};
pub use validate::{validate, Report, Violation};

#[cfg(test)]
mod kernel_ref_tests {
    use super::*;

    #[test]
    fn kernel_ref_is_a_stable_sha256() {
        let a = kernel_ref();
        let b = kernel_ref();
        assert_eq!(a, b, "the running binary has one identity");
        assert!(a.starts_with("sha256:"));
        assert_eq!(a.len(), "sha256:".len() + 64);
    }

    #[test]
    fn kernel_ref_is_content_addressed_to_the_real_implementation() {
        // Guard against a regression to a version-label identity: the digest must
        // fold in the actual enforcement source, so the embedded corpus really is
        // the kernel's own code (e.g. the pre-tool guard entrypoint).
        assert!(!KERNEL_SOURCE.is_empty());
        let corpus: String = KERNEL_SOURCE.concat();
        assert!(corpus.contains("blocked by enforce-file-scope"));
        assert!(corpus.contains("fn pre_tool"));
    }

    #[test]
    fn kernel_ref_binds_the_dependency_lock_and_toolchain() {
        // Identical source built against different dependency versions or a
        // different rustc is a different enforcement binary; the embedded lock
        // and toolchain identity are what let the digest tell them apart.
        assert!(
            KERNEL_LOCKFILE.contains("[[package]]"),
            "the embedded lockfile is the real Cargo.lock"
        );
        assert!(
            KERNEL_TOOLCHAIN.starts_with("rustc"),
            "the toolchain identity comes from the actual rustc: {KERNEL_TOOLCHAIN}"
        );
        assert!(
            KERNEL_TOOLCHAIN.contains("host:"),
            "--verbose identity includes the host triple: {KERNEL_TOOLCHAIN}"
        );
    }
}
