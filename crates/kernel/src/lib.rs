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

pub use event::{Decision, Event, EventLog};
pub use gate::{ApprovalBinding, Approver, AuthMethod, Checkpoint, GateError, GateStore};
pub use hive::{first_write_conflict, validate_spawn, HiveViolation, SpawnRequest};
pub use intake::{admit, AdmitError};
pub use law::{bash_hits_protected, enforce, enforce_file_scope, Enforcement, LawDecision};
pub use ledger::Ledger;
pub use packet::{Access, FileScope, IntakeRecord, Priority, Status, TaskPacket};
pub use validate::{validate, Report, Violation};
