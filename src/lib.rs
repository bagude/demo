//! # Intake
//!
//! A Rust implementation of **The Intake** pattern from *A Pattern Language for
//! Agentic Composition*:
//!
//! > Work enters the system only as a typed artifact — objective, constraints,
//! > files, acceptance criteria — never as loose conversation. The packet
//! > becomes evidence in state, and the contract that Laws enforce against.
//!
//! The crate is split into four small pieces that mirror the pattern's
//! ingredients (*Invocable Workflow + structured task packet*):
//!
//! - [`packet`] — the typed [`TaskPacket`] and the admitted [`IntakeRecord`].
//! - [`validate`] — the deterministic **Guard Laws** that gate admission.
//! - [`ledger`] — the append-only [`Ledger`] that holds evidence in state.
//! - [`intake`] — the workflow that ties them together: validate, then record.
//!
//! ```
//! use intake::packet::{FileScope, Priority, TaskPacket};
//! use intake::{admit, AdmitError};
//!
//! let packet = TaskPacket {
//!     title: "Preserve rows in migration 0007".into(),
//!     objective: "Ensure migration 0007 does not drop rows with null ids".into(),
//!     constraints: vec!["No schema changes outside migrations/".into()],
//!     files: vec![FileScope::write("migrations/0007.sql")],
//!     acceptance_criteria: vec!["Row count is unchanged after migrating".into()],
//!     submitted_by: "alice".into(),
//!     priority: Priority::High,
//! };
//!
//! let record = admit(&packet, "2026-07-31T00:00:00Z".into())
//!     .expect("a complete packet is admissible");
//! assert!(record.packet.authorizes_write("migrations/0007.sql"));
//! ```

pub mod clock;
pub mod intake;
pub mod ledger;
pub mod packet;
pub mod validate;

pub use intake::{admit, AdmitError};
pub use ledger::Ledger;
pub use packet::{Access, FileScope, IntakeRecord, Priority, Status, TaskPacket};
pub use validate::{validate, Report, Violation};
