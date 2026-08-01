//! Runtime-instance identity: the third level of the identity model.
//!
//! Pattern **kind** exists at design time (`Delegate`); a composition **node**
//! exists at compile time (the position `worker`, resolved and checked in the
//! IR); a runtime **instance** exists at execution time — one concrete
//! occupant of that position in one run:
//!
//! ```text
//! run-42/worker/2
//! └─┬──┘ └─┬──┘ └┬┘
//!   run   position (an addressable node)   replica slot (1..=multiplicity)
//! ```
//!
//! The third segment addresses the **replica slot**, bounded by the
//! position's declared multiplicity. Execution *retries* are deliberately not
//! part of the identity path: the event envelope already carries `attempt_id`
//! for replay safety, and folding retries into the identity would make "the
//! same worker, tried again" a different worker.
//!
//! The compile-time → runtime bridge is the generated `positions.json`
//! registry: the addressable positions of the resolved graph with their
//! multiplicity bounds. Validating an instance against it is what makes the
//! IR's replication cardinality **enforceable at runtime** — an instance of a
//! position the architecture never declared, or a replica slot beyond the
//! declared multiplicity, is refused rather than quietly accepted. This is
//! what per-instance Gate approval and instance-scoped obligations stand on.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

/// One runtime instance: `<run>/<position>/<slot>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceId {
    pub run_id: String,
    pub position: String,
    /// Replica slot, 1-based, bounded by the position's multiplicity.
    pub slot: u32,
}

impl InstanceId {
    /// Parse the strict `<run>/<position>/<slot>` form: exactly three
    /// non-empty segments, slot a decimal ≥ 1.
    pub fn parse(s: &str) -> Result<InstanceId, InstanceError> {
        let parts: Vec<&str> = s.split('/').collect();
        let [run_id, position, slot] = parts.as_slice() else {
            return Err(InstanceError::Malformed(format!(
                "'{s}' is not <run>/<position>/<slot>"
            )));
        };
        if run_id.is_empty() || position.is_empty() {
            return Err(InstanceError::Malformed(format!(
                "'{s}' has an empty run or position segment"
            )));
        }
        let slot: u32 =
            slot.parse().ok().filter(|n| *n >= 1).ok_or_else(|| {
                InstanceError::Malformed(format!("'{s}' slot must be a decimal ≥ 1"))
            })?;
        Ok(InstanceId {
            run_id: run_id.to_string(),
            position: position.to_string(),
            slot,
        })
    }
}

impl fmt::Display for InstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.run_id, self.position, self.slot)
    }
}

/// Why an instance was refused.
#[derive(Debug)]
pub enum InstanceError {
    Malformed(String),
    /// The named position is not in the compiled architecture.
    UnknownPosition(String),
    /// The replica slot exceeds the position's declared multiplicity.
    SlotOutOfRange {
        position: String,
        slot: u32,
        multiplicity: u32,
    },
    Registry(String),
    Io(std::io::Error),
}

impl fmt::Display for InstanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstanceError::Malformed(what) => write!(f, "malformed instance: {what}"),
            InstanceError::UnknownPosition(p) => write!(
                f,
                "position '{p}' is not an addressable position of the compiled architecture"
            ),
            InstanceError::SlotOutOfRange {
                position,
                slot,
                multiplicity,
            } => write!(
                f,
                "slot {slot} of position '{position}' exceeds its declared multiplicity \
                 {multiplicity}; the architecture stands for exactly that many instances"
            ),
            InstanceError::Registry(what) => write!(f, "positions registry: {what}"),
            InstanceError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for InstanceError {}

impl From<std::io::Error> for InstanceError {
    fn from(e: std::io::Error) -> Self {
        InstanceError::Io(e)
    }
}

/// The compiled positions registry: addressable position → multiplicity, as
/// the generated `positions.json` records them from the resolved graph.
#[derive(Debug, Clone, Default)]
pub struct PositionRegistry {
    positions: BTreeMap<String, u32>,
}

impl PositionRegistry {
    pub fn load(path: &Path) -> Result<PositionRegistry, InstanceError> {
        let text = std::fs::read_to_string(path)?;
        let v: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| InstanceError::Registry(format!("not valid JSON: {e}")))?;
        let entries = v
            .get("positions")
            .and_then(|p| p.as_array())
            .ok_or_else(|| InstanceError::Registry("no positions array".into()))?;
        let mut positions = BTreeMap::new();
        for entry in entries {
            let name = entry
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| InstanceError::Registry("position entry has no name".into()))?;
            let multiplicity = entry
                .get("multiplicity")
                .and_then(|m| m.as_u64())
                .and_then(|m| u32::try_from(m).ok())
                .filter(|m| *m >= 1)
                .ok_or_else(|| {
                    InstanceError::Registry(format!("position '{name}' has no valid multiplicity"))
                })?;
            positions.insert(name.to_string(), multiplicity);
        }
        Ok(PositionRegistry { positions })
    }

    /// Whether `instance` names a declared position within its multiplicity
    /// bound — the runtime enforcement of the IR's replication cardinality.
    pub fn validate(&self, instance: &InstanceId) -> Result<(), InstanceError> {
        let multiplicity = self
            .positions
            .get(&instance.position)
            .copied()
            .ok_or_else(|| InstanceError::UnknownPosition(instance.position.clone()))?;
        if instance.slot > multiplicity {
            return Err(InstanceError::SlotOutOfRange {
                position: instance.position.clone(),
                slot: instance.slot,
                multiplicity,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display_roundtrip() {
        let i = InstanceId::parse("run-42/worker/2").unwrap();
        assert_eq!(
            i,
            InstanceId {
                run_id: "run-42".into(),
                position: "worker".into(),
                slot: 2
            }
        );
        assert_eq!(i.to_string(), "run-42/worker/2");
    }

    #[test]
    fn malformed_instances_are_refused() {
        for bad in [
            "",
            "run-42/worker",           // two segments
            "run-42/worker/2/extra",   // four
            "run-42//2",               // empty position
            "/worker/2",               // empty run
            "run-42/worker/0",         // slot below 1
            "run-42/worker/attempt-2", // non-decimal slot: retries live on attempt_id
        ] {
            assert!(InstanceId::parse(bad).is_err(), "'{bad}' must be refused");
        }
    }

    #[test]
    fn the_registry_enforces_declared_positions_and_multiplicity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("positions.json");
        std::fs::write(
            &path,
            r#"{"positions":[{"name":"w","kind":"Delegate","multiplicity":3},
                             {"name":"deployer","kind":"Port","multiplicity":1}]}"#,
        )
        .unwrap();
        let reg = PositionRegistry::load(&path).unwrap();

        let ok = |s: &str| reg.validate(&InstanceId::parse(s).unwrap());
        assert!(ok("run-1/w/1").is_ok());
        assert!(ok("run-1/w/3").is_ok(), "the full declared range is valid");
        assert!(
            matches!(
                ok("run-1/w/4"),
                Err(InstanceError::SlotOutOfRange {
                    slot: 4,
                    multiplicity: 3,
                    ..
                })
            ),
            "the architecture stands for exactly three workers"
        );
        assert!(matches!(
            ok("run-1/ghost/1"),
            Err(InstanceError::UnknownPosition(_))
        ));
        assert!(ok("run-1/deployer/1").is_ok());
        assert!(ok("run-1/deployer/2").is_err(), "singletons have one slot");
    }
}
