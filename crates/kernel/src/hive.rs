//! The Law of the Hive.
//!
//! The dangerous fan-out mode is recursive dynamic spawning, so the
//! constitution makes the Law an operational schema: *every spawned task must
//! have a parent, a contract, a budget, a depth, a termination condition, a
//! merge destination, and a declared read/write scope.* This module is the
//! deterministic backstop — an orchestrator asks the kernel to validate each
//! spawn before it runs, and concurrent workers are checked for conflict
//! discipline (disjoint write scopes).

use serde::{Deserialize, Serialize};

/// A request to spawn one task inside a Hive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnRequest {
    /// The parent task id — no orphan spawns.
    pub parent: String,
    /// The typed contract the spawned task returns against.
    pub contract: String,
    /// The token/resource budget granted to this task.
    pub budget: u64,
    /// This task's depth in the fan-out tree.
    pub depth: u32,
    /// The condition under which the task stops.
    pub termination: String,
    /// Where this task's result is merged.
    pub merge: String,
    /// The paths this task is authorized to write (its declared write scope).
    #[serde(default)]
    pub write_scope: Vec<String>,
}

/// Why a spawn was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HiveViolation {
    MissingParent,
    MissingContract,
    ZeroBudget,
    BudgetExceeded { requested: u64, remaining: u64 },
    DepthExceeded { depth: u32, max: u32 },
    MissingTermination,
    MissingMerge,
    UndeclaredScope,
}

impl std::fmt::Display for HiveViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HiveViolation::MissingParent => write!(f, "spawn has no parent"),
            HiveViolation::MissingContract => write!(f, "spawn has no typed contract"),
            HiveViolation::ZeroBudget => write!(f, "spawn has a zero budget"),
            HiveViolation::BudgetExceeded {
                requested,
                remaining,
            } => {
                write!(f, "spawn budget {requested} exceeds remaining {remaining}")
            }
            HiveViolation::DepthExceeded { depth, max } => {
                write!(f, "spawn depth {depth} exceeds max {max}")
            }
            HiveViolation::MissingTermination => write!(f, "spawn has no termination condition"),
            HiveViolation::MissingMerge => write!(f, "spawn has no merge destination"),
            HiveViolation::UndeclaredScope => write!(f, "spawn has no declared write scope"),
        }
    }
}

impl std::error::Error for HiveViolation {}

/// Validate one spawn against the Hive's caps. `budget_remaining` is the pool
/// left for the fan-out; `max_depth` is the recursion backstop.
pub fn validate_spawn(
    req: &SpawnRequest,
    max_depth: u32,
    budget_remaining: u64,
) -> Result<(), HiveViolation> {
    if req.parent.trim().is_empty() {
        return Err(HiveViolation::MissingParent);
    }
    if req.contract.trim().is_empty() {
        return Err(HiveViolation::MissingContract);
    }
    if req.budget == 0 {
        return Err(HiveViolation::ZeroBudget);
    }
    if req.budget > budget_remaining {
        return Err(HiveViolation::BudgetExceeded {
            requested: req.budget,
            remaining: budget_remaining,
        });
    }
    if req.depth > max_depth {
        return Err(HiveViolation::DepthExceeded {
            depth: req.depth,
            max: max_depth,
        });
    }
    if req.termination.trim().is_empty() {
        return Err(HiveViolation::MissingTermination);
    }
    if req.merge.trim().is_empty() {
        return Err(HiveViolation::MissingMerge);
    }
    if req.write_scope.is_empty() {
        return Err(HiveViolation::UndeclaredScope);
    }
    Ok(())
}

/// Conflict discipline: concurrent workers must have disjoint declared write
/// sets. Returns the first overlapping `(i, j, path)` if any two requests share
/// write authority — the distributed form of the Sandbox drift obligation.
///
/// Overlap is decided on normalized path components, not string equality, so
/// `src/` and `src/lib.rs` are correctly recognized as conflicting.
pub fn first_write_conflict(reqs: &[SpawnRequest]) -> Option<(usize, usize, String)> {
    for i in 0..reqs.len() {
        for j in (i + 1)..reqs.len() {
            for a in &reqs[i].write_scope {
                if reqs[j]
                    .write_scope
                    .iter()
                    .any(|b| crate::packet::scopes_overlap(a, b))
                {
                    return Some((i, j, a.clone()));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> SpawnRequest {
        SpawnRequest {
            parent: "root".into(),
            contract: "FindingSchema".into(),
            budget: 1000,
            depth: 1,
            termination: "no new work".into(),
            merge: "root.results".into(),
            write_scope: vec!["shard-a/".into()],
        }
    }

    #[test]
    fn a_complete_spawn_is_valid() {
        assert!(validate_spawn(&req(), 3, 10_000).is_ok());
    }

    #[test]
    fn depth_and_budget_caps_are_enforced() {
        let mut r = req();
        r.depth = 5;
        assert!(matches!(
            validate_spawn(&r, 3, 10_000),
            Err(HiveViolation::DepthExceeded { .. })
        ));
        let mut r = req();
        r.budget = 20_000;
        assert!(matches!(
            validate_spawn(&r, 3, 10_000),
            Err(HiveViolation::BudgetExceeded { .. })
        ));
    }

    #[test]
    fn every_required_field_is_checked() {
        let mut r = req();
        r.write_scope.clear();
        assert_eq!(
            validate_spawn(&r, 3, 10_000),
            Err(HiveViolation::UndeclaredScope)
        );
        let mut r = req();
        r.termination = "".into();
        assert_eq!(
            validate_spawn(&r, 3, 10_000),
            Err(HiveViolation::MissingTermination)
        );
    }

    #[test]
    fn overlapping_write_scopes_are_a_conflict() {
        let mut a = req();
        a.write_scope = vec!["shard-a/".into()];
        let mut b = req();
        b.write_scope = vec!["shard-a/".into()];
        assert_eq!(
            first_write_conflict(&[a, b]),
            Some((0, 1, "shard-a/".into()))
        );
    }

    #[test]
    fn disjoint_write_scopes_are_fine() {
        let mut a = req();
        a.write_scope = vec!["shard-a/".into()];
        let mut b = req();
        b.write_scope = vec!["shard-b/".into()];
        assert!(first_write_conflict(&[a, b]).is_none());
    }

    #[test]
    fn nested_write_scopes_are_a_conflict() {
        // A directory scope and a file beneath it must be recognized as
        // conflicting, not just identical strings.
        let mut a = req();
        a.write_scope = vec!["src/".into()];
        let mut b = req();
        b.write_scope = vec!["src/lib.rs".into()];
        assert!(first_write_conflict(&[a, b]).is_some());
    }
}
