//! The Law of the Hive.
//!
//! The dangerous fan-out mode is recursive dynamic spawning, so the
//! constitution makes the Law an operational schema: *every spawned task must
//! have a parent, a contract, a budget, a depth, a termination condition, a
//! merge destination, and a declared read/write scope.* This module is the
//! deterministic backstop — an orchestrator asks the kernel to validate each
//! spawn before it runs, and concurrent workers are checked for conflict
//! discipline (disjoint write scopes).
//!
//! **Transactional budget.** A cap the caller self-reports against is not a
//! cap: two racing spawns each told "10 000 remaining" jointly reserve
//! 20 000. The [`BudgetPool`] makes the budget a durable resource — one state
//! file per Hive, mutated only under an exclusive on-disk lock and persisted
//! atomically. `reserve` takes tokens out of the pool before the spawn runs
//! (refused when the pool cannot cover it, idempotent on replay of the same
//! reservation), and `settle` converts a reservation into recorded spend,
//! returning the unspent remainder to the pool. Racing spawns serialize on
//! the lock; the pool can never overshoot its total.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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

/// Why a budget-pool operation was refused.
#[derive(Debug)]
pub enum BudgetError {
    /// No pool exists for this Hive — `hive init` must create it first.
    NoPool(String),
    /// The pool exists with a different total; a re-init must agree.
    TotalMismatch {
        existing: u64,
        requested: u64,
    },
    /// The pool cannot cover the requested reservation.
    Insufficient {
        requested: u64,
        remaining: u64,
    },
    /// The spawn id is already reserved with a different amount. (The same
    /// amount is an idempotent replay and succeeds.)
    ReservationConflict {
        spawn_id: String,
        existing: u64,
        requested: u64,
    },
    /// Settling a reservation that does not exist.
    UnknownReservation(String),
    /// Settling more than was reserved.
    Overspend {
        spent: u64,
        reserved: u64,
    },
    /// The pool lock could not be acquired.
    Locked(String),
    Io(std::io::Error),
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetError::NoPool(hive) => {
                write!(
                    f,
                    "no budget pool for hive '{hive}'; run `kernel hive init` first"
                )
            }
            BudgetError::TotalMismatch {
                existing,
                requested,
            } => write!(
                f,
                "pool already exists with total {existing}, not {requested}; a budget is not \
                 renegotiated by re-declaring it"
            ),
            BudgetError::Insufficient {
                requested,
                remaining,
            } => write!(
                f,
                "reservation of {requested} exceeds the pool's remaining {remaining}"
            ),
            BudgetError::ReservationConflict {
                spawn_id,
                existing,
                requested,
            } => write!(
                f,
                "spawn '{spawn_id}' already holds a reservation of {existing}, not {requested}"
            ),
            BudgetError::UnknownReservation(id) => {
                write!(f, "no reservation to settle for spawn '{id}'")
            }
            BudgetError::Overspend { spent, reserved } => write!(
                f,
                "settling {spent} exceeds the {reserved} reserved; spend beyond a reservation \
                 was never authorized"
            ),
            BudgetError::Locked(path) => write!(
                f,
                "budget pool is locked by another operation ({path}); if no spawn is in \
                 progress the lock is stale and may be removed"
            ),
            BudgetError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for BudgetError {}

impl From<std::io::Error> for BudgetError {
    fn from(e: std::io::Error) -> Self {
        BudgetError::Io(e)
    }
}

/// The durable state of one Hive's token pool.
/// `remaining = total - spent - Σ reservations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolState {
    pub hive: String,
    pub total: u64,
    #[serde(default)]
    pub spent: u64,
    #[serde(default)]
    pub reservations: BTreeMap<String, u64>,
}

impl PoolState {
    pub fn reserved(&self) -> u64 {
        self.reservations.values().sum()
    }

    pub fn remaining(&self) -> u64 {
        self.total.saturating_sub(self.spent + self.reserved())
    }
}

/// A Hive's durable budget pool: state in `<store>/<hive>.budget.json`,
/// mutated only under an exclusive lock file and persisted with the atomic
/// write sequence, so concurrent spawners serialize instead of double-
/// reserving and a crash mid-update never leaves a torn pool.
pub struct BudgetPool {
    hive: String,
    path: PathBuf,
    lock: PathBuf,
}

impl BudgetPool {
    pub fn at(store: &Path, hive: &str) -> BudgetPool {
        BudgetPool {
            hive: hive.to_string(),
            path: store.join(format!("{hive}.budget.json")),
            lock: store.join(format!("{hive}.budget.lock")),
        }
    }

    /// Create the pool (idempotent when the total agrees; refused when it
    /// does not — a budget is not renegotiated by re-declaring it).
    pub fn init(&self, total: u64) -> Result<PoolState, BudgetError> {
        self.locked(|| match self.load()? {
            None => {
                let state = PoolState {
                    hive: self.hive.clone(),
                    total,
                    spent: 0,
                    reservations: BTreeMap::new(),
                };
                self.save(&state)?;
                Ok(state)
            }
            Some(existing) if existing.total == total => Ok(existing),
            Some(existing) => Err(BudgetError::TotalMismatch {
                existing: existing.total,
                requested: total,
            }),
        })
    }

    /// Atomically reserve `amount` for `spawn_id`. Replay-safe: the same id
    /// re-reserving the same amount is a no-op success; a different amount is
    /// a conflict.
    pub fn reserve(&self, spawn_id: &str, amount: u64) -> Result<PoolState, BudgetError> {
        self.locked(|| {
            let mut state = self
                .load()?
                .ok_or_else(|| BudgetError::NoPool(self.hive.clone()))?;
            if let Some(&existing) = state.reservations.get(spawn_id) {
                return if existing == amount {
                    Ok(state)
                } else {
                    Err(BudgetError::ReservationConflict {
                        spawn_id: spawn_id.to_string(),
                        existing,
                        requested: amount,
                    })
                };
            }
            if amount > state.remaining() {
                return Err(BudgetError::Insufficient {
                    requested: amount,
                    remaining: state.remaining(),
                });
            }
            state.reservations.insert(spawn_id.to_string(), amount);
            self.save(&state)?;
            Ok(state)
        })
    }

    /// Settle `spawn_id`'s reservation: record `spent` (≤ reserved) as
    /// consumed and return the remainder to the pool. `spent = 0` releases
    /// the reservation entirely (a failed or cancelled worker).
    pub fn settle(&self, spawn_id: &str, spent: u64) -> Result<PoolState, BudgetError> {
        self.locked(|| {
            let mut state = self
                .load()?
                .ok_or_else(|| BudgetError::NoPool(self.hive.clone()))?;
            let reserved = state
                .reservations
                .get(spawn_id)
                .copied()
                .ok_or_else(|| BudgetError::UnknownReservation(spawn_id.to_string()))?;
            if spent > reserved {
                return Err(BudgetError::Overspend { spent, reserved });
            }
            state.reservations.remove(spawn_id);
            state.spent += spent;
            self.save(&state)?;
            Ok(state)
        })
    }

    /// The pool state, read without mutating (still under the lock, so a
    /// concurrent update is never observed half-applied).
    pub fn state(&self) -> Result<PoolState, BudgetError> {
        self.locked(|| {
            self.load()?
                .ok_or_else(|| BudgetError::NoPool(self.hive.clone()))
        })
    }

    fn load(&self) -> Result<Option<PoolState>, BudgetError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(Some(serde_json::from_str(&text).map_err(|e| {
                BudgetError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(BudgetError::Io(e)),
        }
    }

    fn save(&self, state: &PoolState) -> Result<(), BudgetError> {
        let json = serde_json::to_string_pretty(state).map_err(|e| {
            BudgetError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        crate::fsutil::atomic_write(&self.path, json.as_bytes())?;
        Ok(())
    }

    /// Run `f` holding the exclusive pool lock (an `O_EXCL` lock file, the
    /// portable primitive). Contenders retry briefly, then fail loudly naming
    /// the lock so a stale one — a crash mid-operation — is an operator
    /// decision, never silently stolen.
    fn locked<T>(&self, f: impl FnOnce() -> Result<T, BudgetError>) -> Result<T, BudgetError> {
        if let Some(parent) = self.lock.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut acquired = false;
        for _ in 0..250 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&self.lock)
            {
                Ok(_) => {
                    acquired = true;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => return Err(BudgetError::Io(e)),
            }
        }
        if !acquired {
            return Err(BudgetError::Locked(self.lock.display().to_string()));
        }
        let result = f();
        let _ = std::fs::remove_file(&self.lock);
        result
    }
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

    // ---- transactional budget pool -----------------------------------------

    #[test]
    fn reserve_settle_lifecycle_conserves_the_pool() {
        let dir = tempfile::tempdir().unwrap();
        let pool = BudgetPool::at(dir.path(), "research");
        pool.init(10_000).unwrap();
        // Re-init with the same total is idempotent; a different total is not.
        assert!(pool.init(10_000).is_ok());
        assert!(matches!(
            pool.init(99),
            Err(BudgetError::TotalMismatch {
                existing: 10_000,
                ..
            })
        ));

        let s = pool.reserve("w1", 4_000).unwrap();
        assert_eq!(s.remaining(), 6_000);
        // Replay of the same reservation is a no-op success; a different
        // amount under the same id is a conflict.
        assert_eq!(pool.reserve("w1", 4_000).unwrap().remaining(), 6_000);
        assert!(matches!(
            pool.reserve("w1", 5_000),
            Err(BudgetError::ReservationConflict { .. })
        ));

        // Settling spends part and returns the remainder to the pool.
        let s = pool.settle("w1", 1_500).unwrap();
        assert_eq!(s.spent, 1_500);
        assert_eq!(s.remaining(), 8_500);
        assert!(matches!(
            pool.settle("w1", 1),
            Err(BudgetError::UnknownReservation(_))
        ));
    }

    #[test]
    fn the_pool_refuses_what_it_cannot_cover() {
        let dir = tempfile::tempdir().unwrap();
        let pool = BudgetPool::at(dir.path(), "h");
        pool.init(1_000).unwrap();
        pool.reserve("a", 800).unwrap();
        assert!(matches!(
            pool.reserve("b", 300),
            Err(BudgetError::Insufficient {
                requested: 300,
                remaining: 200
            })
        ));
        // Overspending a reservation was never authorized.
        assert!(matches!(
            pool.settle("a", 900),
            Err(BudgetError::Overspend {
                spent: 900,
                reserved: 800
            })
        ));
        // A failed worker settles at zero: the whole reservation returns.
        assert_eq!(pool.settle("a", 0).unwrap().remaining(), 1_000);
    }

    #[test]
    fn racing_reservations_never_overshoot_the_total() {
        // THE race this exists to close: N workers reserving concurrently
        // from a pool that covers only K of them. Exactly K succeed, and the
        // pool never exceeds its total.
        let dir = tempfile::tempdir().unwrap();
        BudgetPool::at(dir.path(), "race").init(5).unwrap();
        let store = dir.path().to_path_buf();
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let store = store.clone();
                std::thread::spawn(move || {
                    BudgetPool::at(&store, "race")
                        .reserve(&format!("w{i}"), 1)
                        .is_ok()
                })
            })
            .collect();
        let successes = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(successes, 5, "exactly the covered reservations succeed");
        let state = BudgetPool::at(&store, "race").state().unwrap();
        assert_eq!(state.reserved(), 5);
        assert_eq!(state.remaining(), 0);
    }

    #[test]
    fn spawning_against_a_missing_pool_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            BudgetPool::at(dir.path(), "ghost").reserve("w", 1),
            Err(BudgetError::NoPool(_))
        ));
    }
}
