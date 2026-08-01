//! `kernel` — the trusted runtime entrypoint that generated hooks invoke.
//!
//! Generated harnesses never re-implement enforcement in Markdown; they shell
//! out to this binary. Subcommands map to cycle stages:
//!
//! - `pre-tool`  — validate/authorize: run a Guard Law over a proposed edit.
//! - `gate`      — control: request, approve, and revalidate Gate checkpoints.
//! - `event`     — record: append to the Ledger.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use kernel::clock::now_rfc3339;
use kernel::event::{Decision, Event, EventLog};
use kernel::gate::{Approver, AuthMethod, Checkpoint, GateStore, Preconditions};
use kernel::law::Enforcement;
use kernel::packet::TaskPacket;

#[derive(Parser)]
#[command(name = "kernel", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Guard Law at validate/authorize: read a proposed tool call as JSON on
    /// stdin and allow or block it against the active task packet's write scope.
    /// Exits 0 to allow, 2 to block (blocking reason on stderr).
    PreTool {
        /// Path to the active task packet (`.json` or `.toml`).
        #[arg(long)]
        packet: PathBuf,
        /// Ledger to append the allow/deny decision to.
        #[arg(long)]
        ledger: Option<PathBuf>,
        /// Correlation id for the run.
        #[arg(long, default_value = "unknown")]
        run_id: String,
        /// The Playbook (spec) content digest governing this run.
        #[arg(long)]
        playbook_ref: Option<String>,
        /// File listing protected enforcement-artifact path prefixes (one per
        /// line). Writes to these require the packet's amends_enforcement grant.
        #[arg(long)]
        protected: Option<PathBuf>,
    },
    /// Guard Law on Bash: read a proposed Bash call on stdin and block (exit 2)
    /// a destructive command against a protected enforcement artifact unless the
    /// active packet carries an amends_enforcement grant.
    PreBash {
        #[arg(long)]
        packet: PathBuf,
        #[arg(long)]
        protected: PathBuf,
        #[arg(long)]
        ledger: Option<PathBuf>,
        #[arg(long, default_value = "unknown")]
        run_id: String,
        #[arg(long)]
        playbook_ref: Option<String>,
    },
    /// Obligation Law at evaluate: record that an obligation (e.g. running the
    /// test suite) is now owed following an edit. Always allows the edit — an
    /// Obligation records a follow-up requirement, it does not block.
    PostTool {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long, default_value = "unknown")]
        run_id: String,
        /// The obligation being recorded.
        #[arg(long, default_value = "require-validation")]
        obligation: String,
        /// The declared scope the debt lives at (run | task | branch |
        /// workspace | action). The event records the key that scope reads.
        #[arg(long, default_value = "run")]
        scope: String,
        /// Active task packet — required for task scope, whose key is the
        /// packet's content digest.
        #[arg(long)]
        packet: Option<PathBuf>,
        /// The Playbook (spec) content digest governing this run.
        #[arg(long)]
        playbook_ref: Option<String>,
    },
    /// Gate at the commit boundary: read a proposed Bash tool call on stdin and,
    /// if it is a `git commit`, block it (exit 2) while any required obligation
    /// is still outstanding. Non-commit commands pass through. Every actual
    /// commit evaluation — allow or deny — is appended to the Ledger: a blocked
    /// commit is a governed decision, and an unrecorded governed decision is a
    /// hole in the evidence.
    PreCommit {
        #[arg(long)]
        ledger: PathBuf,
        /// Required obligations, each `id` (run scope) or `id:scope` as the
        /// compiled Playbook declares them.
        #[arg(long = "require")]
        require: Vec<String>,
        /// The run whose obligations are evaluated.
        #[arg(long, default_value = "unknown")]
        run_id: String,
        /// Active task packet, so task-scoped obligations can be keyed.
        #[arg(long)]
        packet: Option<PathBuf>,
        /// The Playbook (compiled interpretation) digest governing this run.
        #[arg(long)]
        playbook_ref: Option<String>,
    },
    /// Discharge an obligation: optionally run a check command, and on success
    /// append a discharge event so a Gate that requires it can proceed.
    Validate {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long, default_value = "unknown")]
        run_id: String,
        #[arg(long, default_value = "require-validation")]
        obligation: String,
        /// The declared scope being discharged — the event must carry the same
        /// key the open events did, or it clears nothing.
        #[arg(long, default_value = "run")]
        scope: String,
        /// Active task packet (task scope key).
        #[arg(long)]
        packet: Option<PathBuf>,
        /// The path being validated — required for action scope, where every
        /// edited path owes its own discharge.
        #[arg(long)]
        path: Option<String>,
        /// Shell command whose success is the evidence of discharge (e.g.
        /// "cargo test"). If it fails, nothing is discharged.
        #[arg(long)]
        check: Option<String>,
        /// The Playbook (spec) content digest governing this run.
        #[arg(long)]
        playbook_ref: Option<String>,
    },
    /// Law of the Hive: read a spawn request as JSON on stdin and allow (exit 0)
    /// or refuse (exit 2) it against the Hive's caps. In pool mode
    /// (--store/--hive/--spawn-id) the budget is RESERVED transactionally
    /// from the durable pool, so racing spawns cannot jointly overshoot.
    HiveSpawn {
        #[arg(long)]
        max_depth: u32,
        /// Stateless mode: caller-claimed remaining budget. Racing spawns can
        /// jointly overshoot in this mode — prefer the pool flags.
        #[arg(long)]
        budget_remaining: Option<u64>,
        /// Pool mode: directory holding <hive>.budget.json.
        #[arg(long)]
        store: Option<PathBuf>,
        /// Pool mode: the Hive whose pool covers this spawn.
        #[arg(long)]
        hive: Option<String>,
        /// Pool mode: reservation key (replay-safe: the same id re-reserving
        /// the same amount is idempotent).
        #[arg(long)]
        spawn_id: Option<String>,
        /// Ledger to record the spawn decision to.
        #[arg(long)]
        ledger: Option<PathBuf>,
        #[arg(long, default_value = "unknown")]
        run_id: String,
        #[arg(long)]
        playbook_ref: Option<String>,
    },
    /// Hive budget-pool operations: create the pool, settle reservations.
    #[command(subcommand)]
    Hive(HiveCmd),
    /// Gate operations: request a checkpoint, approve it, or verify it.
    #[command(subcommand)]
    Gate(GateCmd),
    /// Ledger chain operations: prove the append-only log's integrity.
    #[command(subcommand)]
    Ledger(LedgerCmd),
    /// Approver key operations for signature-authenticated approvals.
    #[command(subcommand)]
    Key(KeyCmd),
    /// Identity-registry operations: sign and verify the approver registry as
    /// an authority-issued identity document.
    #[command(subcommand)]
    Registry(RegistryCmd),
    /// Append one event to the Ledger.
    Event {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long, default_value = "unknown")]
        run_id: String,
        #[arg(long, default_value = "a0")]
        action_id: String,
        #[arg(long, default_value = "kernel")]
        actor: String,
        #[arg(long)]
        transition: String,
        #[arg(long, value_enum)]
        decision: DecisionArg,
        #[arg(long)]
        task_id: Option<String>,
        #[arg(long = "input-ref")]
        input_refs: Vec<String>,
        #[arg(long = "evidence-ref")]
        evidence_refs: Vec<String>,
        /// The Playbook (spec) content digest governing this run.
        #[arg(long)]
        playbook_ref: Option<String>,
        /// One execution attempt of a logical action (replay safety).
        #[arg(long)]
        attempt_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum GateCmd {
    /// Halt at a boundary: create and durably persist a checkpoint.
    Request {
        #[arg(long)]
        gate: String,
        #[arg(long, default_value = "unknown")]
        run_id: String,
        /// File whose hash becomes the bound action hash.
        #[arg(long)]
        action_file: Option<PathBuf>,
        /// Or supply the action hash directly.
        #[arg(long)]
        action_hash: Option<String>,
        #[arg(long, default_value = "")]
        summary: String,
        #[arg(long, default_value = "resume")]
        continuation: String,
        /// Precondition tokens as `key=value` (e.g. repository_revision=abc123).
        #[arg(long = "precondition")]
        preconditions: Vec<String>,
        /// Obligation ids that must be discharged before this Gate resumes.
        #[arg(long = "require-obligation")]
        require_obligations: Vec<String>,
        #[arg(long, default_value = "checkpoints")]
        checkpoints: PathBuf,
        /// Ledger whose chain head to anchor into the checkpoint. Refuses a
        /// broken chain; at resume, `gate verify --ledger` refuses a log whose
        /// history no longer contains the anchored head (tail truncation).
        #[arg(long)]
        ledger: Option<PathBuf>,
    },
    /// Sign a checkpoint's canonical approval message (gate, run, action,
    /// preconditions, anchored ledger head, expiry) with an approver's private
    /// key. Prints the signature for `gate approve --auth signature`.
    Sign {
        #[arg(long)]
        checkpoint: PathBuf,
        /// The approver's private seed file (from `kernel key generate`).
        #[arg(long)]
        key: PathBuf,
        /// The expiry the approval will carry — it is part of the signed
        /// message, so `gate approve` must be given the same value.
        #[arg(long)]
        expiry: Option<String>,
    },
    /// Record an approval against a persisted checkpoint.
    Approve {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        approver: String,
        /// How the approver identity was established. Defaults to `claimed`
        /// (unauthenticated, caller-asserted) — recorded honestly as such.
        #[arg(long, value_enum, default_value_t = AuthArg::Claimed)]
        auth: AuthArg,
        /// Reference to the authentication evidence (never the secret itself).
        #[arg(long)]
        auth_evidence: Option<String>,
        #[arg(long)]
        expiry: Option<String>,
        /// The approver's signature over the canonical approval message
        /// (from `gate sign`). Required — and verified before anything is
        /// recorded — when --auth signature.
        #[arg(long)]
        signature: Option<String>,
        /// Trusted-keys registry ([approvers] TOML) naming each principal's
        /// public key. Required when --auth signature.
        #[arg(long)]
        trusted_keys: Option<PathBuf>,
        /// Pinned authority public key (`ed25519:<hex>` or a file containing
        /// one). When given, the registry must be an authority-signed,
        /// unexpired, non-rolled-back identity document; without it the
        /// registry is plain host configuration.
        #[arg(long)]
        authority: Option<String>,
    },
    /// Revalidate a checkpoint's approval against the current world, including
    /// any required obligations. Exits 0 if the approval still holds, 1 if it
    /// has been invalidated.
    Verify {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        action_hash: String,
        #[arg(long = "precondition")]
        preconditions: Vec<String>,
        /// Ledger to compute outstanding obligations from. Required if the
        /// checkpoint declares any required obligations.
        #[arg(long)]
        ledger: Option<PathBuf>,
        /// Active task packet, so task-scoped required obligations can be
        /// keyed at resume.
        #[arg(long)]
        packet: Option<PathBuf>,
        /// Trusted-keys registry. Required when the stored approval claims
        /// `signature` auth: the signature is re-verified at resume, so a
        /// rewritten checkpoint fails no matter what the file claims.
        #[arg(long)]
        trusted_keys: Option<PathBuf>,
        /// Pinned authority public key (`ed25519:<hex>` or a file containing
        /// one). The approver is resolved through the CURRENT registry, so a
        /// principal revoked since approval stops resuming — which is what
        /// revocation means.
        #[arg(long)]
        authority: Option<String>,
    },
}

#[derive(Subcommand)]
enum LedgerCmd {
    /// Walk the Ledger's hash chain: every record's `prev` must hash the exact
    /// line before it and `seq` must be contiguous. Detects mutation,
    /// insertion, mid-deletion, and reordering anywhere in history (including
    /// a frozen legacy prefix). Tail truncation is provable only against an
    /// externally anchored head — which this prints for exactly that purpose.
    Verify {
        #[arg(long)]
        ledger: PathBuf,
    },
}

#[derive(Subcommand)]
enum HiveCmd {
    /// Create a Hive's durable budget pool (idempotent when the total agrees;
    /// refused when it does not — a budget is not renegotiated by
    /// re-declaring it).
    Init {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        hive: String,
        #[arg(long)]
        budget: u64,
    },
    /// Settle a spawn's reservation: record what was actually spent (≤
    /// reserved) and return the remainder to the pool. --spent 0 releases a
    /// failed or cancelled worker's reservation entirely.
    Settle {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        hive: String,
        #[arg(long)]
        spawn_id: String,
        #[arg(long)]
        spent: u64,
        /// Ledger to record the settlement to.
        #[arg(long)]
        ledger: Option<PathBuf>,
        #[arg(long, default_value = "unknown")]
        run_id: String,
        #[arg(long)]
        playbook_ref: Option<String>,
    },
}

#[derive(Subcommand)]
enum RegistryCmd {
    /// Sign the registry with the authority's private key: a detached
    /// signature over the file's exact bytes, written to `<registry>.sig`.
    /// Edit one byte afterwards and verification fails — no canonicalization,
    /// no ambiguity.
    Sign {
        #[arg(long)]
        registry: PathBuf,
        /// The authority's private seed file (from `kernel key generate`).
        #[arg(long)]
        key: PathBuf,
    },
    /// Verify a signed registry against the pinned authority key: signature,
    /// validity window, and rollback watermark. Prints the document summary.
    Verify {
        #[arg(long)]
        registry: PathBuf,
        /// The authority public key: a literal `ed25519:<hex>` or a path to a
        /// file containing one.
        #[arg(long)]
        authority: String,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Generate an ed25519 approver keypair: the private seed is written to
    /// --out (mode 0600, a secret the kernel never needs), the public key is
    /// printed for the trusted-keys registry ([approvers] table in TOML).
    Generate {
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum DecisionArg {
    Allowed,
    Denied,
    Approved,
    Rejected,
    Recorded,
}

#[derive(Copy, Clone, ValueEnum)]
enum AuthArg {
    Claimed,
    Token,
    Signature,
}

impl From<AuthArg> for AuthMethod {
    fn from(a: AuthArg) -> Self {
        match a {
            AuthArg::Claimed => AuthMethod::Claimed,
            AuthArg::Token => AuthMethod::Token,
            AuthArg::Signature => AuthMethod::Signature,
        }
    }
}

impl From<DecisionArg> for Decision {
    fn from(d: DecisionArg) -> Self {
        match d {
            DecisionArg::Allowed => Decision::Allowed,
            DecisionArg::Denied => Decision::Denied,
            DecisionArg::Approved => Decision::Approved,
            DecisionArg::Rejected => Decision::Rejected,
            DecisionArg::Recorded => Decision::Recorded,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("kernel error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::PreTool {
            packet,
            ledger,
            run_id,
            playbook_ref,
            protected,
        } => pre_tool(
            &packet,
            ledger.as_deref(),
            &run_id,
            playbook_ref,
            protected.as_deref(),
        ),
        Command::PreBash {
            packet,
            protected,
            ledger,
            run_id,
            playbook_ref,
        } => pre_bash(
            &packet,
            &protected,
            ledger.as_deref(),
            &run_id,
            playbook_ref,
        ),
        Command::PostTool {
            ledger,
            run_id,
            obligation,
            scope,
            packet,
            playbook_ref,
        } => {
            let mut stdin = String::new();
            std::io::stdin().read_to_string(&mut stdin).ok();
            let path = extract_target_path(&stdin);
            // The event carries the key its declared scope reads at eval time.
            let (task_id, scope_refs) = scope_recording(&scope, packet.as_deref())?;
            let mut input_refs: Vec<String> =
                path.map(|p| format!("path:{p}")).into_iter().collect();
            input_refs.extend(scope_refs);
            let event = Event {
                run_id,
                task_id,
                parent_task_id: None,
                action_id: "post_tool".into(),
                actor: "kernel".into(),
                timestamp: now_rfc3339(),
                transition: format!("post_tool.obligation.{obligation}"),
                input_refs,
                output_refs: vec![],
                decision: Decision::Recorded,
                evidence_refs: vec![],
                playbook_ref: playbook_ref.unwrap_or_default(),
                kernel_ref: kernel::kernel_ref(),
                attempt_id: None,
            };
            EventLog::at(&ledger).append(&event)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::PreCommit {
            ledger,
            require,
            run_id,
            packet,
            playbook_ref,
        } => {
            let mut stdin = String::new();
            std::io::stdin().read_to_string(&mut stdin).ok();
            // Only a git commit is gated here; everything else passes through
            // ungated — and unrecorded, since no gate decision was made.
            if !is_git_commit(&stdin) {
                return Ok(ExitCode::SUCCESS);
            }
            let events = EventLog::at(&ledger).read_all().unwrap_or_default();
            let ctx = kernel::obligation::ScopeContext {
                run_id: run_id.clone(),
                task_key: packet.as_deref().and_then(|p| hash_file(p).ok()),
                branch: current_branch(),
            };
            let outstanding = kernel::obligation::outstanding(&events, &require, &ctx);
            let allowed = outstanding.is_empty();
            // The decision is evidence either way: which obligations stood in
            // the way of a denial is exactly what an audit needs to see.
            let event = Event {
                run_id: run_id.clone(),
                task_id: None,
                parent_task_id: None,
                action_id: "pre_commit".into(),
                actor: "kernel".into(),
                timestamp: now_rfc3339(),
                transition: "gate.pre_commit".into(),
                input_refs: outstanding
                    .iter()
                    .map(|o| format!("obligation:{o}"))
                    .collect(),
                output_refs: vec![],
                decision: if allowed {
                    Decision::Allowed
                } else {
                    Decision::Denied
                },
                evidence_refs: vec![],
                playbook_ref: playbook_ref.unwrap_or_default(),
                kernel_ref: kernel::kernel_ref(),
                attempt_id: None,
            };
            EventLog::at(&ledger).append(&event)?;
            if allowed {
                Ok(ExitCode::SUCCESS)
            } else {
                eprintln!(
                    "blocked by approve-commit gate: obligation(s) outstanding: {}. \
                     Run the validation step to discharge before committing.",
                    outstanding.join(", ")
                );
                Ok(ExitCode::from(2))
            }
        }
        Command::Validate {
            ledger,
            run_id,
            obligation,
            scope,
            packet,
            path,
            check,
            playbook_ref,
        } => {
            if scope == "action" && path.is_none() {
                return Err(
                    "action-scoped obligations discharge per path; pass --path <edited-file>"
                        .into(),
                );
            }
            if let Some(cmd) = &check {
                let status = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(cmd)
                    .status()?;
                if !status.success() {
                    eprintln!("validation check failed: `{cmd}`; obligation not discharged");
                    return Ok(ExitCode::FAILURE);
                }
            }
            // The discharge must carry the same key the open events did, or
            // it clears nothing.
            let (task_id, scope_refs) = scope_recording(&scope, packet.as_deref())?;
            let mut input_refs: Vec<String> =
                path.map(|p| format!("path:{p}")).into_iter().collect();
            input_refs.extend(scope_refs);
            let evidence_refs = check
                .as_ref()
                .map(|c| format!("check:{c}"))
                .into_iter()
                .collect();
            let event = Event {
                run_id,
                task_id,
                parent_task_id: None,
                action_id: "validate".into(),
                actor: "kernel".into(),
                timestamp: now_rfc3339(),
                transition: kernel::obligation::discharge_transition(&obligation),
                input_refs,
                output_refs: vec![],
                decision: Decision::Recorded,
                evidence_refs,
                playbook_ref: playbook_ref.unwrap_or_default(),
                kernel_ref: kernel::kernel_ref(),
                attempt_id: None,
            };
            EventLog::at(&ledger).append(&event)?;
            println!("discharged obligation '{obligation}'");
            Ok(ExitCode::SUCCESS)
        }
        Command::HiveSpawn {
            max_depth,
            budget_remaining,
            store,
            hive,
            spawn_id,
            ledger,
            run_id,
            playbook_ref,
        } => {
            let mut stdin = String::new();
            std::io::stdin().read_to_string(&mut stdin)?;
            let req: kernel::hive::SpawnRequest = serde_json::from_str(&stdin)
                .map_err(|e| format!("spawn request is not valid JSON: {e}"))?;

            enum Mode<'a> {
                Stateless(u64),
                Pool(&'a std::path::Path, &'a str, &'a str),
            }
            let mode = match (
                budget_remaining,
                store.as_deref(),
                hive.as_deref(),
                spawn_id.as_deref(),
            ) {
                (Some(m), None, None, None) => Mode::Stateless(m),
                (None, Some(s), Some(h), Some(id)) => Mode::Pool(s, h, id),
                _ => {
                    return Err("pass either --budget-remaining (stateless) or all of \
                                --store/--hive/--spawn-id (transactional pool)"
                        .into())
                }
            };

            let outcome: Result<String, String> = match mode {
                Mode::Stateless(remaining) => {
                    kernel::hive::validate_spawn(&req, max_depth, remaining)
                        .map(|()| "caller-claimed budget (stateless mode)".to_string())
                        .map_err(|e| e.to_string())
                }
                Mode::Pool(store, hive, spawn_id) => {
                    // Field checks first; the budget cap is the POOL's call,
                    // enforced by the atomic reservation below.
                    kernel::hive::validate_spawn(&req, max_depth, u64::MAX)
                        .map_err(|e| e.to_string())
                        .and_then(|()| {
                            kernel::hive::BudgetPool::at(store, hive)
                                .reserve(spawn_id, req.budget)
                                .map(|state| {
                                    format!(
                                        "reserved {} from pool '{hive}' ({} remaining)",
                                        req.budget,
                                        state.remaining()
                                    )
                                })
                                .map_err(|e| e.to_string())
                        })
                }
            };

            // A spawn authorization is a governed decision; record it.
            if let Some(ledger) = &ledger {
                let mut input_refs = vec![
                    format!("parent:{}", req.parent),
                    format!("budget:{}", req.budget),
                ];
                if let Some(id) = &spawn_id {
                    input_refs.push(format!("spawn:{id}"));
                }
                let event = Event {
                    run_id: run_id.clone(),
                    task_id: None,
                    parent_task_id: None,
                    action_id: "hive_spawn".into(),
                    actor: "kernel".into(),
                    timestamp: now_rfc3339(),
                    transition: "hive.spawn".into(),
                    input_refs,
                    output_refs: vec![],
                    decision: if outcome.is_ok() {
                        Decision::Allowed
                    } else {
                        Decision::Denied
                    },
                    evidence_refs: vec![],
                    playbook_ref: playbook_ref.unwrap_or_default(),
                    kernel_ref: kernel::kernel_ref(),
                    attempt_id: None,
                };
                EventLog::at(ledger).append(&event)?;
            }

            match outcome {
                Ok(detail) => {
                    println!(
                        "spawn authorized: parent={} depth={} — {detail}",
                        req.parent, req.depth
                    );
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("blocked by Law of the Hive: {e}");
                    Ok(ExitCode::from(2))
                }
            }
        }
        Command::Hive(cmd) => match cmd {
            HiveCmd::Init {
                store,
                hive,
                budget,
            } => {
                let state = kernel::hive::BudgetPool::at(&store, &hive).init(budget)?;
                println!(
                    "pool '{hive}': total {}, spent {}, reserved {}, remaining {}",
                    state.total,
                    state.spent,
                    state.reserved(),
                    state.remaining()
                );
                Ok(ExitCode::SUCCESS)
            }
            HiveCmd::Settle {
                store,
                hive,
                spawn_id,
                spent,
                ledger,
                run_id,
                playbook_ref,
            } => {
                let result = kernel::hive::BudgetPool::at(&store, &hive).settle(&spawn_id, spent);
                if let Some(ledger) = &ledger {
                    // Settlement — including a refused overspend — is evidence.
                    let event = Event {
                        run_id: run_id.clone(),
                        task_id: None,
                        parent_task_id: None,
                        action_id: "hive_settle".into(),
                        actor: "kernel".into(),
                        timestamp: now_rfc3339(),
                        transition: "hive.settle".into(),
                        input_refs: vec![format!("spawn:{spawn_id}"), format!("spent:{spent}")],
                        output_refs: vec![],
                        decision: if result.is_ok() {
                            Decision::Recorded
                        } else {
                            Decision::Denied
                        },
                        evidence_refs: vec![],
                        playbook_ref: playbook_ref.unwrap_or_default(),
                        kernel_ref: kernel::kernel_ref(),
                        attempt_id: None,
                    };
                    EventLog::at(ledger).append(&event)?;
                }
                match result {
                    Ok(state) => {
                        println!(
                            "settled '{spawn_id}': spent {spent}, pool remaining {}",
                            state.remaining()
                        );
                        Ok(ExitCode::SUCCESS)
                    }
                    Err(e) => {
                        eprintln!("settlement refused: {e}");
                        Ok(ExitCode::FAILURE)
                    }
                }
            }
        },
        Command::Gate(cmd) => gate(cmd),
        Command::Registry(cmd) => match cmd {
            RegistryCmd::Sign { registry, key } => {
                let bytes = std::fs::read(&registry)?;
                // Warn at signing time about what a pinned-authority load will
                // refuse — the issuer should find out now, not at the Gate.
                if let Ok(v) = String::from_utf8_lossy(&bytes).parse::<toml::Value>() {
                    let meta = v.get("registry");
                    if meta.and_then(|r| r.get("serial")).is_none()
                        || meta.and_then(|r| r.get("expires_at")).is_none()
                    {
                        eprintln!(
                            "warning: registry lacks [registry] serial and/or expires_at; a \
                             pinned-authority load will refuse it"
                        );
                    }
                }
                let seed = std::fs::read_to_string(&key)?;
                let kp = kernel::sign::Keypair::from_seed_str(seed.trim())?;
                let sig_path = kernel::identity::signature_path(&registry);
                std::fs::write(&sig_path, format!("{}\n", kp.sign_bytes(&bytes)))?;
                println!("signed {} -> {}", registry.display(), sig_path.display());
                println!("authority public key: {}", kp.public_string());
                Ok(ExitCode::SUCCESS)
            }
            RegistryCmd::Verify {
                registry,
                authority,
            } => {
                let authority = kernel::identity::resolve_authority(&authority)?;
                match kernel::identity::Registry::load(&registry, Some(&authority), &now_rfc3339())
                {
                    Ok(reg) => {
                        println!(
                            "registry ok: issuer {}, serial {}, expires {}, {} approver(s), {} \
                             revoked",
                            reg.issuer.as_deref().unwrap_or("-"),
                            reg.serial
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "-".into()),
                            reg.expires_at.as_deref().unwrap_or("-"),
                            reg.approver_count(),
                            reg.revoked_count(),
                        );
                        Ok(ExitCode::SUCCESS)
                    }
                    Err(e) => {
                        eprintln!("registry refused: {e}");
                        Ok(ExitCode::FAILURE)
                    }
                }
            }
        },
        Command::Key(KeyCmd::Generate { out }) => {
            let kp = kernel::sign::Keypair::generate()?;
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::write(&out, format!("{}\n", kp.seed_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600))?;
            }
            // Public key on stdout for the registry; where the secret went on
            // stderr — never the secret itself.
            println!("{}", kp.public_string());
            eprintln!(
                "private seed written to {} (mode 0600); register the public key above in the \
                 trusted-keys [approvers] table",
                out.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Ledger(LedgerCmd::Verify { ledger }) => {
            match EventLog::at(&ledger).verify_chain() {
                Ok(report) => {
                    println!(
                        "chain ok: {} record(s), {} chained{}",
                        report.records,
                        report.chained,
                        report
                            .head
                            .as_deref()
                            .map(|h| format!(", head {h}"))
                            .unwrap_or_default()
                    );
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("ledger chain broken: {e}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Command::Event {
            ledger,
            run_id,
            action_id,
            actor,
            transition,
            decision,
            task_id,
            input_refs,
            evidence_refs,
            playbook_ref,
            attempt_id,
        } => {
            let event = Event {
                run_id,
                task_id,
                parent_task_id: None,
                action_id,
                actor,
                timestamp: now_rfc3339(),
                transition,
                input_refs,
                output_refs: vec![],
                decision: decision.into(),
                evidence_refs,
                playbook_ref: playbook_ref.unwrap_or_default(),
                kernel_ref: kernel::kernel_ref(),
                attempt_id,
            };
            EventLog::at(&ledger).append(&event)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn pre_tool(
    packet_path: &std::path::Path,
    ledger: Option<&std::path::Path>,
    run_id: &str,
    playbook_ref: Option<String>,
    protected_path: Option<&std::path::Path>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let packet = load_packet(packet_path)?;
    let protected = load_protected(protected_path)?;

    let mut stdin = String::new();
    std::io::stdin().read_to_string(&mut stdin)?;
    let path = extract_target_path(&stdin);

    // A tool call with no file target is outside this law's scope.
    let Some(path) = path else {
        return Ok(ExitCode::SUCCESS);
    };

    // Judged against the CANONICAL target: symlinks resolved on the real
    // filesystem (rooted at the hook's working directory), so a link cannot
    // launder an out-of-scope or protected target into an authorized name.
    let verdict = kernel::law::enforce_at(std::path::Path::new("."), &packet, &path, &protected);
    let (decision, transition) = match &verdict {
        Enforcement::Allow => (Decision::Allowed, "pre_tool.edit"),
        // A distinct, auditable transition when an enforcement artifact is amended.
        Enforcement::AllowAmendment => (Decision::Allowed, "pre_tool.enforcement_amendment"),
        Enforcement::Deny(_) => (Decision::Denied, "pre_tool.edit"),
    };

    // Evidence names the real target too: an allowed write through a symlink
    // must be attributable to where it actually landed.
    let mut input_refs = vec![format!("path:{path}")];
    if let Ok(canonical) = kernel::fsutil::canonical_workspace_rel(std::path::Path::new("."), &path)
    {
        if canonical != path {
            input_refs.push(format!("canonical:{canonical}"));
        }
    }

    if let Some(ledger) = ledger {
        let event = Event {
            run_id: run_id.to_string(),
            task_id: None,
            parent_task_id: None,
            action_id: "pre_tool".into(),
            actor: "kernel".into(),
            timestamp: now_rfc3339(),
            transition: transition.into(),
            input_refs: input_refs.clone(),
            output_refs: vec![],
            decision,
            evidence_refs: vec![],
            playbook_ref: playbook_ref.unwrap_or_default(),
            kernel_ref: kernel::kernel_ref(),
            attempt_id: None,
        };
        EventLog::at(ledger).append(&event)?;
    }

    match verdict {
        Enforcement::Allow => Ok(ExitCode::SUCCESS),
        Enforcement::AllowAmendment => {
            eprintln!(
                "note: enforcement amendment to '{path}' authorized by amends_enforcement grant"
            );
            Ok(ExitCode::SUCCESS)
        }
        Enforcement::Deny(reason) => {
            eprintln!("blocked by enforce-file-scope: {reason}");
            // Exit code 2 is Claude Code's signal to block the tool call and
            // surface stderr to the model.
            Ok(ExitCode::from(2))
        }
    }
}

fn pre_bash(
    packet_path: &std::path::Path,
    protected_path: &std::path::Path,
    ledger: Option<&std::path::Path>,
    run_id: &str,
    playbook_ref: Option<String>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let protected = load_protected(Some(protected_path))?;

    let mut stdin = String::new();
    std::io::stdin().read_to_string(&mut stdin).ok();
    let command = extract_command(&stdin).unwrap_or_default();

    let Some(hit) = kernel::law::bash_hits_protected(&command, &protected) else {
        return Ok(ExitCode::SUCCESS);
    };

    // A destructive command touches a protected artifact. Allow only under an
    // explicit amends_enforcement grant.
    let packet = load_packet(packet_path).ok();
    let granted = packet.map(|p| p.amends_enforcement).unwrap_or(false);

    if let Some(ledger) = ledger {
        let event = Event {
            run_id: run_id.to_string(),
            task_id: None,
            parent_task_id: None,
            action_id: "pre_bash".into(),
            actor: "kernel".into(),
            timestamp: now_rfc3339(),
            transition: "pre_bash.protected".into(),
            input_refs: vec![format!("protected:{hit}")],
            output_refs: vec![],
            decision: if granted {
                Decision::Allowed
            } else {
                Decision::Denied
            },
            evidence_refs: vec![],
            playbook_ref: playbook_ref.unwrap_or_default(),
            kernel_ref: kernel::kernel_ref(),
            attempt_id: None,
        };
        EventLog::at(ledger).append(&event)?;
    }

    if granted {
        eprintln!(
            "note: destructive command on protected '{hit}' authorized by amends_enforcement"
        );
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!(
            "blocked by self-protection: this command would destructively modify protected \
             enforcement artifact '{hit}'. Amending enforcement requires a task packet with \
             amends_enforcement = true."
        );
        Ok(ExitCode::from(2))
    }
}

/// Load protected path prefixes from a file (one per line; `#` comments and
/// blanks ignored). Missing file → empty set.
fn load_protected(
    path: Option<&std::path::Path>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

fn gate(cmd: GateCmd) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cmd {
        GateCmd::Request {
            gate,
            run_id,
            action_file,
            action_hash,
            summary,
            continuation,
            preconditions,
            require_obligations,
            checkpoints,
            ledger,
        } => {
            let action_hash = match (action_hash, action_file) {
                (Some(h), _) => h,
                (None, Some(file)) => hash_file(&file)?,
                (None, None) => return Err("provide --action-hash or --action-file".into()),
            };
            // Anchor the Ledger's chain head into the durable checkpoint —
            // the out-of-band pin that makes tail truncation detectable at
            // resume. A chain that is already broken is refused outright: a
            // checkpoint must not notarize corrupt history.
            let ledger_head = match &ledger {
                None => None,
                Some(l) => match EventLog::at(l).verify_chain() {
                    Ok(report) => report.head,
                    Err(e) => {
                        eprintln!("refusing to checkpoint over a broken ledger chain: {e}");
                        return Ok(ExitCode::FAILURE);
                    }
                },
            };
            let checkpoint = Checkpoint::new(
                gate,
                run_id,
                action_hash,
                summary,
                continuation,
                parse_preconditions(&preconditions)?,
                now_rfc3339(),
            )
            .requiring_obligations(require_obligations)
            .anchoring_ledger_head(ledger_head);
            let path = GateStore::at(&checkpoints).save(&checkpoint)?;
            println!("{}", path.display());
            Ok(ExitCode::SUCCESS)
        }
        GateCmd::Sign {
            checkpoint,
            key,
            expiry,
        } => {
            let cp = GateStore::load(&checkpoint)?;
            let seed = std::fs::read_to_string(&key)?;
            let kp = kernel::sign::Keypair::from_seed_str(seed.trim())?;
            let message = kernel::sign::approval_message(&cp, &cp.preconditions, expiry.as_deref());
            println!("{}", kp.sign(&message));
            Ok(ExitCode::SUCCESS)
        }
        GateCmd::Approve {
            checkpoint,
            approver,
            auth,
            auth_evidence,
            expiry,
            signature,
            trusted_keys,
            authority,
        } => {
            let mut cp = GateStore::load(&checkpoint)?;
            // Signature auth is VERIFIED before anything is recorded: an
            // approval that claims cryptographic identity must prove it here,
            // or the record would launder a claim into a guarantee.
            let evidence = if matches!(auth, AuthArg::Signature) {
                let (Some(signature), Some(trusted_keys)) = (signature, trusted_keys.as_deref())
                else {
                    return Err("--auth signature requires --signature and --trusted-keys".into());
                };
                if auth_evidence.is_some() {
                    return Err(
                        "--auth signature takes --signature; the signature IS the evidence".into(),
                    );
                }
                let public = match approver_key(trusted_keys, authority.as_deref(), &approver) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("approval NOT recorded: {e}");
                        return Ok(ExitCode::FAILURE);
                    }
                };
                let message =
                    kernel::sign::approval_message(&cp, &cp.preconditions, expiry.as_deref());
                if let Err(e) = kernel::sign::verify(&public, &message, &signature) {
                    eprintln!("approval NOT recorded: {e}");
                    return Ok(ExitCode::FAILURE);
                }
                Some(signature)
            } else {
                if signature.is_some() {
                    return Err("--signature requires --auth signature".into());
                }
                auth_evidence
            };
            let approver = Approver {
                principal: approver,
                auth: auth.into(),
                evidence,
            };
            let authed = approver.is_authenticated();
            cp.approve(approver, now_rfc3339(), expiry);
            let store = GateStore::at(
                checkpoint
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new(".")),
            );
            store.save(&cp)?;
            let a = cp.approval.as_ref().unwrap();
            println!(
                "approved {} by {} ({})",
                cp.action_hash,
                a.approver.principal,
                if authed {
                    "authenticated"
                } else {
                    "claimed — unauthenticated"
                }
            );
            Ok(ExitCode::SUCCESS)
        }
        GateCmd::Verify {
            checkpoint,
            action_hash,
            preconditions,
            ledger,
            packet,
            trusted_keys,
            authority,
        } => {
            let cp = GateStore::load(&checkpoint)?;
            let preconds = parse_preconditions(&preconditions)?;

            if let Err(e) = cp.revalidate(&action_hash, &preconds, &now_rfc3339()) {
                eprintln!("approval invalid: {e}");
                return Ok(ExitCode::FAILURE);
            }

            // The Gate also refuses to resume while a required obligation is
            // outstanding — this is how "recorded" becomes "enforced".
            if !cp.requires_obligations.is_empty() {
                let Some(ledger) = ledger.as_ref() else {
                    return Err(
                        "checkpoint requires obligations; pass --ledger to evaluate them".into(),
                    );
                };
                let events = EventLog::at(ledger).read_all()?;
                let ctx = kernel::obligation::ScopeContext {
                    run_id: cp.run_id.clone(),
                    task_key: packet.as_deref().and_then(|p| hash_file(p).ok()),
                    branch: current_branch(),
                };
                let outstanding =
                    kernel::obligation::outstanding(&events, &cp.requires_obligations, &ctx);
                if let Err(e) = cp.check_obligations(&outstanding) {
                    eprintln!("gate refused: {e}");
                    return Ok(ExitCode::FAILURE);
                }
            }

            // The anchored chain head must still be in the log's history: the
            // checkpoint pinned it precisely so that a tail truncated (or a
            // log rewritten) while the Gate was closed is refused, not
            // silently resumed over.
            if let Some(head) = &cp.ledger_head {
                let Some(ledger) = ledger.as_ref() else {
                    return Err(
                        "checkpoint anchors the ledger head; pass --ledger to verify it".into(),
                    );
                };
                if let Err(e) = EventLog::at(ledger).verify_anchor(head) {
                    eprintln!("gate refused: ledger integrity: {e}");
                    return Ok(ExitCode::FAILURE);
                }
            }

            // A signature-authenticated approval is re-proved at resume. The
            // canonical message is rebuilt from the checkpoint's CURRENT
            // contents, so a rewrite of any covered field — action, the
            // precondition snapshot, the anchored ledger head, the expiry —
            // invalidates the signature no matter what the file claims. This
            // is the custody boundary moving from disk to key: forging a
            // resumable approval now requires the approver's private key, not
            // write access to the checkpoint and ledger.
            if let Some(approval) = &cp.approval {
                if matches!(approval.approver.auth, AuthMethod::Signature) {
                    let Some(trusted_keys) = trusted_keys.as_deref() else {
                        return Err("approval claims signature auth; pass --trusted-keys to \
                                    re-verify it"
                            .into());
                    };
                    let Some(evidence) = &approval.approver.evidence else {
                        eprintln!(
                            "gate refused: signature-authenticated approval carries no \
                             signature evidence"
                        );
                        return Ok(ExitCode::FAILURE);
                    };
                    // The approver is resolved through the CURRENT registry:
                    // a principal revoked since approval is refused here,
                    // which is exactly what revocation means.
                    let public = match approver_key(
                        trusted_keys,
                        authority.as_deref(),
                        &approval.approver.principal,
                    ) {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("gate refused: {e}");
                            return Ok(ExitCode::FAILURE);
                        }
                    };
                    let message = kernel::sign::approval_message(
                        &cp,
                        &approval.preconditions,
                        approval.expiry.as_deref(),
                    );
                    if let Err(e) = kernel::sign::verify(&public, &message, evidence) {
                        eprintln!("gate refused: {e}");
                        return Ok(ExitCode::FAILURE);
                    }
                }
            }

            println!("approval valid");
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// The current git branch, when one can be determined — the key branch-scoped
/// obligations live at. `None` (detached HEAD, not a repo, no git) makes the
/// fail-safe rule apply: unprovable debts block.
fn current_branch() -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "HEAD")
}

/// The scope-relevant identity an obligation event must carry: the task key
/// (packet content digest) and/or branch ref, per the declared scope. Returns
/// (task_id, extra input_refs). Task scope without a packet is an error — the
/// key cannot be invented, and an unkeyed event would block everyone.
fn scope_recording(
    scope: &str,
    packet: Option<&std::path::Path>,
) -> Result<(Option<String>, Vec<String>), Box<dyn std::error::Error>> {
    let scope = kernel::obligation::Scope::parse(scope)
        .ok_or_else(|| format!("unknown obligation scope '{scope}'"))?;
    match scope {
        kernel::obligation::Scope::Task => {
            let packet =
                packet.ok_or("task-scoped obligations need --packet to derive the task key")?;
            Ok((Some(hash_file(packet)?), vec![]))
        }
        kernel::obligation::Scope::Branch => {
            // Record what we can determine; an unknown branch records nothing
            // and the unkeyed debt blocks everyone — fail-safe, not silent.
            Ok((
                None,
                current_branch()
                    .map(|b| format!("branch:{b}"))
                    .into_iter()
                    .collect(),
            ))
        }
        _ => Ok((None, vec![])),
    }
}

/// Resolve an approver's public key through the identity registry. With a
/// pinned authority, the registry must be a verified, unexpired,
/// non-rolled-back signed document; without one it is plain host
/// configuration (revocations are honored either way).
fn approver_key(
    trusted_keys: &std::path::Path,
    authority: Option<&str>,
    principal: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let authority = authority
        .map(kernel::identity::resolve_authority)
        .transpose()?;
    let registry =
        kernel::identity::Registry::load(trusted_keys, authority.as_deref(), &now_rfc3339())?;
    Ok(registry.key_for(principal)?.to_string())
}

/// Load a packet from a `.json` file (JSON) or anything else (TOML).
fn load_packet(path: &std::path::Path) -> Result<TaskPacket, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read active packet {}: {e}", path.display()))?;
    let is_json = path.extension().and_then(|e| e.to_str()) == Some("json");
    Ok(if is_json {
        serde_json::from_str(&text)?
    } else {
        toml::from_str(&text)?
    })
}

/// Pull the Bash command string out of a tool-call JSON payload.
fn extract_command(stdin: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(stdin).ok()?;
    value
        .pointer("/tool_input/command")
        .or_else(|| value.pointer("/command"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// True if the tool-call JSON on stdin is a Bash `git commit`. Heuristic: the
/// command string contains both `git` and `commit` tokens. Documented as such;
/// commit-alias schemes would need a richer matcher.
fn is_git_commit(stdin: &str) -> bool {
    let command = extract_command(stdin).unwrap_or_default();
    let tokens: Vec<&str> = command.split_whitespace().collect();
    tokens.contains(&"git") && tokens.contains(&"commit")
}

/// Pull a file path out of a Claude Code tool-call JSON payload, checking the
/// keys used by the file-touching tools (Edit/Write/etc.).
fn extract_target_path(stdin: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(stdin).ok()?;
    let candidates = [
        value.pointer("/tool_input/file_path"),
        value.pointer("/tool_input/path"),
        value.pointer("/file_path"),
        value.pointer("/path"),
    ];
    let found = candidates
        .into_iter()
        .flatten()
        .find_map(|v| v.as_str())
        .map(|s| s.to_string());
    found
}

fn parse_preconditions(pairs: &[String]) -> Result<Preconditions, Box<dyn std::error::Error>> {
    let mut map = BTreeMap::new();
    for pair in pairs {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| format!("precondition '{pair}' must be key=value"))?;
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
}

fn hash_file(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    let mut hex = String::from("sha256:");
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    Ok(hex)
}
