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
use kernel::law::{enforce, Enforcement};
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
        /// The Playbook (spec) content digest governing this run.
        #[arg(long)]
        playbook_ref: Option<String>,
    },
    /// Gate at the commit boundary: read a proposed Bash tool call on stdin and,
    /// if it is a `git commit`, block it (exit 2) while any required obligation
    /// is still outstanding. Non-commit commands pass through.
    PreCommit {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long = "require")]
        require: Vec<String>,
        /// The run whose obligations are evaluated (obligations are per-run).
        #[arg(long, default_value = "unknown")]
        run_id: String,
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
        /// Shell command whose success is the evidence of discharge (e.g.
        /// "cargo test"). If it fails, nothing is discharged.
        #[arg(long)]
        check: Option<String>,
        /// The Playbook (spec) content digest governing this run.
        #[arg(long)]
        playbook_ref: Option<String>,
    },
    /// Law of the Hive: read a spawn request as JSON on stdin and allow (exit 0)
    /// or refuse (exit 2) it against the Hive's depth and budget caps.
    HiveSpawn {
        #[arg(long)]
        max_depth: u32,
        #[arg(long)]
        budget_remaining: u64,
    },
    /// Gate operations: request a checkpoint, approve it, or verify it.
    #[command(subcommand)]
    Gate(GateCmd),
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
            playbook_ref,
        } => {
            let mut stdin = String::new();
            std::io::stdin().read_to_string(&mut stdin).ok();
            let path = extract_target_path(&stdin);
            let event = Event {
                run_id,
                task_id: None,
                parent_task_id: None,
                action_id: "post_tool".into(),
                actor: "kernel".into(),
                timestamp: now_rfc3339(),
                transition: format!("post_tool.obligation.{obligation}"),
                input_refs: path.map(|p| format!("path:{p}")).into_iter().collect(),
                output_refs: vec![],
                decision: Decision::Recorded,
                evidence_refs: vec![],
                playbook_ref,
                attempt_id: None,
            };
            EventLog::at(&ledger).append(&event)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::PreCommit {
            ledger,
            require,
            run_id,
        } => {
            let mut stdin = String::new();
            std::io::stdin().read_to_string(&mut stdin).ok();
            // Only a git commit is gated here; everything else passes.
            if !is_git_commit(&stdin) {
                return Ok(ExitCode::SUCCESS);
            }
            let events = EventLog::at(&ledger).read_all().unwrap_or_default();
            let outstanding = kernel::obligation::outstanding(&events, &require, &run_id);
            if outstanding.is_empty() {
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
            check,
            playbook_ref,
        } => {
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
            let evidence_refs = check
                .as_ref()
                .map(|c| format!("check:{c}"))
                .into_iter()
                .collect();
            let event = Event {
                run_id,
                task_id: None,
                parent_task_id: None,
                action_id: "validate".into(),
                actor: "kernel".into(),
                timestamp: now_rfc3339(),
                transition: kernel::obligation::discharge_transition(&obligation),
                input_refs: vec![],
                output_refs: vec![],
                decision: Decision::Recorded,
                evidence_refs,
                playbook_ref,
                attempt_id: None,
            };
            EventLog::at(&ledger).append(&event)?;
            println!("discharged obligation '{obligation}'");
            Ok(ExitCode::SUCCESS)
        }
        Command::HiveSpawn {
            max_depth,
            budget_remaining,
        } => {
            let mut stdin = String::new();
            std::io::stdin().read_to_string(&mut stdin)?;
            let req: kernel::hive::SpawnRequest = serde_json::from_str(&stdin)
                .map_err(|e| format!("spawn request is not valid JSON: {e}"))?;
            match kernel::hive::validate_spawn(&req, max_depth, budget_remaining) {
                Ok(()) => {
                    println!(
                        "spawn authorized: parent={} depth={}",
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
        Command::Gate(cmd) => gate(cmd),
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
                playbook_ref,
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

    let verdict = enforce(&packet, &path, &protected);
    let (decision, transition) = match &verdict {
        Enforcement::Allow => (Decision::Allowed, "pre_tool.edit"),
        // A distinct, auditable transition when an enforcement artifact is amended.
        Enforcement::AllowAmendment => (Decision::Allowed, "pre_tool.enforcement_amendment"),
        Enforcement::Deny(_) => (Decision::Denied, "pre_tool.edit"),
    };

    if let Some(ledger) = ledger {
        let event = Event {
            run_id: run_id.to_string(),
            task_id: None,
            parent_task_id: None,
            action_id: "pre_tool".into(),
            actor: "kernel".into(),
            timestamp: now_rfc3339(),
            transition: transition.into(),
            input_refs: vec![format!("path:{path}")],
            output_refs: vec![],
            decision,
            evidence_refs: vec![],
            playbook_ref,
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
            playbook_ref,
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
        } => {
            let action_hash = match (action_hash, action_file) {
                (Some(h), _) => h,
                (None, Some(file)) => hash_file(&file)?,
                (None, None) => return Err("provide --action-hash or --action-file".into()),
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
            .requiring_obligations(require_obligations);
            let path = GateStore::at(&checkpoints).save(&checkpoint)?;
            println!("{}", path.display());
            Ok(ExitCode::SUCCESS)
        }
        GateCmd::Approve {
            checkpoint,
            approver,
            auth,
            auth_evidence,
            expiry,
        } => {
            let mut cp = GateStore::load(&checkpoint)?;
            let approver = Approver {
                principal: approver,
                auth: auth.into(),
                evidence: auth_evidence,
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
                let Some(ledger) = ledger else {
                    return Err(
                        "checkpoint requires obligations; pass --ledger to evaluate them".into(),
                    );
                };
                let events = EventLog::at(&ledger).read_all()?;
                let outstanding =
                    kernel::obligation::outstanding(&events, &cp.requires_obligations, &cp.run_id);
                if let Err(e) = cp.check_obligations(&outstanding) {
                    eprintln!("gate refused: {e}");
                    return Ok(ExitCode::FAILURE);
                }
            }

            println!("approval valid");
            Ok(ExitCode::SUCCESS)
        }
    }
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
