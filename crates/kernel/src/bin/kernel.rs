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
use kernel::gate::{Checkpoint, GateStore, Preconditions};
use kernel::law::enforce_file_scope;
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
        #[arg(long, default_value = "checkpoints")]
        checkpoints: PathBuf,
    },
    /// Record an approval against a persisted checkpoint.
    Approve {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        approver: String,
        #[arg(long)]
        expiry: Option<String>,
    },
    /// Revalidate a checkpoint's approval against the current world. Exits 0 if
    /// the approval still holds, 1 if it has been invalidated.
    Verify {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        action_hash: String,
        #[arg(long = "precondition")]
        preconditions: Vec<String>,
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
        } => pre_tool(&packet, ledger.as_deref(), &run_id),
        Command::PostTool {
            ledger,
            run_id,
            obligation,
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
            };
            EventLog::at(&ledger).append(&event)?;
            Ok(ExitCode::SUCCESS)
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
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let packet = load_packet(packet_path)?;

    let mut stdin = String::new();
    std::io::stdin().read_to_string(&mut stdin)?;
    let path = extract_target_path(&stdin);

    // A tool call with no file target is outside this law's scope.
    let Some(path) = path else {
        return Ok(ExitCode::SUCCESS);
    };

    let decision = enforce_file_scope(&packet, &path);
    if let Some(ledger) = ledger {
        let event = Event {
            run_id: run_id.to_string(),
            task_id: None,
            parent_task_id: None,
            action_id: "pre_tool".into(),
            actor: "kernel".into(),
            timestamp: now_rfc3339(),
            transition: "pre_tool.edit".into(),
            input_refs: vec![format!("path:{path}")],
            output_refs: vec![],
            decision: if decision.is_allowed() {
                Decision::Allowed
            } else {
                Decision::Denied
            },
            evidence_refs: vec![],
        };
        EventLog::at(ledger).append(&event)?;
    }

    match decision.reason() {
        None => Ok(ExitCode::SUCCESS),
        Some(reason) => {
            eprintln!("blocked by enforce-file-scope: {reason}");
            // Exit code 2 is Claude Code's signal to block the tool call and
            // surface stderr to the model.
            Ok(ExitCode::from(2))
        }
    }
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
            );
            let path = GateStore::at(&checkpoints).save(&checkpoint)?;
            println!("{}", path.display());
            Ok(ExitCode::SUCCESS)
        }
        GateCmd::Approve {
            checkpoint,
            approver,
            expiry,
        } => {
            let mut cp = GateStore::load(&checkpoint)?;
            cp.approve(approver, now_rfc3339(), expiry);
            let store = GateStore::at(
                checkpoint
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new(".")),
            );
            store.save(&cp)?;
            println!(
                "approved {} by {}",
                cp.action_hash,
                cp.approval.as_ref().unwrap().approver
            );
            Ok(ExitCode::SUCCESS)
        }
        GateCmd::Verify {
            checkpoint,
            action_hash,
            preconditions,
        } => {
            let cp = GateStore::load(&checkpoint)?;
            let preconds = parse_preconditions(&preconditions)?;
            match cp.revalidate(&action_hash, &preconds, &now_rfc3339()) {
                Ok(_) => {
                    println!("approval valid");
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("approval invalid: {e}");
                    Ok(ExitCode::FAILURE)
                }
            }
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
