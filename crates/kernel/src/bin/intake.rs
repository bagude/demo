//! The Intake CLI — the Invocable Workflow half of the pattern.
//!
//! `intake template` emits a blank packet, `intake submit` runs the Guard Laws
//! and records the packet as evidence, and the remaining commands read that
//! evidence back or enforce the packet's file-scope contract.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use kernel::clock::now_rfc3339;
use kernel::intake::{admit_with_protected, AdmitError};
use kernel::ledger::Ledger;
use kernel::packet::TaskPacket;
use kernel::validate::validate_with_protected;

/// The Intake pattern as a command: work enters only as a typed, validated
/// task packet recorded as append-only evidence.
#[derive(Parser)]
#[command(name = "intake", version, about)]
struct Cli {
    /// Path to the append-only ledger file.
    #[arg(long, global = true, default_value = ".intake/ledger.jsonl")]
    ledger: PathBuf,

    /// File listing protected enforcement-artifact path prefixes (one per
    /// line). A packet whose write scope intersects them must declare
    /// amends_enforcement = true — the classification is derived, never
    /// self-asserted. Missing file → empty set.
    #[arg(long, global = true, default_value = "harness/enforcement.protected")]
    protected: PathBuf,

    /// The governed event ledger, consulted for the succession regime: a
    /// runtime in candidate mode may not admit work. Missing file → no
    /// regime. The check runs only when --playbook-ref is also given (the
    /// runtime identity cannot be computed without it).
    #[arg(long, global = true, default_value = "evidence/events.jsonl")]
    events_ledger: PathBuf,

    /// The Playbook digest this invocation runs under, for the candidate-mode
    /// check on submission.
    #[arg(long, global = true)]
    playbook_ref: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print a blank task-packet template to stdout.
    Template {
        /// Template serialization format.
        #[arg(long, value_enum, default_value_t = Format::Toml)]
        format: Format,
    },
    /// Validate a packet file without recording it (a dry run of the Guard Laws).
    Validate {
        /// Path to a `.toml` or `.json` task packet.
        file: PathBuf,
    },
    /// Validate a packet and, if it passes, append it to the ledger.
    Submit {
        /// Path to a `.toml` or `.json` task packet.
        file: PathBuf,
    },
    /// List every recorded packet.
    List,
    /// Print one recorded packet as JSON, by task-id prefix.
    Show {
        /// A task id or unique prefix of one.
        task_id: String,
    },
    /// Guard Law: is editing `path` authorized by the packet's file scope?
    CheckEdit {
        /// A task id or unique prefix of one.
        task_id: String,
        /// The path an edit would touch.
        path: String,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum Format {
    Toml,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match &cli.command {
        Command::Template { format } => {
            print!("{}", render_template(*format)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Validate { file } => {
            let packet = load_packet(file)?;
            let report = validate_with_protected(&packet, &load_protected(&cli.protected));
            if report.is_ok() {
                println!("ok: '{}' is a valid task packet", packet.title);
                Ok(ExitCode::SUCCESS)
            } else {
                print_violations(&report);
                Ok(ExitCode::FAILURE)
            }
        }
        Command::Submit { file } => {
            // Task admission is ordinary governance: a candidate runtime may
            // describe its succession, not take in work. (The check needs the
            // playbook identity; without --playbook-ref it cannot run — a
            // stated limitation until the compiled harness bakes it in.)
            if let Some(playbook) = &cli.playbook_ref {
                let events = kernel::event::EventLog::at(&cli.events_ledger)
                    .read_all()
                    .unwrap_or_default();
                if let kernel::RuntimeStatus::Candidate { active_runtime } =
                    kernel::runtime_status(&events, &kernel::runtime_ref(playbook))
                {
                    eprintln!(
                        "refused [{}]: task admission is ordinary governance and this \
                         runtime is in candidate mode (active runtime {active_runtime}, \
                         candidate {}).",
                        kernel::succession::codes::RUNTIME_NOT_ACTIVE,
                        kernel::runtime_ref(playbook),
                    );
                    return Ok(ExitCode::FAILURE);
                }
            }
            let packet = load_packet(file)?;
            match admit_with_protected(&packet, now_rfc3339(), &load_protected(&cli.protected)) {
                Ok(record) => {
                    let ledger = Ledger::at(&cli.ledger);
                    ledger.append(&record)?;
                    println!(
                        "recorded {} '{}' -> {}",
                        record.task_id,
                        record.packet.title,
                        ledger.path().display()
                    );
                    Ok(ExitCode::SUCCESS)
                }
                Err(AdmitError::Invalid(report)) => {
                    print_violations(&report);
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Command::List => {
            let records = Ledger::at(&cli.ledger).read_all()?;
            if records.is_empty() {
                println!("(no packets recorded)");
            } else {
                for r in &records {
                    println!(
                        "{}  {:<8?} {:<11?} {}",
                        r.task_id, r.packet.priority, r.status, r.packet.title
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Show { task_id } => match Ledger::at(&cli.ledger).find(task_id)? {
            Some(record) => {
                println!("{}", serde_json::to_string_pretty(&record)?);
                Ok(ExitCode::SUCCESS)
            }
            None => {
                eprintln!("error: no packet matching '{task_id}'");
                Ok(ExitCode::FAILURE)
            }
        },
        Command::CheckEdit { task_id, path } => match Ledger::at(&cli.ledger).find(task_id)? {
            Some(record) => {
                if record.packet.authorizes_write(path) {
                    println!(
                        "allow: '{path}' is within the write scope of {}",
                        record.task_id
                    );
                    Ok(ExitCode::SUCCESS)
                } else {
                    println!(
                        "deny: '{path}' is not in the file scope of {}",
                        record.task_id
                    );
                    Ok(ExitCode::FAILURE)
                }
            }
            None => {
                eprintln!("error: no packet matching '{task_id}'");
                Ok(ExitCode::FAILURE)
            }
        },
    }
}

/// Load protected path prefixes (one per line; `#` comments and blanks
/// ignored). A missing file reads as an empty set — a workspace without a
/// compiled harness has no enforcement tree to protect.
fn load_protected(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Load a packet from a `.json` file (parsed as JSON) or anything else
/// (parsed as TOML).
fn load_packet(path: &Path) -> Result<TaskPacket, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let is_json = path.extension().and_then(|e| e.to_str()) == Some("json");
    let packet = if is_json {
        serde_json::from_str(&text)?
    } else {
        toml::from_str(&text)?
    };
    Ok(packet)
}

fn print_violations(report: &kernel::validate::Report) {
    eprintln!("rejected: {} violation(s)", report.violations.len());
    for v in &report.violations {
        eprintln!("  - {v}");
    }
}

fn render_template(format: Format) -> Result<String, Box<dyn std::error::Error>> {
    match format {
        Format::Toml => Ok(TEMPLATE_TOML.to_string()),
        Format::Json => {
            // Round-trip the TOML template through the typed struct so the JSON
            // template can never drift out of sync with the schema.
            let packet: TaskPacket = toml::from_str(TEMPLATE_TOML)?;
            Ok(serde_json::to_string_pretty(&packet)?)
        }
    }
}

/// A blank, annotated task packet. This is the "typed template" ingredient:
/// the shape a submitter fills in, with the four named fields called out.
const TEMPLATE_TOML: &str = r#"# Task packet — the only shape in which work may enter the system.
# Fill in every field, then: intake submit this-file.toml
#
# All top-level keys must appear before the [[files]] tables below; TOML
# assigns any key after a table header to that table.

title = "Short name for the work"

# Objective: what "done" looks like, specifically. Not "fix the bug".
objective = "State precisely what must be true when this task is complete"

# Constraints: boundaries the work must respect. May be empty.
constraints = [
  "Example: do not change the public API",
]

# Acceptance criteria: mechanically checkable statements. At least one.
acceptance_criteria = [
  "Example: the test suite passes",
]

submitted_by = "your-name"
priority = "medium" # low | medium | high | critical

# Files in scope, with per-file authority ("read" or "write").
# The set of write paths is the contract Guard Laws enforce against.
[[files]]
path = "src/example.rs"
access = "write"
"#;
