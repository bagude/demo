//! `refinery` — read the Ledger, propose a patch against the harness spec.
//!
//! The output is a proposal directory, never an edit to the live spec or the
//! generated Playbook. Promotion (reviewing the diff and applying it) is a
//! separate, human step.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use kernel::event::EventLog;

#[derive(Parser)]
#[command(name = "refinery", version, about)]
struct Cli {
    /// The harness spec to propose changes against.
    #[arg(long, default_value = "harness.patterns.yaml")]
    spec: PathBuf,
    /// The Ledger to learn from.
    #[arg(long, default_value = "evidence/events.jsonl")]
    ledger: PathBuf,
    /// Directory to write proposals under.
    #[arg(long, default_value = "refinery/proposals")]
    out: PathBuf,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let spec_text = std::fs::read_to_string(&cli.spec)
        .map_err(|e| format!("cannot read {}: {e}", cli.spec.display()))?;
    let events = EventLog::at(&cli.ledger).read_all()?;

    let proposal = refinery::analyze(&spec_text, &events)?;
    let dir = refinery::write_proposal(&proposal, &cli.out, &cli.spec)?;

    println!("proposal {} written to {}", proposal.id, dir.display());
    println!(
        "  {} lesson(s), {} auto-applied (monotone), {} disputed (needs human)",
        proposal.lessons.len(),
        proposal.changes.len(),
        proposal.disputed.len()
    );
    for lesson in &proposal.lessons {
        let tag = if lesson.auto_applied {
            "auto"
        } else {
            "review"
        };
        println!("  [{tag}] {}", lesson.title);
    }
    println!(
        "Promotion is a separate human step: review {}/changes.diff, apply to the spec, recompile.",
        dir.display()
    );
    Ok(ExitCode::SUCCESS)
}
