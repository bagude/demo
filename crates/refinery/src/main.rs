//! `refinery` — read the Ledger, propose a patch against the harness spec,
//! and promote **approved** proposals.
//!
//! `propose` writes a proposal directory, never an edit to the live spec or
//! the generated Playbook. `promote` is the separate, human-approved step made
//! into tooling: it applies a proposal only under a Gate approval bound to the
//! proposal's exact bytes, and records the outcome — promotion or refusal —
//! in the Ledger. The running agent never rewrites the rules governing its
//! current run; a human's approval, not this binary, is what changes them.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use kernel::clock::now_rfc3339;
use kernel::event::{Decision, Event, EventLog, Stage};

#[derive(Parser)]
#[command(name = "refinery", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze the Ledger and write a reviewable proposal directory.
    Propose {
        /// The harness spec to propose changes against.
        #[arg(long, default_value = "harness.patterns.yaml")]
        spec: PathBuf,
        /// The Ledger to learn from — and to record the proposal in.
        #[arg(long, default_value = "evidence/events.jsonl")]
        ledger: PathBuf,
        /// Directory to write proposals under.
        #[arg(long, default_value = "refinery/proposals")]
        out: PathBuf,
        /// Run id recorded on the proposal event.
        #[arg(long, default_value = "refinery")]
        run_id: String,
        /// Playbook identity to bind the proposal event to.
        #[arg(long)]
        playbook_ref: Option<String>,
    },
    /// Apply an APPROVED proposal to the live spec, under Gate revalidation.
    Promote {
        /// The proposal directory written by `propose`.
        #[arg(long)]
        proposal: PathBuf,
        /// The live spec the proposal replaces.
        #[arg(long, default_value = "harness.patterns.yaml")]
        spec: PathBuf,
        /// The approved Gate checkpoint bound to the proposal's bytes.
        #[arg(long)]
        checkpoint: PathBuf,
        /// Identity registry for re-proving signature-authenticated approvals.
        #[arg(long)]
        trusted_keys: Option<PathBuf>,
        /// Pinned authority key (`ed25519:<hex>` or `@file`) for the registry.
        #[arg(long)]
        authority: Option<String>,
        /// Accept approvals promotion cannot re-prove (claimed/token auth).
        #[arg(long)]
        allow_unproven: bool,
        /// The Ledger: required for anchored/obligated checkpoints, and where
        /// the promotion decision is recorded.
        #[arg(long, default_value = "evidence/events.jsonl")]
        ledger: PathBuf,
        /// Playbook identity to bind the promotion event to.
        #[arg(long)]
        playbook_ref: Option<String>,
    },
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
    match Cli::parse().command {
        Command::Propose {
            spec,
            ledger,
            out,
            run_id,
            playbook_ref,
        } => {
            let spec_text = std::fs::read_to_string(&spec)
                .map_err(|e| format!("cannot read {}: {e}", spec.display()))?;
            let events = EventLog::at(&ledger).read_all()?;

            let proposal = refinery::analyze(&spec_text, &events)?;
            let dir = refinery::write_proposal(&proposal, &out, &spec)?;

            // The proposal is itself evidence: the arc's `proposed` stage.
            record(
                &ledger,
                &run_id,
                "refinery.propose",
                Stage::Proposed,
                Decision::Recorded,
                vec![format!("spec:{}", proposal.base_spec_ref)],
                vec![format!("proposal:{}", proposal.authored_ref)],
                vec![format!("proposal_id:{}", proposal.id)],
                playbook_ref.as_deref(),
            )?;

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
            let (action, base) = refinery::promote::approval_binding_for(&dir)?;
            println!("Promotion is gated. To approve these exact bytes:");
            println!(
                "  kernel gate request --gate promote-spec --run-id <run> \\\n    \
                 --action-hash {action} --precondition {}={base} \\\n    \
                 --checkpoints checkpoints --ledger {}",
                refinery::promote::BASE_SPEC_TOKEN,
                ledger.display()
            );
            println!(
                "  kernel gate approve --checkpoint <path> --approver <who> [--auth signature ...]"
            );
            println!(
                "  refinery promote --proposal {} --spec {} --checkpoint <path>",
                dir.display(),
                spec.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Promote {
            proposal,
            spec,
            checkpoint,
            trusted_keys,
            authority,
            allow_unproven,
            ledger,
            playbook_ref,
        } => {
            let req = refinery::promote::PromoteRequest {
                proposal_dir: &proposal,
                spec_path: &spec,
                checkpoint_path: &checkpoint,
                trusted_keys: trusted_keys.as_deref(),
                authority: authority.as_deref(),
                allow_unproven,
                ledger: Some(&ledger),
                now: now_rfc3339(),
            };
            match refinery::promote::promote(&req) {
                Ok(done) => {
                    // The arc completes: approved bytes are now the spec.
                    record(
                        &ledger,
                        &done.run_id,
                        "refinery.promote",
                        Stage::Completed,
                        Decision::Approved,
                        vec![
                            format!("proposal:{}", done.proposal_ref),
                            format!("base:{}", done.base_spec_ref),
                            format!("gate:{}", done.gate_id),
                            format!("approver:{}", done.approver),
                        ],
                        vec![format!("spec:{}", done.proposal_ref)],
                        if done.edited {
                            vec!["edited:proposal differs from authored bytes".into()]
                        } else {
                            vec![]
                        },
                        playbook_ref.as_deref(),
                    )?;
                    println!("promoted {} -> {}", done.proposal_ref, spec.display());
                    if done.edited {
                        println!("  note: proposal was hand-edited after authoring (recorded)");
                    }
                    println!("  approved by {} at gate {}", done.approver, done.gate_id);
                    println!("Recompile to make it live: harnessc build --out .");
                    Ok(ExitCode::SUCCESS)
                }
                Err(refinery::promote::PromoteError::Refused(reason)) => {
                    // A refusal is evidence, not just an exit code — the same
                    // posture as `gate verify`.
                    record(
                        &ledger,
                        "refinery",
                        "refinery.promote",
                        Stage::Authorized,
                        Decision::Rejected,
                        vec![format!("proposal_dir:{}", proposal.display())],
                        vec![],
                        vec![format!("reason:{reason}")],
                        playbook_ref.as_deref(),
                    )?;
                    eprintln!("promotion refused: {reason}");
                    Ok(ExitCode::FAILURE)
                }
                Err(e) => Err(e.into()),
            }
        }
    }
}

/// Append a Refinery lifecycle event. The append is not best-effort — losing
/// promotion evidence is an error.
#[allow(clippy::too_many_arguments)]
fn record(
    ledger: &std::path::Path,
    run_id: &str,
    transition: &str,
    stage: Stage,
    decision: Decision,
    input_refs: Vec<String>,
    output_refs: Vec<String>,
    evidence_refs: Vec<String>,
    playbook_ref: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let playbook: String = playbook_ref.unwrap_or_default().into();
    let event = Event {
        run_id: run_id.into(),
        task_id: None,
        parent_task_id: None,
        action_id: transition.into(),
        actor: "refinery".into(),
        timestamp: now_rfc3339(),
        transition: transition.into(),
        stage: stage.as_str().into(),
        input_refs,
        output_refs,
        decision,
        evidence_refs,
        runtime_ref: kernel::runtime_ref(&playbook),
        playbook_ref: playbook,
        kernel_ref: kernel::kernel_ref(),
        attempt_id: None,
    };
    EventLog::at(ledger).append(&event)?;
    Ok(())
}
