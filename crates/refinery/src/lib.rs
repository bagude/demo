//! The Refinery.
//!
//! Converts operational *state* into improved *memory*: it reads the Ledger,
//! extracts candidate lessons, and produces a **reviewable patch against the
//! harness spec**. It never edits generated artifacts (those are compiled from
//! the spec), and it never hot-patches the running system — a proposal is
//! written to a proposals directory for a separate, human-approved promotion.
//!
//! > *The running agent never rewrites the rules governing its current run.*
//!
//! The safety posture is conservative on purpose: the Refinery will *strengthen*
//! a spec automatically (e.g. hardening redaction) but will never *weaken* a
//! Guard — widening a file scope is always surfaced as a manual-review lesson,
//! not applied.

use std::io;
use std::path::{Path, PathBuf};

use kernel::event::{Decision, Event};

/// A candidate lesson extracted from operational state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lesson {
    pub title: String,
    pub detail: String,
    /// True if a corresponding safe change was applied to the proposed spec.
    /// False means "surfaced for human review, not applied".
    pub auto_applied: bool,
}

/// One line-level edit to the spec, tracked so a diff can be shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Replace {
        line: usize,
        old: String,
        new: String,
    },
    Insert {
        after_line: usize,
        new: String,
    },
}

/// The ratchet classification of a proposed change.
///
/// **The ratchet** (constitution §14): *automatic promotion is permitted only
/// for transformations proven monotone under a predeclared, mechanically
/// decidable policy ordering.* Everything else — authority widening, constraint
/// relaxation, ambiguous restriction, or a cross-policy tradeoff — stays a
/// reviewable proposal requiring human promotion.
///
/// The ordering declared here is deliberately small and total:
/// - **Monotone (auto):** administrative changes with no semantic policy effect
///   (a version bump).
/// - **Disputed (human):** everything that touches a policy — including changes
///   that *look* like strengthening but are cross-policy (adding redaction
///   trades secrecy against audit evidence; a shorter timeout trades latency
///   against partial operations). When in doubt, Disputed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Monotone,
    Disputed,
}

/// A proposed change together with its ratchet classification and rationale.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub change: Change,
    pub direction: Direction,
    pub rationale: String,
}

/// A complete proposal: lessons, the monotone changes actually applied, the
/// disputed changes left for a human, the proposed spec text, and a diff.
#[derive(Debug, Clone)]
pub struct Proposal {
    pub id: String,
    pub lessons: Vec<Lesson>,
    pub proposed_spec: String,
    /// Monotone changes — applied to `proposed_spec` automatically.
    pub changes: Vec<Change>,
    /// Disputed changes — surfaced for human promotion, NOT applied.
    pub disputed: Vec<Candidate>,
    pub proposal_md: String,
    pub diff: String,
}

impl Proposal {
    /// Whether the proposal actually contains anything.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.disputed.is_empty() && self.lessons.is_empty()
    }
}

/// Analyze a spec and its Ledger, producing a proposal. Does no I/O.
pub fn analyze(spec_text: &str, events: &[Event]) -> Result<Proposal, String> {
    let model = spec::parse_model(spec_text).map_err(|e| e.to_string())?;

    let mut lessons = Vec::new();
    let mut applied: Vec<Change> = Vec::new();
    let mut disputed: Vec<Candidate> = Vec::new();
    let lines: Vec<String> = spec_text.lines().map(String::from).collect();

    // --- Lesson: frequently denied paths (manual review; never auto-widen) ---
    for (path, count) in denied_paths(events) {
        if count >= DENIAL_THRESHOLD {
            lessons.push(Lesson {
                title: format!("path '{path}' denied {count}×"),
                detail: format!(
                    "The Guard blocked writes to '{path}' {count} times. If packets legitimately \
                     need it, add it to their file scope. Widening a Guard is authority widening — \
                     the ratchet never auto-promotes it; this is a human decision."
                ),
                auto_applied: false,
            });
        }
    }

    // --- Lesson: obligations left open (manual review) ---
    let (opened, discharged) = obligation_counts(events);
    if opened > discharged {
        lessons.push(Lesson {
            title: format!("{} validation obligation(s) left open", opened - discharged),
            detail: format!(
                "{opened} obligation(s) were recorded but only {discharged} discharged. Consider \
                 whether the validation step needs to be easier to run, or the workflow tightened."
            ),
            auto_applied: false,
        });
    }

    // --- DISPUTED: harden ledger redaction.
    // Adding redaction *looks* like strengthening, but the constitution names it
    // a cross-policy tradeoff (secrecy vs. required audit evidence). The ratchet
    // therefore refuses to auto-promote it — it becomes a human proposal.
    if let Some(ledger) = &model.bindings.ledger {
        if !events.is_empty() && !ledger.redact.iter().any(|r| r == "raw_model_context") {
            if let Some(change) = harden_redaction(&lines) {
                let rationale = "adding 'raw_model_context' to redaction trades secrecy against \
                    audit evidence — a cross-policy change the ratchet cannot classify as monotone, \
                    so it requires human promotion"
                    .to_string();
                lessons.push(Lesson {
                    title: "harden ledger redaction (proposed, not applied)".into(),
                    detail: rationale.clone(),
                    auto_applied: false,
                });
                disputed.push(Candidate {
                    change,
                    direction: Direction::Disputed,
                    rationale,
                });
            }
        }
    }

    // --- MONOTONE: bump the harness version.
    // Administrative, no semantic policy effect — provably safe under the
    // declared ordering, so it is applied automatically as a promotion marker.
    if let Some(change) = bump_version(&lines) {
        applied.push(change);
    }

    let proposed_spec = apply_changes(&lines, &applied);
    let diff = render_diff(&applied, &disputed);
    let id = proposal_id(spec_text, events);
    let proposal_md = render_proposal_md(&model.harness.name, &lessons, &applied, &disputed);

    Ok(Proposal {
        id,
        lessons,
        proposed_spec,
        changes: applied,
        disputed,
        proposal_md,
        diff,
    })
}

/// Threshold at which a denied path becomes a lesson.
const DENIAL_THRESHOLD: usize = 2;

fn denied_paths(events: &[Event]) -> Vec<(String, usize)> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for ev in events {
        if ev.decision != Decision::Denied {
            continue;
        }
        for r in &ev.input_refs {
            if let Some(path) = r.strip_prefix("path:") {
                match counts.iter_mut().find(|(p, _)| p == path) {
                    Some((_, c)) => *c += 1,
                    None => counts.push((path.to_string(), 1)),
                }
            }
        }
    }
    counts
}

fn obligation_counts(events: &[Event]) -> (usize, usize) {
    let opened = events
        .iter()
        .filter(|e| e.transition.starts_with("post_tool.obligation."))
        .count();
    let discharged = events
        .iter()
        .filter(|e| e.transition.starts_with("obligation.discharge."))
        .count();
    (opened, discharged)
}

/// Bump the patch component of the first `version:` line under `harness:`.
fn bump_version(lines: &[String]) -> Option<Change> {
    let harness_idx = lines.iter().position(|l| l.trim() == "harness:")?;
    for (i, line) in lines.iter().enumerate().skip(harness_idx + 1) {
        let trimmed = line.trim();
        // Stop if we leave the harness block (a new top-level key).
        if !line.starts_with(' ') && !trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("version:") {
            let current = rest.trim();
            let bumped = bump_patch(current)?;
            let indent = &line[..line.len() - line.trim_start().len()];
            return Some(Change::Replace {
                line: i,
                old: line.clone(),
                new: format!("{indent}version: {bumped}"),
            });
        }
    }
    None
}

fn bump_patch(v: &str) -> Option<String> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let patch: u64 = parts[2].parse().ok()?;
    Some(format!("{}.{}.{}", parts[0], parts[1], patch + 1))
}

/// Insert a `raw_model_context` item after the last item of the `redact:` list.
fn harden_redaction(lines: &[String]) -> Option<Change> {
    let redact_idx = lines.iter().position(|l| l.trim() == "redact:")?;
    // Find the extent of the list items that follow.
    let mut last_item = redact_idx;
    let mut item_line = None;
    for (i, line) in lines.iter().enumerate().skip(redact_idx + 1) {
        if line.trim_start().starts_with("- ") {
            last_item = i;
            item_line = Some(line.clone());
        } else if !line.trim().is_empty() {
            break;
        }
    }
    let template = item_line?;
    let indent = &template[..template.len() - template.trim_start().len()];
    Some(Change::Insert {
        after_line: last_item,
        new: format!("{indent}- raw_model_context"),
    })
}

/// Apply line changes to produce the proposed text.
fn apply_changes(lines: &[String], changes: &[Change]) -> String {
    let mut out: Vec<String> = lines.to_vec();
    // Apply replacements first (indices stay valid), then insertions from the
    // bottom up so earlier indices are unaffected.
    for change in changes {
        if let Change::Replace { line, new, .. } = change {
            out[*line] = new.clone();
        }
    }
    let mut inserts: Vec<(usize, String)> = changes
        .iter()
        .filter_map(|c| match c {
            Change::Insert { after_line, new } => Some((*after_line, new.clone())),
            _ => None,
        })
        .collect();
    inserts.sort_by(|a, b| b.0.cmp(&a.0));
    for (after, new) in inserts {
        out.insert(after + 1, new);
    }
    let mut text = out.join("\n");
    text.push('\n');
    text
}

fn render_change_hunk(change: &Change) -> String {
    match change {
        Change::Replace { line, old, new } => {
            format!("@@ line {} @@\n-{old}\n+{new}\n", line + 1)
        }
        Change::Insert { after_line, new } => {
            format!("@@ after line {} @@\n+{new}\n", after_line + 1)
        }
    }
}

fn render_diff(applied: &[Change], disputed: &[Candidate]) -> String {
    let mut s = String::from("--- harness.patterns.yaml\n+++ harness.patterns.proposed.yaml\n");
    s.push_str("# APPLIED (monotone — auto-promoted)\n");
    for change in applied {
        s.push_str(&render_change_hunk(change));
    }
    if !disputed.is_empty() {
        s.push_str("\n# DISPUTED (NOT applied — requires human promotion)\n");
        for c in disputed {
            s.push_str(&format!("# {}\n", c.rationale));
            s.push_str(&render_change_hunk(&c.change));
        }
    }
    s
}

fn render_proposal_md(
    harness: &str,
    lessons: &[Lesson],
    applied: &[Change],
    disputed: &[Candidate],
) -> String {
    let mut s = String::new();
    s.push_str(&format!("# Refinery proposal for `{harness}`\n\n"));
    s.push_str(
        "This is a **proposal against the spec**, not a change to the running system. Promotion \
         is a separate, human-approved step: review `changes.diff`, apply it to \
         `harness.patterns.yaml`, and recompile. The running agent never rewrites the rules \
         governing its current run.\n\n",
    );

    s.push_str("## Lessons\n\n");
    if lessons.is_empty() {
        s.push_str("_No lessons extracted from the current Ledger._\n\n");
    } else {
        for l in lessons {
            let tag = if l.auto_applied {
                "auto-applied"
            } else {
                "manual review"
            };
            s.push_str(&format!("- **{}** ({tag}): {}\n", l.title, l.detail));
        }
        s.push('\n');
    }

    s.push_str("## Applied automatically (monotone under the ratchet)\n\n");
    if applied.is_empty() {
        s.push_str("_None._\n\n");
    } else {
        s.push_str(&format!(
            "{} change(s) applied to `harness.patterns.proposed.yaml`.\n\n",
            applied.len()
        ));
    }

    s.push_str("## Requires human promotion (disputed)\n\n");
    if disputed.is_empty() {
        s.push_str("_None._\n");
    } else {
        s.push_str(
            "These changes were withheld by the ratchet because their effect is not provably \
             monotone. Review and apply by hand if appropriate:\n\n",
        );
        for c in disputed {
            s.push_str(&format!("- {}\n", c.rationale));
        }
    }
    s
}

fn proposal_id(spec_text: &str, events: &[Event]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(spec_text.as_bytes());
    for ev in events {
        // Deterministic, and independent of pretty-printing.
        hasher.update(ev.transition.as_bytes());
        hasher.update(format!("{:?}", ev.decision).as_bytes());
    }
    let digest = hasher.finalize();
    let mut hex = String::new();
    for b in digest.iter().take(6) {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// Write a proposal under `proposals_root/<id>/`, refusing to touch the live
/// spec or anything outside that directory.
///
/// Returns the proposal directory. `spec_path` is passed only so the guardrail
/// can prove none of the written files coincides with the live spec.
pub fn write_proposal(
    proposal: &Proposal,
    proposals_root: &Path,
    spec_path: &Path,
) -> io::Result<PathBuf> {
    let dir = proposals_root.join(&proposal.id);
    std::fs::create_dir_all(&dir)?;

    let files = [
        ("harness.patterns.proposed.yaml", &proposal.proposed_spec),
        ("changes.diff", &proposal.diff),
        ("PROPOSAL.md", &proposal.proposal_md),
    ];

    let spec_canon = canonical(spec_path);
    for (name, content) in files {
        let path = dir.join(name);
        // Guardrail: never write onto the live spec.
        if canonical(&path) == spec_canon {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refinery refused to write onto the live spec file",
            ));
        }
        std::fs::write(&path, content)?;
    }
    Ok(dir)
}

/// Best-effort canonicalization that also works for not-yet-existing files.
fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| {
        let parent = path.parent().and_then(|p| std::fs::canonicalize(p).ok());
        match (parent, path.file_name()) {
            (Some(p), Some(name)) => p.join(name),
            _ => path.to_path_buf(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::event::{Decision, Event};

    const SPEC: &str = include_str!("../../../harness.patterns.yaml");

    fn ev(transition: &str, decision: Decision, path: Option<&str>) -> Event {
        Event {
            run_id: "r".into(),
            task_id: None,
            parent_task_id: None,
            action_id: "a".into(),
            actor: "kernel".into(),
            timestamp: "2026-07-31T00:00:00Z".into(),
            transition: transition.into(),
            input_refs: path.map(|p| format!("path:{p}")).into_iter().collect(),
            output_refs: vec![],
            decision,
            evidence_refs: vec![],
            playbook_ref: String::new(),
            kernel_ref: String::new(),
            attempt_id: None,
        }
    }

    #[test]
    fn bumps_the_harness_version() {
        let proposal = analyze(SPEC, &[]).unwrap();
        assert!(proposal.proposed_spec.contains("version: 0.1.1"));
        assert!(proposal.diff.contains("+  version: 0.1.1"));
    }

    #[test]
    fn frequent_denials_become_a_manual_lesson() {
        let events = vec![
            ev("pre_tool.edit", Decision::Denied, Some(".env")),
            ev("pre_tool.edit", Decision::Denied, Some(".env")),
        ];
        let proposal = analyze(SPEC, &events).unwrap();
        let lesson = proposal
            .lessons
            .iter()
            .find(|l| l.title.contains(".env"))
            .unwrap();
        assert!(
            !lesson.auto_applied,
            "widening a Guard must never be auto-applied"
        );
    }

    #[test]
    fn redaction_hardening_is_disputed_not_applied() {
        // The constitution's ratchet names added redaction a cross-policy
        // tradeoff (secrecy vs. audit evidence). It must be proposed, not applied.
        let weakened = SPEC.replace("      - raw_model_context\n", "");
        let events = vec![ev("pre_tool.edit", Decision::Allowed, Some("src/lib.rs"))];
        let proposal = analyze(&weakened, &events).unwrap();

        // NOT applied to the proposed spec...
        assert!(!proposal.proposed_spec.contains("raw_model_context"));
        // ...and surfaced as a disputed change for a human.
        assert!(proposal
            .disputed
            .iter()
            .any(|c| c.direction == Direction::Disputed));
        assert!(proposal
            .lessons
            .iter()
            .any(|l| !l.auto_applied && l.title.contains("redaction")));
    }

    #[test]
    fn only_monotone_changes_are_applied() {
        let weakened = SPEC.replace("      - raw_model_context\n", "");
        let events = vec![ev("pre_tool.edit", Decision::Allowed, Some("src/lib.rs"))];
        let proposal = analyze(&weakened, &events).unwrap();
        // The one auto-applied change is the administrative version bump.
        assert_eq!(proposal.changes.len(), 1);
        assert!(proposal.proposed_spec.contains("version: 0.1.1"));
    }

    #[test]
    fn write_proposal_refuses_to_touch_the_live_spec() {
        let dir = tempfile::tempdir().unwrap();
        let spec_path = dir.path().join("harness.patterns.yaml");
        std::fs::write(&spec_path, SPEC).unwrap();
        let before = std::fs::read(&spec_path).unwrap();

        let proposal = analyze(SPEC, &[]).unwrap();
        let out = write_proposal(
            &proposal,
            &dir.path().join("refinery/proposals"),
            &spec_path,
        )
        .unwrap();

        // The proposal landed under the proposals dir...
        assert!(out.starts_with(dir.path().join("refinery/proposals")));
        assert!(out.join("PROPOSAL.md").exists());
        // ...and the live spec is byte-for-byte unchanged.
        assert_eq!(std::fs::read(&spec_path).unwrap(), before);
    }
}
