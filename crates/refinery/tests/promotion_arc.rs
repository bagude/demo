//! The Refinery's closed loop, end to end at the CLI: propose → gate-approve →
//! promote, with every step landing in the Ledger at its protocol stage — and
//! a tampered proposal refused with the refusal itself recorded as evidence.

use std::path::{Path, PathBuf};
use std::process::Command;

use kernel::event::EventLog;
use kernel::gate::{Approver, Checkpoint, GateStore, Preconditions};

const SPEC: &str = include_str!("../../../harness.patterns.yaml");

fn refinery(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_refinery")))
        .args(args)
        .output()
        .expect("refinery runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn events(ledger: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(ledger)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Approve the proposal's exact bytes at a Gate, the way a human would after
/// reviewing the diff. Returns the checkpoint path.
fn approve_proposal(dir: &Path, cp_dir: &Path) -> PathBuf {
    let (action, base) = refinery::promote::approval_binding_for(dir).unwrap();
    let mut pre = Preconditions::new();
    pre.insert(refinery::promote::BASE_SPEC_TOKEN.into(), base);
    let mut cp = Checkpoint::new(
        "promote-spec",
        "run-arc",
        action,
        "promote refinery proposal",
        "resume:promote",
        pre,
        "2026-08-01T00:00:00Z",
    );
    cp.approve(Approver::claimed("alice"), "2026-08-01T00:00:01Z", None);
    GateStore::at(cp_dir).save(&cp).unwrap()
}

#[test]
fn the_full_arc_proposes_approves_promotes_and_chains() {
    let dir = tempfile::tempdir().unwrap();
    let spec = dir.path().join("harness.patterns.yaml");
    std::fs::write(&spec, SPEC).unwrap();
    let ledger = dir.path().join("events.jsonl");
    let out = dir.path().join("proposals");

    // PROPOSED.
    let (ok, stdout, err) = refinery(&[
        "propose",
        "--spec",
        spec.to_str().unwrap(),
        "--ledger",
        ledger.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--playbook-ref",
        "sha256:pb",
    ]);
    assert!(ok, "{err}");
    assert!(
        stdout.contains("Promotion is gated"),
        "propose prints the approval path: {stdout}"
    );
    let pdir: PathBuf = stdout
        .lines()
        .next()
        .and_then(|l| l.split(" written to ").nth(1))
        .expect("propose names its directory")
        .trim()
        .into();

    // A human reviews and approves the exact bytes.
    let cp_path = approve_proposal(&pdir, &dir.path().join("cp"));

    // COMPLETED: promotion applies the approved bytes.
    let (ok, stdout, err) = refinery(&[
        "promote",
        "--proposal",
        pdir.to_str().unwrap(),
        "--spec",
        spec.to_str().unwrap(),
        "--checkpoint",
        cp_path.to_str().unwrap(),
        "--allow-unproven",
        "--ledger",
        ledger.to_str().unwrap(),
        "--playbook-ref",
        "sha256:pb",
    ]);
    assert!(ok, "{err}");
    assert!(
        stdout.contains("harnessc build"),
        "points at the compile gate"
    );

    // The live spec IS the proposal now (version bumped by the monotone change).
    let live = std::fs::read_to_string(&spec).unwrap();
    assert!(live.contains("version: 0.1.1"));

    // The Ledger tells the whole story at the right stages...
    let evs = events(&ledger);
    let propose = evs
        .iter()
        .find(|e| e["transition"] == "refinery.propose")
        .expect("the proposal is evidence");
    assert_eq!(propose["stage"], "proposed");
    assert_eq!(propose["playbook_ref"], "sha256:pb");
    let promote = evs
        .iter()
        .find(|e| e["transition"] == "refinery.promote")
        .expect("the promotion is evidence");
    assert_eq!(promote["stage"], "completed");
    assert_eq!(promote["decision"], "approved");
    assert!(promote["input_refs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r.as_str().unwrap() == "approver:alice"));

    // ...and the chain still proves it.
    EventLog::at(&ledger)
        .verify_chain()
        .expect("chained history");
}

#[test]
fn a_tampered_proposal_is_refused_and_the_refusal_is_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let spec = dir.path().join("harness.patterns.yaml");
    std::fs::write(&spec, SPEC).unwrap();
    let ledger = dir.path().join("events.jsonl");
    let out = dir.path().join("proposals");

    let (ok, stdout, _) = refinery(&[
        "propose",
        "--spec",
        spec.to_str().unwrap(),
        "--ledger",
        ledger.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok);
    let pdir: PathBuf = stdout
        .lines()
        .next()
        .and_then(|l| l.split(" written to ").nth(1))
        .unwrap()
        .trim()
        .into();
    let cp_path = approve_proposal(&pdir, &dir.path().join("cp"));

    // Tamper AFTER approval: different bytes than the approver signed off on.
    let f = pdir.join(refinery::promote::PROPOSED_SPEC_FILE);
    let mut text = std::fs::read_to_string(&f).unwrap();
    text.push_str("# sneaky\n");
    std::fs::write(&f, text).unwrap();

    let (ok, _, stderr) = refinery(&[
        "promote",
        "--proposal",
        pdir.to_str().unwrap(),
        "--spec",
        spec.to_str().unwrap(),
        "--checkpoint",
        cp_path.to_str().unwrap(),
        "--allow-unproven",
        "--ledger",
        ledger.to_str().unwrap(),
    ]);
    assert!(!ok, "tampered bytes must not promote");
    assert!(stderr.contains("action changed"), "{stderr}");
    // Untouched spec, and the refusal recorded at the authorization stage.
    assert_eq!(std::fs::read_to_string(&spec).unwrap(), SPEC);
    let evs = events(&ledger);
    let rejection = evs
        .iter()
        .find(|e| e["transition"] == "refinery.promote" && e["decision"] == "rejected")
        .expect("the refusal is evidence");
    assert_eq!(rejection["stage"], "authorized");
    assert!(rejection["evidence_refs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r.as_str().unwrap().contains("action changed")));
}
