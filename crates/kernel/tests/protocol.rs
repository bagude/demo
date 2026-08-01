//! The unified transition protocol end-to-end: one governed action walks
//! proposed → authorized → executing → completed, and every event the kernel
//! writes names its lifecycle stage on the envelope — including the Gate's
//! own arc, which previously left no Ledger evidence at all.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn kernel_with_stdin(args: &[&str], stdin_json: &str) -> (bool, String, String) {
    let mut child = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_kernel")))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kernel spawns");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_json.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("kernel runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn kernel(args: &[&str]) -> (bool, String, String) {
    kernel_with_stdin(args, "")
}

fn events(ledger: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(ledger)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn one_governed_arc_walks_the_protocol_and_every_event_names_its_stage() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let ledger_s = ledger.to_str().unwrap();
    let cp_dir = dir.path().join("cp");

    // PROPOSED: the Gate halts an action into a durable checkpoint — and the
    // halt itself is now Ledger evidence.
    let (ok, stdout, err) = kernel(&[
        "gate",
        "request",
        "--gate",
        "release",
        "--run-id",
        "run-1",
        "--action-hash",
        "sha256:action",
        "--checkpoints",
        cp_dir.to_str().unwrap(),
        "--ledger",
        ledger_s,
        "--require-obligation",
        "require-validation",
        "--playbook-ref",
        "sha256:pb",
    ]);
    assert!(ok, "{err}");
    let cp_path = stdout.trim().to_string();

    // EXECUTING: an edit runs; the obligation opening is evidence from the
    // execution phase.
    let (ok, _, err) = kernel_with_stdin(
        &[
            "post-tool",
            "--ledger",
            ledger_s,
            "--run-id",
            "run-1",
            "--playbook-ref",
            "sha256:pb",
        ],
        &serde_json::json!({"tool_input": {"file_path": "src/x.rs"}}).to_string(),
    );
    assert!(ok, "{err}");

    // COMPLETED: validation discharges the debt.
    let (ok, _, err) = kernel(&[
        "validate",
        "--ledger",
        ledger_s,
        "--run-id",
        "run-1",
        "--playbook-ref",
        "sha256:pb",
    ]);
    assert!(ok, "{err}");

    // AUTHORIZED, twice: the approval decision, then resume revalidation.
    let (ok, _, err) = kernel(&[
        "gate",
        "approve",
        "--checkpoint",
        &cp_path,
        "--approver",
        "alice",
        "--ledger",
        ledger_s,
        "--playbook-ref",
        "sha256:pb",
    ]);
    assert!(ok, "{err}");
    let (ok, _, err) = kernel(&[
        "gate",
        "verify",
        "--checkpoint",
        &cp_path,
        "--action-hash",
        "sha256:action",
        "--ledger",
        ledger_s,
        "--playbook-ref",
        "sha256:pb",
    ]);
    assert!(ok, "{err}");

    // The protocol, read back from the evidence: each subject at its stage.
    let evs = events(&ledger);
    let stage_of = |transition: &str| -> Vec<&str> {
        evs.iter()
            .filter(|e| e["transition"] == transition)
            .map(|e| e["stage"].as_str().unwrap())
            .collect()
    };
    assert_eq!(stage_of("gate.request"), ["proposed"]);
    assert_eq!(
        stage_of("post_tool.obligation.require-validation"),
        ["executing"]
    );
    assert_eq!(
        stage_of("obligation.discharge.require-validation"),
        ["completed"]
    );
    assert_eq!(stage_of("gate.approve"), ["authorized"]);
    assert_eq!(stage_of("gate.verify"), ["authorized"]);

    // Every event the kernel writes names a stage — no unclassified evidence.
    for e in &evs {
        let stage = e["stage"].as_str().unwrap();
        assert!(
            [
                "proposed",
                "authorized",
                "executing",
                "completed",
                "recorded"
            ]
            .contains(&stage),
            "unstaged event: {e}"
        );
        assert_eq!(e["playbook_ref"], "sha256:pb", "run-bound throughout: {e}");
    }

    // And the chain still proves the whole history.
    let (ok, _, err) = kernel(&["ledger", "verify", "--ledger", ledger_s]);
    assert!(ok, "the staged history chains: {err}");
}

#[test]
fn a_refused_resume_is_authorized_stage_rejected_evidence() {
    // Refusals are where evidence matters most: a gate.verify rejection lands
    // in the Ledger with its reason, not just an exit code.
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let ledger_s = ledger.to_str().unwrap();
    let cp_dir = dir.path().join("cp");

    let (ok, stdout, _) = kernel(&[
        "gate",
        "request",
        "--gate",
        "g",
        "--run-id",
        "r",
        "--action-hash",
        "sha256:x",
        "--checkpoints",
        cp_dir.to_str().unwrap(),
        "--ledger",
        ledger_s,
    ]);
    assert!(ok);
    let cp_path = stdout.trim().to_string();
    let (ok, _, _) = kernel(&[
        "gate",
        "approve",
        "--checkpoint",
        &cp_path,
        "--approver",
        "a",
    ]);
    assert!(ok);

    // Resume with a DIFFERENT action: refused, and recorded as such.
    let (ok, _, _) = kernel(&[
        "gate",
        "verify",
        "--checkpoint",
        &cp_path,
        "--action-hash",
        "sha256:tampered",
        "--ledger",
        ledger_s,
    ]);
    assert!(!ok);
    let evs = events(&ledger);
    let rejection = evs
        .iter()
        .find(|e| e["transition"] == "gate.verify" && e["decision"] == "rejected")
        .expect("the refusal is evidence");
    assert_eq!(rejection["stage"], "authorized");
    assert!(
        rejection["evidence_refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap().contains("action changed")),
        "the reason travels with the record: {rejection}"
    );
}

#[test]
fn no_packet_means_no_authorization_and_the_refusal_is_a_block() {
    // The fail-safe that real-life testing caught: with no active packet the
    // Guard used to exit 1 — which the hook protocol treats as a WARNING, so
    // an unpacketed session sailed through ungoverned. Absent authorization
    // must be a block (exit 2), and the refusal must be evidence.
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let missing = dir.path().join("tasks/active.json");

    let mut child = std::process::Command::new(PathBuf::from(env!("CARGO_BIN_EXE_kernel")))
        .args([
            "pre-tool",
            "--packet",
            missing.to_str().unwrap(),
            "--ledger",
            ledger.to_str().unwrap(),
            "--run-id",
            "run-unpacketed",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"tool_input": {"file_path": "src/x.rs"}}"#)
        .unwrap();
    let out = child.wait_with_output().unwrap();

    // Exit 2 — the BLOCK signal — not a generic error status.
    assert_eq!(out.status.code(), Some(2), "deny must be exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no active task packet"), "{stderr}");

    // And the refusal is chained evidence with its reason.
    let evs = events(&ledger);
    let denial = evs
        .iter()
        .find(|e| e["transition"] == "pre_tool.edit" && e["decision"] == "denied")
        .expect("the refusal is evidence");
    assert_eq!(denial["stage"], "authorized");
    assert!(denial["evidence_refs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r.as_str().unwrap().contains("no active task packet")));

    // A tool call with no file target stays out of scope — allowed — even
    // with no packet: the law governs file writes, not every tool.
    let (ok, _, _) = kernel_with_stdin(
        &[
            "pre-tool",
            "--packet",
            missing.to_str().unwrap(),
            "--run-id",
            "run-unpacketed",
        ],
        r#"{"tool_input": {"query": "hello"}}"#,
    );
    assert!(ok, "non-file tool calls are outside the file-scope law");
}

#[test]
fn free_form_evidence_declares_its_stage_and_defaults_to_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let ledger_s = ledger.to_str().unwrap();

    let (ok, _, _) = kernel(&[
        "event",
        "--ledger",
        ledger_s,
        "--transition",
        "note",
        "--decision",
        "recorded",
    ]);
    assert!(ok);
    let (ok, _, _) = kernel(&[
        "event",
        "--ledger",
        ledger_s,
        "--transition",
        "deploy.started",
        "--decision",
        "recorded",
        "--stage",
        "executing",
    ]);
    assert!(ok);
    let (ok, _, stderr) = kernel(&[
        "event",
        "--ledger",
        ledger_s,
        "--transition",
        "x",
        "--decision",
        "recorded",
        "--stage",
        "bogus",
    ]);
    assert!(!ok, "an unknown stage is refused, not recorded");
    assert!(stderr.contains("unknown lifecycle stage"), "{stderr}");

    let evs = events(&ledger);
    assert_eq!(evs[0]["stage"], "recorded");
    assert_eq!(evs[1]["stage"], "executing");
}
