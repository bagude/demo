//! The Ledger chain end-to-end: records appended by the compiled `kernel`
//! binary form a verifiable hash chain, and `kernel ledger verify` proves it —
//! or names the exact line where history was altered.

use std::path::PathBuf;
use std::process::Command;

fn kernel(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_kernel")))
        .args(args)
        .output()
        .expect("kernel runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn gate_checkpoint_anchors_the_chain_head_and_refuses_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let ledger_s = ledger.to_str().unwrap();
    let checkpoints = dir.path().join("checkpoints");
    let checkpoints_s = checkpoints.to_str().unwrap();

    let append = |t: &str| {
        let (ok, _, err) = kernel(&[
            "event",
            "--ledger",
            ledger_s,
            "--transition",
            t,
            "--decision",
            "recorded",
        ]);
        assert!(ok, "append: {err}");
    };
    append("pre_tool.edit");
    append("post_tool.obligation.require-validation");

    // Request a checkpoint WITH the ledger: the chain head is pinned into the
    // durable record — the external anchor the chain itself cannot provide.
    let (ok, stdout, err) = kernel(&[
        "gate",
        "request",
        "--gate",
        "approve-commit",
        "--run-id",
        "run-1",
        "--action-hash",
        "sha256:action",
        "--checkpoints",
        checkpoints_s,
        "--ledger",
        ledger_s,
    ]);
    assert!(ok, "request: {err}");
    let cp_path = stdout.trim().to_string();
    let cp: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cp_path).unwrap()).unwrap();
    let anchored = cp["ledger_head"].as_str().expect("head is anchored");
    assert!(anchored.starts_with("sha256:"));

    // History may grow past the anchor; the approval flow proceeds normally.
    append("obligation.discharge.require-validation");
    let (ok, _, err) = kernel(&[
        "gate",
        "approve",
        "--checkpoint",
        &cp_path,
        "--approver",
        "alice",
    ]);
    assert!(ok, "approve: {err}");
    let (ok, _, err) = kernel(&[
        "gate",
        "verify",
        "--checkpoint",
        &cp_path,
        "--action-hash",
        "sha256:action",
        "--ledger",
        ledger_s,
    ]);
    assert!(ok, "an intact, anchor-containing log resumes: {err}");

    // Truncate the tail past the anchor. The remaining chain is internally
    // consistent — the exact blind spot — but the Gate pinned the head, so
    // resume is refused instead of silently proceeding over erased history.
    let text = std::fs::read_to_string(&ledger).unwrap();
    let one_line: Vec<&str> = text.lines().take(1).collect();
    std::fs::write(&ledger, one_line.join("\n") + "\n").unwrap();
    let (ok, _, _) = kernel(&["ledger", "verify", "--ledger", ledger_s]);
    assert!(ok, "the chain alone cannot see truncation");
    let (ok, _, stderr) = kernel(&[
        "gate",
        "verify",
        "--checkpoint",
        &cp_path,
        "--action-hash",
        "sha256:action",
        "--ledger",
        ledger_s,
    ]);
    assert!(!ok, "the anchored Gate can");
    assert!(
        stderr.contains("anchored head") && stderr.contains("truncated"),
        "the refusal explains itself: {stderr}"
    );
}

#[test]
fn gate_request_refuses_to_notarize_a_broken_chain() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let ledger_s = ledger.to_str().unwrap();

    for t in ["a", "b"] {
        let (ok, _, _) = kernel(&[
            "event",
            "--ledger",
            ledger_s,
            "--transition",
            t,
            "--decision",
            "recorded",
        ]);
        assert!(ok);
    }
    let text = std::fs::read_to_string(&ledger).unwrap();
    std::fs::write(&ledger, text.replacen("\"a\"", "\"z\"", 1)).unwrap();

    let (ok, _, stderr) = kernel(&[
        "gate",
        "request",
        "--gate",
        "g",
        "--run-id",
        "r",
        "--action-hash",
        "sha256:x",
        "--checkpoints",
        dir.path().join("cp").to_str().unwrap(),
        "--ledger",
        ledger_s,
    ]);
    assert!(!ok, "a checkpoint must not notarize corrupt history");
    assert!(stderr.contains("broken ledger chain"), "{stderr}");
}

#[test]
fn cli_appends_chain_and_verify_proves_or_refutes() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let ledger_s = ledger.to_str().unwrap();

    for transition in ["gate.approve", "pre_tool.edit", "obligation.discharge.x"] {
        let (ok, _, err) = kernel(&[
            "event",
            "--ledger",
            ledger_s,
            "--transition",
            transition,
            "--decision",
            "recorded",
            "--playbook-ref",
            "sha256:pb",
        ]);
        assert!(ok, "append succeeds: {err}");
    }

    let (ok, stdout, _) = kernel(&["ledger", "verify", "--ledger", ledger_s]);
    assert!(ok, "an untouched log verifies");
    assert!(
        stdout.contains("3 record(s), 3 chained") && stdout.contains("head sha256:"),
        "the report counts the chain and prints the anchorable head: {stdout}"
    );

    // Rewrite history: alter the first record's transition.
    let text = std::fs::read_to_string(&ledger).unwrap();
    let tampered = text.replacen("gate.approve", "gate.reject", 1);
    std::fs::write(&ledger, tampered).unwrap();

    let (ok, _, stderr) = kernel(&["ledger", "verify", "--ledger", ledger_s]);
    assert!(!ok, "rewritten history fails verification");
    assert!(
        stderr.contains("prev-link"),
        "the break is located and explained: {stderr}"
    );
}
