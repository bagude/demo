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
