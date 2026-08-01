//! The commit Gate leaves evidence: every actual `git commit` evaluation —
//! allow or deny — is a governed decision appended to the Ledger, bound to the
//! run (`playbook_ref`) and to the enforcement binary that made it
//! (`kernel_ref`). A blocked commit that leaves no record is a hole in the
//! evidence; these tests drive the compiled `kernel` binary through the full
//! obligation lifecycle and read the record back.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PLAYBOOK: &str = "sha256:playbook-under-test";

fn kernel_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kernel"))
}

/// Run a kernel subcommand with `stdin_json` piped in; return (success, stderr).
fn run_with_stdin(args: &[&str], stdin_json: &str) -> (bool, String) {
    let mut child = Command::new(kernel_bin())
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
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn bash_call(command: &str) -> String {
    serde_json::json!({ "tool_input": { "command": command } }).to_string()
}

fn events(ledger: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(ledger)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("ledger lines are JSON"))
        .collect()
}

#[test]
fn commit_gate_decisions_are_recorded_and_run_bound() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let ledger_s = ledger.to_str().unwrap();
    let pre_commit = [
        "pre-commit",
        "--ledger",
        ledger_s,
        "--run-id",
        "run-1",
        "--require",
        "require-validation",
        "--playbook-ref",
        PLAYBOOK,
    ];

    // 1. An edit opens the obligation.
    let (ok, _) = run_with_stdin(
        &[
            "post-tool",
            "--ledger",
            ledger_s,
            "--run-id",
            "run-1",
            "--playbook-ref",
            PLAYBOOK,
        ],
        &serde_json::json!({ "tool_input": { "file_path": "src/x.rs" } }).to_string(),
    );
    assert!(ok, "post-tool records the obligation");

    // 2. A commit while the obligation is open is DENIED — and recorded.
    let (ok, stderr) = run_with_stdin(&pre_commit, &bash_call("git commit -m wip"));
    assert!(!ok, "outstanding obligation blocks the commit: {stderr}");
    let evs = events(&ledger);
    let denial = evs
        .iter()
        .find(|e| e["transition"] == "gate.pre_commit" && e["decision"] == "denied")
        .expect("the denial is evidence, not just an exit code");
    assert_eq!(denial["playbook_ref"], PLAYBOOK, "run-bound");
    assert!(
        denial["kernel_ref"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"),
        "the enforcement binary names itself"
    );
    assert!(
        denial["input_refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "obligation:require-validation"),
        "the denial names what stood in the way"
    );

    // 3. Validation discharges; the same commit is now ALLOWED — and recorded.
    let (ok, _) = run_with_stdin(
        &[
            "validate",
            "--ledger",
            ledger_s,
            "--run-id",
            "run-1",
            "--playbook-ref",
            PLAYBOOK,
        ],
        "",
    );
    assert!(ok, "validate discharges");
    let (ok, stderr) = run_with_stdin(&pre_commit, &bash_call("git commit -m done"));
    assert!(ok, "discharged obligation admits the commit: {stderr}");
    let evs = events(&ledger);
    let approval = evs
        .iter()
        .find(|e| e["transition"] == "gate.pre_commit" && e["decision"] == "allowed")
        .expect("the allow is recorded too");
    assert_eq!(approval["playbook_ref"], PLAYBOOK);

    // Every event this kernel wrote carries both identities explicitly.
    for e in &evs {
        assert!(e.get("playbook_ref").is_some(), "mandatory field: {e}");
        assert!(e.get("kernel_ref").is_some(), "mandatory field: {e}");
    }
}

#[test]
fn a_non_commit_command_is_neither_gated_nor_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");

    // No gate decision is made for `ls`, so no gate event may be fabricated.
    let (ok, _) = run_with_stdin(
        &[
            "pre-commit",
            "--ledger",
            ledger.to_str().unwrap(),
            "--run-id",
            "run-1",
            "--require",
            "require-validation",
            "--playbook-ref",
            PLAYBOOK,
        ],
        &bash_call("ls -la"),
    );
    assert!(ok, "non-commit passes through");
    assert!(
        events(&ledger)
            .iter()
            .all(|e| e["transition"] != "gate.pre_commit"),
        "pass-through leaves no gate decision"
    );
}
