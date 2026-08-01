//! Declared obligation scopes end-to-end: debt opened at a scope is evaluated
//! at that scope by the compiled kernel — across runs for `workspace`, per
//! edited path for `action`.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn kernel_with_stdin(args: &[&str], stdin_json: &str) -> (bool, String) {
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
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn edit_json(path: &str) -> String {
    serde_json::json!({ "tool_input": { "file_path": path } }).to_string()
}

fn commit_json() -> String {
    serde_json::json!({ "tool_input": { "command": "git commit -m x" } }).to_string()
}

#[test]
fn workspace_scope_blocks_and_clears_across_runs() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let ledger_s = ledger.to_str().unwrap();

    // Run A edits under a workspace-scoped obligation.
    let (ok, err) = kernel_with_stdin(
        &[
            "post-tool",
            "--ledger",
            ledger_s,
            "--run-id",
            "run-A",
            "--scope",
            "workspace",
        ],
        &edit_json("src/a.rs"),
    );
    assert!(ok, "{err}");

    // Run B — a different run entirely — is blocked by run A's debt: the
    // scope is the workspace, not the run.
    let pre_commit_b = [
        "pre-commit",
        "--ledger",
        ledger_s,
        "--run-id",
        "run-B",
        "--require",
        "require-validation:workspace",
    ];
    let (ok, stderr) = kernel_with_stdin(&pre_commit_b, &commit_json());
    assert!(!ok, "another run's workspace debt blocks the commit");
    assert!(stderr.contains("require-validation"), "{stderr}");

    // Run B validates — and that clears the workspace for everyone.
    let (ok, err) = kernel_with_stdin(
        &[
            "validate",
            "--ledger",
            ledger_s,
            "--run-id",
            "run-B",
            "--scope",
            "workspace",
        ],
        "",
    );
    assert!(ok, "{err}");
    let (ok, stderr) = kernel_with_stdin(&pre_commit_b, &commit_json());
    assert!(
        ok,
        "workspace debt discharged in any run clears it: {stderr}"
    );
}

#[test]
fn action_scope_owes_validation_per_edited_path() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let ledger_s = ledger.to_str().unwrap();

    for path in ["src/a.rs", "src/b.rs"] {
        let (ok, err) = kernel_with_stdin(
            &[
                "post-tool",
                "--ledger",
                ledger_s,
                "--run-id",
                "r",
                "--scope",
                "action",
            ],
            &edit_json(path),
        );
        assert!(ok, "{err}");
    }

    let pre_commit = [
        "pre-commit",
        "--ledger",
        ledger_s,
        "--run-id",
        "r",
        "--require",
        "require-validation:action",
    ];
    // One path validated is not enough: every edited path owes its own.
    let (ok, err) = kernel_with_stdin(
        &[
            "validate", "--ledger", ledger_s, "--run-id", "r", "--scope", "action", "--path",
            "src/a.rs",
        ],
        "",
    );
    assert!(ok, "{err}");
    let (ok, _) = kernel_with_stdin(&pre_commit, &commit_json());
    assert!(!ok, "src/b.rs is still owed");

    let (ok, err) = kernel_with_stdin(
        &[
            "validate", "--ledger", ledger_s, "--run-id", "r", "--scope", "action", "--path",
            "src/b.rs",
        ],
        "",
    );
    assert!(ok, "{err}");
    let (ok, stderr) = kernel_with_stdin(&pre_commit, &commit_json());
    assert!(ok, "all edited paths validated: {stderr}");

    // And an action-scoped discharge without a path is refused outright.
    let (ok, stderr) =
        kernel_with_stdin(&["validate", "--ledger", ledger_s, "--scope", "action"], "");
    assert!(!ok);
    assert!(stderr.contains("--path"), "{stderr}");
}
