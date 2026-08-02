//! The conformance fixture matrix: the invariants a candidate kernel must
//! uphold before `succession activate` will seat it as the governor.
//!
//! This file IS the versioned suite — its content digest names the matrix a
//! succession manifest's `conformance_ref` commits to (digest of this file
//! plus the run's outcome). Every case here restates, as executable fact, a
//! guarantee the harness claims in prose: default-deny scope authority,
//! self-protection with explicit amendment, platform-path rebinding,
//! fail-closed absence of authorization, the obligation-to-gate loop, and
//! tamper-evident history. A candidate that fails any row is not fit to
//! govern, whatever its author says.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn kernel_in(dir: &Path, args: &[&str], stdin_json: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kernel"))
        .args(args)
        .current_dir(dir)
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
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn edit_payload(path: &str) -> String {
    serde_json::json!({ "session_id": "conf-run", "tool_input": { "file_path": path } })
        .to_string()
}

fn events(ledger: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(ledger)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// A workspace with a packet scoping `docs/` (write) and, under an
/// enforcement grant variant, the protected `guard/` tree.
fn workspace(amends: bool) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("docs")).unwrap();
    std::fs::create_dir_all(dir.path().join("guard")).unwrap();
    std::fs::write(dir.path().join("protected.txt"), "guard/\n").unwrap();
    std::fs::write(
        dir.path().join("packet.json"),
        serde_json::json!({
            "title": "conformance fixture",
            "objective": "exercise the guarantees a governor must uphold",
            "files": [
                { "path": "docs/", "access": "write" },
                { "path": "guard/", "access": "write" },
            ],
            "acceptance_criteria": ["the matrix passes"],
            "submitted_by": "conformance",
            "amends_enforcement": amends,
        })
        .to_string(),
    )
    .unwrap();
    dir
}

fn pre_tool(ws: &Path, packet: &str, path: &str) -> (i32, String, String) {
    kernel_in(
        ws,
        &[
            "pre-tool",
            "--packet",
            packet,
            "--ledger",
            "events.jsonl",
            "--run-id",
            "conf-run",
            "--playbook-ref",
            "sha256:conf",
            "--protected",
            "protected.txt",
        ],
        &edit_payload(path),
    )
}

#[test]
fn matrix_scope_authority_is_default_deny() {
    let ws = workspace(false);
    let (code, _, _) = pre_tool(ws.path(), "packet.json", "docs/ok.md");
    assert_eq!(code, 0, "in-scope write is allowed");
    let (code, _, err) = pre_tool(ws.path(), "packet.json", "src/never-granted.rs");
    assert_eq!(code, 2, "unlisted path is denied: {err}");
    assert!(err.contains("file_scope.outside"));
}

#[test]
fn matrix_absence_of_authorization_fails_closed() {
    let ws = workspace(false);
    let (code, _, err) = pre_tool(ws.path(), "no-such-packet.json", "docs/ok.md");
    assert_eq!(code, 2, "no packet means NO authorization: {err}");
    assert!(err.contains("intake.no_active_packet"));
}

#[test]
fn matrix_platform_paths_rebind_and_the_workspace_is_the_boundary() {
    let ws = workspace(false);
    let inside = ws.path().join("docs/abs.md");
    let (code, _, err) = pre_tool(ws.path(), "packet.json", inside.to_str().unwrap());
    assert_eq!(code, 0, "absolute-inside rebinds to in-scope: {err}");
    let outside = tempfile::tempdir().unwrap();
    let foreign = outside.path().join("x.md");
    let (code, _, err) = pre_tool(ws.path(), "packet.json", foreign.to_str().unwrap());
    assert_eq!(code, 2, "absolute-outside is refused: {err}");
}

#[test]
fn matrix_enforcement_amendment_is_never_ambient() {
    // Same path, same scope — the only difference is the explicit grant.
    let ws = workspace(false);
    let (code, _, err) = pre_tool(ws.path(), "packet.json", "guard/hook.sh");
    assert_eq!(code, 2, "protected without grant: {err}");
    assert!(err.contains("enforcement.amendment_required"));

    let ws = workspace(true);
    let (code, _, err) = pre_tool(ws.path(), "packet.json", "guard/hook.sh");
    assert_eq!(code, 0, "protected WITH grant is a recorded amendment: {err}");
    let evs = events(&ws.path().join("events.jsonl"));
    assert_eq!(evs[0]["transition"], "pre_tool.enforcement_amendment");
}

#[test]
fn matrix_the_obligation_loop_holds_the_commit_gate() {
    let ws = workspace(false);
    // An edit opens the debt.
    let (code, _, _) = kernel_in(
        ws.path(),
        &[
            "post-tool",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "conf-run",
            "--playbook-ref",
            "sha256:conf",
        ],
        &edit_payload("docs/ok.md"),
    );
    assert_eq!(code, 0);
    let commit = serde_json::json!({
        "session_id": "conf-run",
        "tool_input": { "command": "git commit -m x" }
    })
    .to_string();
    let gate = |ws: &Path| {
        kernel_in(
            ws,
            &[
                "pre-commit",
                "--ledger",
                "events.jsonl",
                "--run-id",
                "conf-run",
                "--require",
                "require-validation",
                "--playbook-ref",
                "sha256:conf",
            ],
            &commit,
        )
    };
    let (code, _, err) = gate(ws.path());
    assert_eq!(code, 2, "open debt blocks the commit: {err}");
    // Discharge clears it — for this run only.
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "validate",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "conf-run",
            "--playbook-ref",
            "sha256:conf",
        ],
        "",
    );
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = gate(ws.path());
    assert_eq!(code, 0, "discharged debt releases the gate: {err}");
}

#[test]
fn matrix_history_is_tamper_evident() {
    let ws = workspace(false);
    let (code, _, _) = pre_tool(ws.path(), "packet.json", "docs/ok.md");
    assert_eq!(code, 0);
    let (code, _, _) = pre_tool(ws.path(), "packet.json", "docs/two.md");
    assert_eq!(code, 0);
    let ledger = ws.path().join("events.jsonl");
    let (code, out, _) = kernel_in(ws.path(), &["ledger", "verify", "--ledger", "events.jsonl"], "");
    assert_eq!(code, 0, "{out}");

    let text = std::fs::read_to_string(&ledger).unwrap();
    std::fs::write(&ledger, text.replacen("\"allowed\"", "\"denied\"", 1)).unwrap();
    let (code, _, err) = kernel_in(ws.path(), &["ledger", "verify", "--ledger", "events.jsonl"], "");
    assert_ne!(code, 0, "a mutated record must not verify: {err}");
}
