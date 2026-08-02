//! Identity binding under the live hook protocol, as the first self-hosting
//! trial demanded: the run identity comes from the payload's `session_id`
//! when the CLI value is a fallback, platform-absolute paths rebind to
//! workspace-relative form before policy runs, every denial carries a stable
//! `policy:` code, and the commit gate fails closed on a run identity that
//! cannot attribute debt.

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

fn events(ledger: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(ledger)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// A workspace with an active packet scoping `docs/` for writing.
fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("docs")).unwrap();
    std::fs::write(
        dir.path().join("packet.json"),
        serde_json::json!({
            "title": "docs work",
            "objective": "write documentation under docs/",
            "files": [{ "path": "docs/", "access": "write" }],
            "acceptance_criteria": ["docs updated"],
            "submitted_by": "test",
        })
        .to_string(),
    )
    .unwrap();
    dir
}

fn pre_tool_args<'a>(run_id: &'a str) -> Vec<&'a str> {
    vec![
        "pre-tool",
        "--packet",
        "packet.json",
        "--ledger",
        "events.jsonl",
        "--run-id",
        run_id,
        "--playbook-ref",
        "sha256:pb",
    ]
}

#[test]
fn payload_session_id_binds_the_run_when_the_cli_value_is_a_fallback() {
    let ws = workspace();
    // The environment exported nothing, so the hook fell back to unbound-$PPID
    // — but the payload knows the session. The payload wins.
    let (code, _, err) = kernel_in(
        ws.path(),
        &pre_tool_args("unbound-4711"),
        &serde_json::json!({
            "session_id": "sess-9",
            "tool_input": { "file_path": "docs/a.md" }
        })
        .to_string(),
    );
    assert_eq!(code, 0, "{err}");
    let evs = events(&ws.path().join("events.jsonl"));
    assert_eq!(evs[0]["run_id"], "sess-9");

    // A REAL cli identity (CLAUDE_SESSION_ID reached the hook) is not
    // overridden by the payload.
    let (code, _, err) = kernel_in(
        ws.path(),
        &pre_tool_args("real-run"),
        &serde_json::json!({
            "session_id": "sess-9",
            "tool_input": { "file_path": "docs/b.md" }
        })
        .to_string(),
    );
    assert_eq!(code, 0, "{err}");
    let evs = events(&ws.path().join("events.jsonl"));
    assert_eq!(evs[1]["run_id"], "real-run");
}

#[test]
fn an_absolute_path_inside_the_workspace_rebinds_and_is_judged_in_scope() {
    // THE self-trial defect: the platform hands the Guard absolute paths, and
    // denying them wholesale blocks every legitimate edit. Inside the
    // workspace the path rebinds; the evidence names both spellings.
    let ws = workspace();
    let abs = ws.path().join("docs/new.md");
    let (code, _, err) = kernel_in(
        ws.path(),
        &pre_tool_args("run-1"),
        &serde_json::json!({ "tool_input": { "file_path": abs.to_str().unwrap() } }).to_string(),
    );
    assert_eq!(code, 0, "{err}");
    let ev = &events(&ws.path().join("events.jsonl"))[0];
    assert_eq!(ev["decision"], "allowed");
    assert_eq!(ev["task_id"].as_str().unwrap().len(), 12, "admitted identity");
    assert_eq!(ev["action_id"], "pre_tool:docs/new.md");
    assert!(ev["attempt_id"].as_str().is_some());
    assert!(!ev["runtime_ref"].as_str().unwrap().is_empty());
    let refs: Vec<&str> = ev["input_refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(refs[0].starts_with("path:/"), "supplied spelling: {refs:?}");
    assert!(
        refs.contains(&"canonical:docs/new.md"),
        "canonical target: {refs:?}"
    );

    // An absolute path OUTSIDE the workspace is refused with its own code.
    let outside = tempfile::tempdir().unwrap();
    let foreign = outside.path().join("x.md");
    let (code, _, err) = kernel_in(
        ws.path(),
        &pre_tool_args("run-1"),
        &serde_json::json!({ "tool_input": { "file_path": foreign.to_str().unwrap() } })
            .to_string(),
    );
    assert_eq!(code, 2, "{err}");
    let evs = events(&ws.path().join("events.jsonl"));
    let refs: Vec<&str> = evs[1]["evidence_refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(refs.contains(&"policy:path.outside_workspace"), "{refs:?}");
}

#[test]
fn every_denial_carries_a_stable_policy_code() {
    let ws = workspace();
    // Out of scope.
    let (code, _, _) = kernel_in(
        ws.path(),
        &pre_tool_args("run-1"),
        &serde_json::json!({ "tool_input": { "file_path": "src/lib.rs" } }).to_string(),
    );
    assert_eq!(code, 2);
    // No active packet.
    let mut args = pre_tool_args("run-1");
    args[2] = "missing-packet.json";
    let (code, _, _) = kernel_in(
        ws.path(),
        &args,
        &serde_json::json!({ "tool_input": { "file_path": "docs/a.md" } }).to_string(),
    );
    assert_eq!(code, 2);

    let evs = events(&ws.path().join("events.jsonl"));
    let all_refs: Vec<String> = evs
        .iter()
        .flat_map(|e| e["evidence_refs"].as_array().unwrap().clone())
        .map(|r| r.as_str().unwrap().to_string())
        .collect();
    assert!(all_refs.contains(&"policy:file_scope.outside".to_string()));
    assert!(all_refs.contains(&"policy:intake.no_active_packet".to_string()));
    // Every denial also explains itself in prose.
    for ev in &evs {
        assert!(ev["evidence_refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str().unwrap().starts_with("reason:")));
    }
}

#[test]
fn the_commit_gate_fails_closed_on_an_unbound_run() {
    let ws = workspace();
    let commit = |run: &str, payload: serde_json::Value| {
        kernel_in(
            ws.path(),
            &[
                "pre-commit",
                "--ledger",
                "events.jsonl",
                "--run-id",
                run,
                "--require",
                "require-validation",
                "--playbook-ref",
                "sha256:pb",
            ],
            &payload.to_string(),
        )
    };
    let git = serde_json::json!({ "tool_input": { "command": "git commit -m x" } });

    // The legacy shared bucket and the per-invocation fallback both refuse:
    // debt that cannot be attributed cannot be evaluated.
    let (code, _, err) = commit("unknown", git.clone());
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("run identity"), "{err}");
    let (code, _, _) = commit("unbound-77", git.clone());
    assert_eq!(code, 2);
    let evs = events(&ws.path().join("events.jsonl"));
    assert!(evs.iter().all(|e| e["decision"] == "denied"));
    assert!(evs.iter().all(|e| e["evidence_refs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r.as_str().unwrap() == "policy:identity.run_unbound")));

    // A payload-bound session identity evaluates normally (no debt → allowed).
    let mut bound = git.clone();
    bound["session_id"] = serde_json::json!("sess-9");
    let (code, _, err) = commit("unbound-77", bound);
    assert_eq!(code, 0, "{err}");
    let evs = events(&ws.path().join("events.jsonl"));
    let last = evs.last().unwrap();
    assert_eq!(last["decision"], "allowed");
    assert_eq!(last["run_id"], "sess-9");
}
