//! Candidate mode, boundary rejection, bootstrap handling, and adversarial
//! succession — the runtime-facing half of the boundary-repair matrix. (The
//! verifier's pure judgments are unit-tested in `succession.rs`; the full
//! normal cycle lives in `tests/succession.rs`.)

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use kernel::event::{Decision, Event, EventLog};

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

fn intake_in(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_intake"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("intake runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn ev(runtime: &str, transition: &str, decision: Decision, input_refs: Vec<String>) -> Event {
    Event {
        run_id: "r".into(),
        task_id: None,
        parent_task_id: None,
        action_id: "a".into(),
        actor: "kernel".into(),
        timestamp: "2026-08-02T00:00:00Z".into(),
        transition: transition.into(),
        stage: "recorded".into(),
        input_refs,
        output_refs: vec![],
        decision,
        evidence_refs: vec![],
        playbook_ref: String::new(),
        kernel_ref: String::new(),
        runtime_ref: runtime.into(),
        attempt_id: None,
    }
}

fn record_count(ledger: &Path) -> usize {
    std::fs::read_to_string(ledger)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count()
}

fn packet_json() -> String {
    serde_json::json!({
        "title": "candidate probe",
        "objective": "attempt ordinary governance from candidate mode",
        "files": [{ "path": "docs/", "access": "write" }],
        "acceptance_criteria": ["never reached"],
        "submitted_by": "probe",
        "amends_enforcement": true,
    })
    .to_string()
}

/// A workspace whose ledger has a founded regime: the active runtime is the
/// one this binary computes for `sha256:pb-active`, so invocations under
/// `sha256:pb-cand` are candidates.
fn regime_workspace() -> tempfile::TempDir {
    let ws = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(ws.path().join("docs")).unwrap();
    std::fs::write(ws.path().join("packet.json"), packet_json()).unwrap();
    let active = kernel::runtime_ref("sha256:pb-active");
    EventLog::at(ws.path().join("events.jsonl"))
        .append(&ev(
            &active,
            "succession.activate",
            Decision::Approved,
            vec!["old_runtime:sha256:genesis".into()],
        ))
        .unwrap();
    ws
}

#[test]
fn candidate_mode_mechanically_refuses_ordinary_governance() {
    let ws = regime_workspace();
    let ledger = ws.path().join("events.jsonl");
    let before = record_count(&ledger);

    // 7. A file edit is refused — and NOT recorded: any kind the refusal
    // could carry is ordinary governance a candidate must not write.
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "pre-tool",
            "--packet",
            "packet.json",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "r",
            "--playbook-ref",
            "sha256:pb-cand",
        ],
        &serde_json::json!({ "tool_input": { "file_path": "docs/x.md" } }).to_string(),
    );
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("succession-runtime-not-active"), "{err}");
    assert!(err.contains("active runtime"), "{err}");
    assert_eq!(record_count(&ledger), before, "refusals are not recorded");

    // 8. A validation discharge is refused.
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "validate",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "r",
            "--playbook-ref",
            "sha256:pb-cand",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("succession-runtime-not-active"), "{err}");

    // 9. The commit gate is refused.
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "pre-commit",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "r",
            "--require",
            "require-validation",
            "--playbook-ref",
            "sha256:pb-cand",
        ],
        &serde_json::json!({ "tool_input": { "command": "git commit -m x" } }).to_string(),
    );
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("succession-runtime-not-active"), "{err}");

    // Obligation recording is refused.
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "post-tool",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "r",
            "--playbook-ref",
            "sha256:pb-cand",
        ],
        &serde_json::json!({ "tool_input": { "file_path": "docs/x.md" } }).to_string(),
    );
    assert_eq!(code, 2, "{err}");

    // A hive spawn is refused.
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "hive-spawn",
            "--max-depth",
            "2",
            "--budget-remaining",
            "10",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "r",
            "--playbook-ref",
            "sha256:pb-cand",
        ],
        &serde_json::json!({
            "parent": "root",
            "contract": "schema.json",
            "budget": 1,
            "depth": 1,
            "termination": "done",
            "merge": "parent",
        })
        .to_string(),
    );
    assert_eq!(code, 2, "{err}");

    // A disarm from a candidate is refused: it does not hold the runtime.
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "succession",
            "disarm",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "r",
            "--packet",
            "packet.json",
            "--reason",
            "x",
            "--playbook-ref",
            "sha256:pb-cand",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("succession-runtime-not-active"), "{err}");

    // Gate commands may not write ledger events from candidate mode…
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "gate",
            "request",
            "--gate",
            "succession",
            "--action-hash",
            "sha256:x",
            "--checkpoints",
            "cp",
            "--ledger",
            "events.jsonl",
            "--playbook-ref",
            "sha256:pb-cand",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("succession-runtime-not-active"), "{err}");
    // …but the checkpoint machinery itself stays available to the ceremony.
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "gate",
            "request",
            "--gate",
            "succession",
            "--action-hash",
            "sha256:x",
            "--checkpoints",
            "cp",
        ],
        "",
    );
    assert_eq!(code, 0, "{err}");

    // 10. Task admission is refused when the intake can see the regime.
    let (code, _, err) = intake_in(
        ws.path(),
        &[
            "--ledger",
            "tasks.jsonl",
            "--events-ledger",
            "events.jsonl",
            "--playbook-ref",
            "sha256:pb-cand",
            "submit",
            "packet.json",
        ],
    );
    assert_ne!(code, 0);
    assert!(err.contains("succession-runtime-not-active"), "{err}");

    // 12 (analog): the ACTIVE runtime still governs normally.
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "pre-tool",
            "--packet",
            "packet.json",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "r",
            "--playbook-ref",
            "sha256:pb-active",
        ],
        &serde_json::json!({ "tool_input": { "file_path": "docs/x.md" } }).to_string(),
    );
    assert_eq!(code, 0, "{err}");
}

#[test]
fn candidate_safe_kinds_are_permitted_and_the_allowlist_is_closed() {
    let ws = regime_workspace();

    // 6. Every allowlisted kind may be appended by a candidate.
    for kind in kernel::CANDIDATE_SAFE {
        if *kind == "succession.activate" {
            continue; // exercised by the activation flow itself
        }
        let (code, _, err) = kernel_in(
            ws.path(),
            &[
                "event",
                "--ledger",
                "events.jsonl",
                "--run-id",
                "r",
                "--transition",
                kind,
                "--decision",
                "recorded",
                "--playbook-ref",
                "sha256:pb-cand",
            ],
            "",
        );
        assert_eq!(code, 0, "candidate-safe kind '{kind}' refused: {err}");
    }

    // 11. An unknown succession.* kind is NOT candidate-safe: the allowlist
    // is membership, not a naming convention.
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "event",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "r",
            "--transition",
            "succession.exfiltrate",
            "--decision",
            "recorded",
            "--playbook-ref",
            "sha256:pb-cand",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("succession-candidate-event-not-allowed"), "{err}");

    // 13. An abort is recorded — and ordinary governance stays refused.
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "succession",
            "abort",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "r",
            "--reason",
            "ceremony abandoned",
            "--playbook-ref",
            "sha256:pb-cand",
        ],
        "",
    );
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "pre-tool",
            "--packet",
            "packet.json",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "r",
            "--playbook-ref",
            "sha256:pb-cand",
        ],
        &serde_json::json!({ "tool_input": { "file_path": "docs/x.md" } }).to_string(),
    );
    assert_eq!(code, 2, "an abort never opens governance: {err}");
}

/// Author a manifest file and a checkpoint approving it, returning the
/// checkpoint path. Approval is claimed; activation callers pass
/// --allow-unproven so the checks under test are reached.
fn manifest_and_checkpoint(ws: &Path, manifest: &serde_json::Value) -> String {
    std::fs::write(
        ws.join("m.json"),
        serde_json::to_string_pretty(manifest).unwrap(),
    )
    .unwrap();
    let (code, stdout, err) = kernel_in(
        ws,
        &[
            "gate", "request", "--gate", "succession", "--action-file", "m.json",
            "--checkpoints", "cp",
        ],
        "",
    );
    assert_eq!(code, 0, "{err}");
    let cp = stdout.trim().to_string();
    let (code, _, err) = kernel_in(
        ws,
        &["gate", "approve", "--checkpoint", &cp, "--approver", "op"],
        "",
    );
    assert_eq!(code, 0, "{err}");
    cp
}

fn base_manifest(old_runtime: &str, old_head: &str, new_playbook: &str) -> serde_json::Value {
    serde_json::json!({
        "transition_mode": "normal",
        "old_runtime_ref": old_runtime,
        "old_ledger_head": old_head,
        "maintenance_task_id": "maint-1",
        "ceremony_task_id": "cer-1",
        "reason": "test",
        "patch_ref": "sha256:p",
        "conformance_ref": "sha256:c",
        "new_kernel_ref": kernel::kernel_ref(),
        "new_runtime_ref": kernel::runtime_ref(new_playbook),
    })
}

fn activate(ws: &Path, cp: &str, playbook: &str) -> (i32, String, String) {
    kernel_in(
        ws,
        &[
            "succession", "activate", "--manifest", "m.json", "--checkpoint", cp,
            "--ledger", "events.jsonl", "--run-id", "r", "--playbook-ref", playbook,
            "--allow-unproven",
        ],
        "",
    )
}

/// A ledger governed by `sha256:pb-old` with a disarm as its final record;
/// returns (old_runtime, head-after-disarm).
fn disarmed_ledger(ws: &Path) -> (String, String) {
    std::fs::create_dir_all(ws.join("docs")).unwrap();
    std::fs::write(ws.join("packet.json"), packet_json()).unwrap();
    let (code, _, err) = kernel_in(
        ws,
        &[
            "pre-tool", "--packet", "packet.json", "--ledger", "events.jsonl",
            "--run-id", "r", "--playbook-ref", "sha256:pb-old",
        ],
        &serde_json::json!({ "tool_input": { "file_path": "docs/w.md" } }).to_string(),
    );
    assert_eq!(code, 0, "{err}");
    let (code, stdout, err) = kernel_in(
        ws,
        &[
            "succession", "disarm", "--ledger", "events.jsonl", "--run-id", "r",
            "--packet", "packet.json", "--reason", "test", "--playbook-ref", "sha256:pb-old",
        ],
        "",
    );
    assert_eq!(code, 0, "{err}");
    let get = |k: &str| {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .unwrap()
            .trim()
            .to_string()
    };
    (get("old_runtime_ref:"), get("old_ledger_head:"))
}

#[test]
fn activation_rejects_a_head_that_is_not_the_predecessors_final_record() {
    // 22 (approval names the wrong head) / 3 / 4: sign off on a mid-history
    // head; activation must refuse even though the approval itself is valid.
    let ws = tempfile::tempdir().unwrap();
    let (old_runtime, _head) = disarmed_ledger(ws.path());
    // The FIRST record's digest — a real record, but not the final one.
    let lines = EventLog::at(ws.path().join("events.jsonl")).read_lines().unwrap();
    let early_head = lines[0].digest.clone();
    let m = base_manifest(&old_runtime, &early_head, "sha256:pb-new");
    let cp = manifest_and_checkpoint(ws.path(), &m);
    let (code, _, err) = activate(ws.path(), &cp, "sha256:pb-new");
    assert_ne!(code, 0);
    assert!(err.contains("succession-boundary-head-mismatch"), "{err}");
    // The refusal IS recorded (a rejected activation is candidate-safe).
    let evs = std::fs::read_to_string(ws.path().join("events.jsonl")).unwrap();
    assert!(evs.contains("succession-boundary-head-mismatch"), "{evs}");
}

#[test]
fn activation_rejects_bootstrap_mode_absent_mode_and_missing_disarm_claims() {
    let ws = tempfile::tempdir().unwrap();
    let (old_runtime, head) = disarmed_ledger(ws.path());

    // 17. transition_mode: bootstrap is never activatable.
    let mut m = base_manifest(&old_runtime, &head, "sha256:pb-new");
    m["transition_mode"] = serde_json::json!("bootstrap");
    let cp = manifest_and_checkpoint(ws.path(), &m);
    let (code, _, err) = activate(ws.path(), &cp, "sha256:pb-new");
    assert_ne!(code, 0);
    assert!(err.contains("succession-bootstrap-not-authorized"), "{err}");

    // 18 (runtime side). An absent transition_mode is refused.
    let mut m = base_manifest(&old_runtime, &head, "sha256:pb-new");
    m.as_object_mut().unwrap().remove("transition_mode");
    let cp = manifest_and_checkpoint(ws.path(), &m);
    let (code, _, err) = activate(ws.path(), &cp, "sha256:pb-new");
    assert_ne!(code, 0);
    assert!(err.contains("succession-activation-invalid"), "{err}");

    // A normal transition may not claim disarm_recorded: false.
    let mut m = base_manifest(&old_runtime, &head, "sha256:pb-new");
    m["disarm_recorded"] = serde_json::json!(false);
    let cp = manifest_and_checkpoint(ws.path(), &m);
    let (code, _, err) = activate(ws.path(), &cp, "sha256:pb-new");
    assert_ne!(code, 0);
    assert!(err.contains("succession-activation-invalid"), "{err}");

    // A normal transition must bind the ceremony identity.
    let mut m = base_manifest(&old_runtime, &head, "sha256:pb-new");
    m["ceremony_task_id"] = serde_json::json!("");
    let cp = manifest_and_checkpoint(ws.path(), &m);
    let (code, _, err) = activate(ws.path(), &cp, "sha256:pb-new");
    assert_ne!(code, 0);
    assert!(err.contains("succession-activation-invalid"), "{err}");
}

#[test]
fn forged_histories_fail_verification() {
    // 20. A candidate that governed before activating — with a TRUE head and
    // a valid-looking approval — still fails verification.
    let ws = tempfile::tempdir().unwrap();
    let ledger = ws.path().join("forged.jsonl");
    let log = EventLog::at(&ledger);
    log.append(&ev("rt-old", "succession.disarm", Decision::Recorded, vec![]))
        .unwrap();
    let head = log.verify_chain().unwrap().head.unwrap();
    log.append(&ev("rt-new", "pre_tool.edit", Decision::Allowed, vec![]))
        .unwrap();
    log.append(&ev(
        "rt-new",
        "succession.activate",
        Decision::Approved,
        vec![
            "old_runtime:rt-old".into(),
            format!("old_head:{head}"),
            "manifest:sha256:m".into(),
            "mode:normal".into(),
        ],
    ))
    .unwrap();
    let (code, _, err) = kernel_in(
        ws.path(),
        &["ledger", "verify", "--ledger", "forged.jsonl"],
        "",
    );
    assert_ne!(code, 0);
    assert!(
        err.contains("succession-candidate-governance-before-activation"),
        "{err}"
    );

    // 21. Governance whose activation names a head INSIDE the candidate's
    // own records fails.
    let ledger = ws.path().join("forged2.jsonl");
    let log = EventLog::at(&ledger);
    log.append(&ev("rt-old", "succession.disarm", Decision::Recorded, vec![]))
        .unwrap();
    log.append(&ev("rt-new", "pre_tool.edit", Decision::Allowed, vec![]))
        .unwrap();
    let mid_head = log.verify_chain().unwrap().head.unwrap();
    log.append(&ev(
        "rt-new",
        "succession.activate",
        Decision::Approved,
        vec![
            "old_runtime:rt-old".into(),
            format!("old_head:{mid_head}"),
            "manifest:sha256:m".into(),
            "mode:normal".into(),
        ],
    ))
    .unwrap();
    let (code, _, err) = kernel_in(
        ws.path(),
        &["ledger", "verify", "--ledger", "forged2.jsonl"],
        "",
    );
    assert_ne!(code, 0);
    assert!(
        err.contains("succession-predecessor-runtime-mismatch"),
        "{err}"
    );

    // 24. A previously valid activation REPLAYED against a different ledger
    // fails: its bound head names history the new ledger does not have.
    let donor = ws.path().join("donor.jsonl");
    let log = EventLog::at(&donor);
    log.append(&ev("rt-old", "succession.disarm", Decision::Recorded, vec![]))
        .unwrap();
    let donor_head = log.verify_chain().unwrap().head.unwrap();
    let valid_activate = ev(
        "rt-new",
        "succession.activate",
        Decision::Approved,
        vec![
            "old_runtime:rt-old".into(),
            format!("old_head:{donor_head}"),
            "manifest:sha256:m".into(),
            "mode:normal".into(),
        ],
    );
    log.append(&valid_activate).unwrap();
    let (code, _, _) = kernel_in(ws.path(), &["ledger", "verify", "--ledger", "donor.jsonl"], "");
    assert_eq!(code, 0, "the donor history is valid");

    let replayed = ws.path().join("replayed.jsonl");
    let log = EventLog::at(&replayed);
    log.append(&ev("rt-old", "pre_tool.edit", Decision::Allowed, vec![]))
        .unwrap();
    log.append(&valid_activate).unwrap();
    let (code, _, err) = kernel_in(
        ws.path(),
        &["ledger", "verify", "--ledger", "replayed.jsonl"],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("succession-boundary-head-mismatch"), "{err}");
}

#[test]
fn the_founding_exception_is_exact_visible_and_single_use() {
    // A legacy activation (no mode) whose declared head sits inside the
    // candidate's own governance — succession-0001's exact shape.
    let ws = tempfile::tempdir().unwrap();
    let ledger = ws.path().join("legacy.jsonl");
    let log = EventLog::at(&ledger);
    log.append(&ev("rt-old", "pre_tool.edit", Decision::Allowed, vec![]))
        .unwrap();
    log.append(&ev(
        "rt-new",
        "obligation.discharge.require-validation",
        Decision::Recorded,
        vec![],
    ))
    .unwrap();
    let bound_head = log.verify_chain().unwrap().head.unwrap();
    log.append(&ev(
        "rt-new",
        "succession.activate",
        Decision::Approved,
        vec![
            "old_runtime:rt-old".into(),
            format!("old_head:{bound_head}"),
            "manifest:sha256:founding".into(),
        ],
    ))
    .unwrap();

    // 18. Without the allowlist: verification fails.
    let (code, _, err) = kernel_in(
        ws.path(),
        &["ledger", "verify", "--ledger", "legacy.jsonl"],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("succession-activation-invalid"), "{err}");

    // 14 + 15. With the exact entry: accepted as the exception, reported
    // with its anomaly retained, never described as normal.
    std::fs::write(
        ws.path().join("exceptions.json"),
        serde_json::json!([{
            "transition_id": "succession-0001",
            "manifest_digest": "sha256:founding",
            "exception": "legacy-founding-bootstrap",
        }])
        .to_string(),
    )
    .unwrap();
    let (code, stdout, err) = kernel_in(
        ws.path(),
        &[
            "ledger", "verify", "--ledger", "legacy.jsonl", "--exceptions", "exceptions.json",
        ],
        "",
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        stdout.contains("VALID_WITH_LEGACY_BOOTSTRAP_EXCEPTION"),
        "{stdout}"
    );
    assert!(
        stdout.contains("NOT the predecessor's final record"),
        "the anomaly is retained, not suppressed: {stdout}"
    );
    assert!(!stdout.contains("VALID (normal"), "{stdout}");

    // 16 + 19. A different digest under the same transition id matches
    // nothing: a modified founding manifest is rejected.
    std::fs::write(
        ws.path().join("exceptions.json"),
        serde_json::json!([{
            "transition_id": "succession-0001",
            "manifest_digest": "sha256:a-modified-copy",
            "exception": "legacy-founding-bootstrap",
        }])
        .to_string(),
    )
    .unwrap();
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "ledger", "verify", "--ledger", "legacy.jsonl", "--exceptions", "exceptions.json",
        ],
        "",
    );
    assert_ne!(code, 0, "{err}");
}
