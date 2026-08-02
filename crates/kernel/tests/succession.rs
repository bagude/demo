//! The constitutional succession protocol end-to-end, on a fixture workspace:
//! disarm under the old runtime → gate-bound manifest → signature approval →
//! refused tampered activation → activation that attests the handover — and a
//! ledger whose runtime boundary the verifier accepts as governed.

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

fn line_value(stdout: &str, key: &str) -> String {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .unwrap_or_else(|| panic!("'{key}' not printed in:\n{stdout}"))
        .trim()
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

#[test]
fn a_governed_succession_cycle_leaves_an_attested_runtime_boundary() {
    let ws = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(ws.path().join("docs")).unwrap();
    std::fs::write(
        ws.path().join("packet.json"),
        serde_json::json!({
            "title": "repair the guard",
            "objective": "replace the defective kernel under governance",
            "files": [{ "path": "docs/", "access": "write" }],
            "acceptance_criteria": ["conformance passes"],
            "submitted_by": "maintainer",
            "amends_enforcement": true,
        })
        .to_string(),
    )
    .unwrap();

    // History under the OLD constitution.
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "pre-tool",
            "--packet",
            "packet.json",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "run-old",
            "--playbook-ref",
            "sha256:pb-old",
        ],
        &serde_json::json!({ "tool_input": { "file_path": "docs/work.md" } }).to_string(),
    );
    assert_eq!(code, 0, "{err}");

    // DISARM, under the old runtime — a packet without the grant is refused
    // (proven elsewhere by the intake); here the granted one records the
    // start of the ungoverned window and prints the facts a manifest binds.
    let (code, stdout, err) = kernel_in(
        ws.path(),
        &[
            "succession",
            "disarm",
            "--ledger",
            "events.jsonl",
            "--run-id",
            "run-old",
            "--packet",
            "packet.json",
            "--reason",
            "absolute-path binding defect blocks all platform edits",
            "--playbook-ref",
            "sha256:pb-old",
        ],
        "",
    );
    assert_eq!(code, 0, "{err}");
    let task_id = line_value(&stdout, "disarmed under task");
    let old_runtime = line_value(&stdout, "old_runtime_ref:");
    let old_head = line_value(&stdout, "old_ledger_head:");

    // The MANIFEST: authored from recorded fact. The successor here is the
    // same binary governed by a new playbook — a real constitutional change,
    // since runtime_ref binds both.
    let new_runtime = kernel::runtime_ref("sha256:pb-new");
    assert_ne!(old_runtime, new_runtime);
    let manifest = ws.path().join("succession.json");
    let manifest_json = serde_json::json!({
        "old_runtime_ref": old_runtime,
        "old_ledger_head": old_head,
        "maintenance_task_id": task_id,
        "reason": "absolute-path binding defect blocks all platform edits",
        "patch_ref": "sha256:patch-digest",
        "conformance_ref": "sha256:conformance-suite-and-outcome",
        "new_kernel_ref": kernel::kernel_ref(),
        "new_runtime_ref": new_runtime,
    });
    std::fs::write(&manifest, serde_json::to_string_pretty(&manifest_json).unwrap()).unwrap();

    // GATE: the halt binds the manifest bytes and anchors the chain head.
    let (code, stdout, err) = kernel_in(
        ws.path(),
        &[
            "gate",
            "request",
            "--gate",
            "succession",
            "--run-id",
            "run-old",
            "--action-file",
            "succession.json",
            "--summary",
            "seat the repaired kernel",
            "--checkpoints",
            "cp",
            "--ledger",
            "events.jsonl",
            "--playbook-ref",
            "sha256:pb-old",
        ],
        "",
    );
    assert_eq!(code, 0, "{err}");
    let cp_path = stdout.trim().to_string();

    // An UNPROVEN approval does not seat a governor.
    let (code, _, err) = kernel_in(
        ws.path(),
        &["gate", "approve", "--checkpoint", &cp_path, "--approver", "mallory"],
        "",
    );
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "succession",
            "activate",
            "--manifest",
            "succession.json",
            "--checkpoint",
            &cp_path,
            "--ledger",
            "events.jsonl",
            "--run-id",
            "run-new",
            "--playbook-ref",
            "sha256:pb-new",
        ],
        "",
    );
    assert_ne!(code, 0);
    assert!(err.contains("succession.approval_unproven"), "{err}");

    // A SIGNATURE approval by a registered principal.
    let (code, alice_public, err) =
        kernel_in(ws.path(), &["key", "generate", "--out", "alice.seed"], "");
    assert_eq!(code, 0, "{err}");
    std::fs::write(
        ws.path().join("approvers.toml"),
        format!("[approvers]\nalice = \"{}\"\n", alice_public.trim()),
    )
    .unwrap();
    let (code, signature, err) = kernel_in(
        ws.path(),
        &["gate", "sign", "--checkpoint", &cp_path, "--key", "alice.seed"],
        "",
    );
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = kernel_in(
        ws.path(),
        &[
            "gate",
            "approve",
            "--checkpoint",
            &cp_path,
            "--approver",
            "alice",
            "--auth",
            "signature",
            "--signature",
            signature.trim(),
            "--trusted-keys",
            "approvers.toml",
        ],
        "",
    );
    assert_eq!(code, 0, "{err}");

    // A POST-APPROVAL EDIT of the manifest is the same refusal as a
    // substituted deploy artifact — and the refusal is recorded.
    let approved_bytes = std::fs::read(&manifest).unwrap();
    let mut tampered = manifest_json.clone();
    tampered["patch_ref"] = serde_json::json!("sha256:a-different-patch");
    std::fs::write(&manifest, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();
    let activate = |run: &str| {
        kernel_in(
            ws.path(),
            &[
                "succession",
                "activate",
                "--manifest",
                "succession.json",
                "--checkpoint",
                &cp_path,
                "--ledger",
                "events.jsonl",
                "--run-id",
                run,
                "--playbook-ref",
                "sha256:pb-new",
                "--trusted-keys",
                "approvers.toml",
            ],
            "",
        )
    };
    let (code, _, err) = activate("run-new");
    assert_ne!(code, 0);
    assert!(err.contains("succession.manifest_mismatch"), "{err}");

    // The approved bytes, restored, ACTIVATE — the successor's event attests
    // exactly which runtime and which history it succeeded.
    std::fs::write(&manifest, approved_bytes).unwrap();
    let (code, stdout, err) = activate("run-new");
    assert_eq!(code, 0, "{err}");
    assert!(stdout.contains("succession activated"), "{stdout}");

    let evs = events(&ws.path().join("events.jsonl"));
    let activated = evs
        .iter()
        .find(|e| e["transition"] == "succession.activate" && e["decision"] == "approved")
        .expect("the activation is evidence");
    assert_eq!(activated["runtime_ref"], serde_json::json!(new_runtime));
    assert_eq!(activated["task_id"], serde_json::json!(task_id));
    let refs: Vec<&str> = activated["input_refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(refs.contains(&format!("old_runtime:{old_runtime}").as_str()));
    assert!(refs.contains(&format!("old_head:{old_head}").as_str()));

    // The VERIFIER accepts the boundary as governed: segments appear, and no
    // unattested-succession warning fires despite the recorded refusals.
    let (code, stdout, err) = kernel_in(
        ws.path(),
        &["ledger", "verify", "--ledger", "events.jsonl"],
        "",
    );
    assert_eq!(code, 0, "{err}");
    assert!(stdout.contains("runtime segments: 2"), "{stdout}");
    assert!(
        !stdout.contains("unattested succession"),
        "the handover is attested: {stdout}"
    );

    // And the counterfactual: the self-trial's shape — the successor's
    // runtime just starts writing ordinary events, no activation record.
    // Rebuild that history as its own well-formed ledger and the same
    // verifier gets loud.
    let text = std::fs::read_to_string(ws.path().join("events.jsonl")).unwrap();
    let rebuilt = ws.path().join("rebuilt.jsonl");
    for line in text.lines().filter(|l| !l.contains("succession.activate")) {
        let ev: kernel::Event = serde_json::from_str(line).unwrap();
        kernel::EventLog::at(&rebuilt).append(&ev).unwrap();
    }
    let mut silent_successor: kernel::Event =
        serde_json::from_str(text.lines().next().unwrap()).unwrap();
    silent_successor.runtime_ref = new_runtime.clone();
    kernel::EventLog::at(&rebuilt).append(&silent_successor).unwrap();
    let (code, stdout, err) = kernel_in(
        ws.path(),
        &["ledger", "verify", "--ledger", "rebuilt.jsonl"],
        "",
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        stdout.contains("unattested succession"),
        "a silent handover must be loud: {stdout}"
    );
}
