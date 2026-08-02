//! The mechanical twin of the self-governance trial (docs/SELF_TRIAL.md).
//!
//! This suite drives the **checked-in generated hook scripts** — not the
//! kernel directly — exactly the way the platform drives them: same shell,
//! same JSON payloads on stdin, same env contract (`KERNEL_BIN`,
//! `CLAUDE_SESSION_ID`), same exit-code protocol (0 = allow, 2 = block,
//! anything else = a warning the platform ignores). Where the live trial
//! proves the harness binds to a real agent once, this proves the
//! enforcement semantics of the exact artifacts in the tree, repeatably,
//! in CI. The freshness test already proves those artifacts match the spec;
//! together: spec → artifacts → behavior, all checked.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kernel::event::EventLog;
use kernel::packet::{FileScope, Priority, TaskPacket};

/// Repo root: the checked-in Playbook artifacts live here.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// A scratch workspace laid out the way the generated hooks expect:
/// `harness/` (hooks + protected list) copied from the tree, plus the
/// relative dirs the hooks reference from the workspace root.
struct Workspace {
    dir: tempfile::TempDir,
}

impl Workspace {
    fn new() -> Workspace {
        let dir = tempfile::tempdir().unwrap();
        let root = repo_root();
        let harness = dir.path().join("harness");
        std::fs::create_dir_all(harness.join("hooks")).unwrap();
        for entry in std::fs::read_dir(root.join("harness/hooks")).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), harness.join("hooks").join(entry.file_name())).unwrap();
        }
        std::fs::copy(
            root.join("harness/enforcement.protected"),
            harness.join("enforcement.protected"),
        )
        .unwrap();
        for sub in ["evidence", "tasks", "docs", "src"] {
            std::fs::create_dir_all(dir.path().join(sub)).unwrap();
        }
        std::fs::write(dir.path().join("src/app.py"), "def app(): pass\n").unwrap();
        Workspace { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Invoke a generated hook the way the platform does: bash, JSON on
    /// stdin, env contract, workspace cwd. Returns (exit_code, stderr).
    fn hook(&self, name: &str, payload: &str) -> (i32, String) {
        let mut child = Command::new("bash")
            .arg(self.path().join("harness/hooks").join(name))
            .current_dir(self.path())
            .env("KERNEL_BIN", env!("CARGO_BIN_EXE_kernel"))
            .env("CLAUDE_SESSION_ID", "conformance-run")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("hook runs under bash");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn edit_payload(path: &str) -> String {
        serde_json::json!({"tool_name": "Edit", "tool_input": {"file_path": path}}).to_string()
    }

    fn bash_payload(command: &str) -> String {
        serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}}).to_string()
    }

    /// Activate a packet the way /pick-task expects: `tasks/active.json`.
    fn activate_packet(&self, packet: &TaskPacket) {
        std::fs::write(
            self.path().join("tasks/active.json"),
            serde_json::to_string_pretty(packet).unwrap(),
        )
        .unwrap();
    }

    fn kernel(&self, args: &[&str]) -> (i32, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_kernel"))
            .args(args)
            .current_dir(self.path())
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn events(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.path().join("evidence/events.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

fn trial_packet() -> TaskPacket {
    TaskPacket {
        title: "Conformance trial".into(),
        objective: "Exercise the generated hook surface mechanically".into(),
        constraints: vec![],
        files: vec![
            FileScope::write("docs/trial-notes.md"),
            FileScope::write("docs/trial-link.md"),
        ],
        acceptance_criteria: vec!["every matrix row observed".into()],
        submitted_by: "conformance".into(),
        priority: Priority::High,
        amends_enforcement: false,
    }
}

const BLOCK: i32 = 2;
const ALLOW: i32 = 0;

#[test]
fn the_full_trial_matrix_through_the_generated_hooks() {
    let ws = Workspace::new();

    // T1 — fail-closed: no active packet, edit blocked, refusal chained.
    let (code, stderr) = ws.hook(
        "enforce_file_scope.sh",
        &Workspace::edit_payload("src/app.py"),
    );
    assert_eq!(code, BLOCK, "unpacketed edit must block: {stderr}");
    assert!(stderr.contains("no active task packet"), "{stderr}");

    // T2 — admission: activate the trial packet.
    ws.activate_packet(&trial_packet());

    // T3 — in-scope edit allowed; obligation debt recorded.
    let (code, stderr) = ws.hook(
        "enforce_file_scope.sh",
        &Workspace::edit_payload("docs/trial-notes.md"),
    );
    assert_eq!(code, ALLOW, "in-scope edit allows: {stderr}");
    let (code, _) = ws.hook(
        "require_validation.sh",
        &Workspace::edit_payload("docs/trial-notes.md"),
    );
    assert_eq!(code, ALLOW, "obligation records without blocking");

    // T4 — out-of-scope edit blocked.
    let (code, stderr) = ws.hook(
        "enforce_file_scope.sh",
        &Workspace::edit_payload("README.md"),
    );
    assert_eq!(code, BLOCK, "out-of-scope edit blocks");
    assert!(stderr.contains("not in the write scope"), "{stderr}");

    // T5 — the Guard's own script is protected from its subject.
    let (code, stderr) = ws.hook(
        "enforce_file_scope.sh",
        &Workspace::edit_payload("harness/hooks/enforce_file_scope.sh"),
    );
    assert_eq!(code, BLOCK, "enforcement artifacts are protected");
    assert!(
        stderr.contains("protected enforcement artifact"),
        "{stderr}"
    );

    // T6 — symlink laundering: in-scope NAME, out-of-scope target.
    std::os::unix::fs::symlink("/etc/hostname", ws.path().join("docs/trial-link.md")).unwrap();
    let (code, stderr) = ws.hook(
        "enforce_file_scope.sh",
        &Workspace::edit_payload("docs/trial-link.md"),
    );
    assert_eq!(code, BLOCK, "symlink escape blocks");
    assert!(
        stderr.contains("resolves outside the workspace"),
        "{stderr}"
    );

    // T7 — destructive Bash against protected artifacts blocked.
    let (code, stderr) = ws.hook(
        "protect_enforcement.sh",
        &Workspace::bash_payload("rm -rf harness/"),
    );
    assert_eq!(code, BLOCK, "rm of enforcement blocks");
    assert!(stderr.contains("amends_enforcement"), "{stderr}");

    // T8 — commit gate blocks while T3's debt is open.
    let (code, stderr) = ws.hook(
        "approve_commit.sh",
        &Workspace::bash_payload("git commit -m results"),
    );
    assert_eq!(code, BLOCK, "commit blocks while validation is owed");
    assert!(stderr.contains("require-validation"), "{stderr}");

    // T9 — discharge the debt, run-bound the way every governed call is:
    // the playbook identity comes from the generated artifact itself.
    let hook_text =
        std::fs::read_to_string(ws.path().join("harness/hooks/enforce_file_scope.sh")).unwrap();
    let playbook_ref = hook_text
        .lines()
        .find_map(|l| l.split("--playbook-ref \"").nth(1))
        .and_then(|rest| rest.split('"').next())
        .expect("the generated hook names its playbook")
        .to_string();
    let (code, stderr) = ws.kernel(&[
        "validate",
        "--ledger",
        "evidence/events.jsonl",
        "--run-id",
        "conformance-run",
        "--playbook-ref",
        &playbook_ref,
    ]);
    assert_eq!(code, ALLOW, "validate discharges: {stderr}");

    // T10 — the commit now passes its gate.
    let (code, stderr) = ws.hook(
        "approve_commit.sh",
        &Workspace::bash_payload("git commit -m results"),
    );
    assert_eq!(code, ALLOW, "commit allowed after discharge: {stderr}");

    // Non-commit Bash always passes through the gate untouched.
    let (code, _) = ws.hook("approve_commit.sh", &Workspace::bash_payload("cargo test"));
    assert_eq!(code, ALLOW, "non-commit commands pass through");

    // T11 — the chain proves the whole run, and every event is run-bound
    // to the checked-in Playbook and staged under the protocol.
    EventLog::at(ws.path().join("evidence/events.jsonl"))
        .verify_chain()
        .expect("the conformance run's history chains");
    let evs = ws.events();
    assert!(!evs.is_empty());
    for e in &evs {
        assert!(
            !e["playbook_ref"].as_str().unwrap().is_empty(),
            "hook-recorded events carry the compiled playbook identity: {e}"
        );
        assert!(
            !e["kernel_ref"].as_str().unwrap().is_empty(),
            "and the kernel identity: {e}"
        );
        assert!(
            [
                "proposed",
                "authorized",
                "executing",
                "completed",
                "recorded"
            ]
            .contains(&e["stage"].as_str().unwrap()),
            "and a protocol stage: {e}"
        );
    }
    // The refusals are all evidence: T1's unpacketed denial and T4/T5/T6's
    // scope denials appear as denied pre_tool events with the T1 reason ref.
    let denied = evs
        .iter()
        .filter(|e| e["transition"] == "pre_tool.edit" && e["decision"] == "denied")
        .count();
    assert!(
        denied >= 4,
        "the blocked attempts are chained ({denied} found)"
    );
    assert!(
        evs.iter()
            .any(|e| e["transition"] == "gate.pre_commit" && e["decision"] == "denied"),
        "the blocked commit is chained"
    );
}

#[test]
fn amendment_grant_turns_protection_into_a_recorded_amendment() {
    // The lawful path to changing enforcement: a packet that says so.
    let ws = Workspace::new();
    let mut packet = trial_packet();
    packet
        .files
        .push(FileScope::write("harness/enforcement.protected"));
    packet.amends_enforcement = true;
    ws.activate_packet(&packet);

    let (code, stderr) = ws.hook(
        "enforce_file_scope.sh",
        &Workspace::edit_payload("harness/enforcement.protected"),
    );
    assert_eq!(code, ALLOW, "granted amendment allows: {stderr}");
    assert!(
        stderr.contains("amendment"),
        "and is loudly noted: {stderr}"
    );
    assert!(
        ws.events()
            .iter()
            .any(|e| e["transition"] == "pre_tool.enforcement_amendment"),
        "the amendment is a distinct chained transition"
    );
}
