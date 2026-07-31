//! End-to-end tests that drive the compiled `intake` binary the way a user
//! would: emit a template, submit the example packet, read it back, and check
//! the file-scope Guard Law.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    // Cargo exposes the built binary's path to integration tests.
    PathBuf::from(env!("CARGO_BIN_EXE_intake"))
}

/// Run `intake` with the given args and a scratch ledger, returning
/// (status_success, stdout, stderr).
fn run(ledger: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(bin())
        .arg("--ledger")
        .arg(ledger)
        .args(args)
        .output()
        .expect("binary runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn template_is_valid_and_submittable() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    // The emitted template must itself parse and validate as a packet.
    let (ok, template, _) = run(&ledger, &["template"]);
    assert!(ok);
    let packet_file = dir.path().join("packet.toml");
    std::fs::write(&packet_file, &template).unwrap();

    let (ok, _, _) = run(&ledger, &["validate", packet_file.to_str().unwrap()]);
    assert!(ok, "template should pass validation");
}

#[test]
fn full_lifecycle_submit_list_show_checkedit() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let example = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/task-packet.toml");

    // Submit the example packet.
    let (ok, out, _) = run(&ledger, &["submit", example]);
    assert!(ok);
    let task_id = out.split_whitespace().nth(1).unwrap().to_string();
    assert_eq!(task_id.len(), 12);

    // It shows up in the list.
    let (ok, out, _) = run(&ledger, &["list"]);
    assert!(ok);
    assert!(out.contains(&task_id));
    assert!(out.contains("Preserve rows in migration 0007"));

    // The write-scoped file is allowed; a read-scoped and an unlisted one are denied.
    let (ok, _, _) = run(
        &ledger,
        &["check-edit", &task_id, "migrations/0007_backfill_ids.sql"],
    );
    assert!(ok, "write-scoped path should be allowed");

    let (ok, _, _) = run(&ledger, &["check-edit", &task_id, "src/schema.rs"]);
    assert!(!ok, "read-only path should be denied for writing");

    let (ok, _, _) = run(&ledger, &["check-edit", &task_id, "src/main.rs"]);
    assert!(!ok, "unlisted path should be denied");
}

#[test]
fn invalid_packet_is_rejected_and_not_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let bad = dir.path().join("bad.toml");
    // Parses fine, but fails the Guard Laws: vague objective, no files, no
    // acceptance criteria.
    std::fs::write(
        &bad,
        "title = \"x\"\nobjective = \"fix\"\nsubmitted_by = \"me\"\n",
    )
    .unwrap();

    let (ok, _, err) = run(&ledger, &["submit", bad.to_str().unwrap()]);
    assert!(!ok);
    assert!(err.contains("rejected"));

    // Nothing was recorded.
    let (ok, out, _) = run(&ledger, &["list"]);
    assert!(ok);
    assert!(out.contains("no packets recorded"));
}
