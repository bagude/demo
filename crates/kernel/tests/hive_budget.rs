//! The transactional Hive budget end-to-end: a cap the caller self-reports
//! against is not a cap. In pool mode the compiled kernel reserves a spawn's
//! budget atomically from the durable pool, settlement records actual spend
//! and returns the remainder, and every decision is Ledger evidence.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn kernel_with_stdin(args: &[&str], stdin_json: &str) -> (bool, String, String) {
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
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn kernel(args: &[&str]) -> (bool, String, String) {
    kernel_with_stdin(args, "")
}

fn spawn_json(budget: u64, scope: &str) -> String {
    serde_json::json!({
        "parent": "root",
        "contract": "FindingSchema",
        "budget": budget,
        "depth": 1,
        "termination": "no new work",
        "merge": "root.results",
        "write_scope": [scope],
    })
    .to_string()
}

#[test]
fn pool_mode_reserves_settles_and_records() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("hive");
    let store_s = store.to_str().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let ledger_s = ledger.to_str().unwrap();

    let (ok, stdout, err) = kernel(&[
        "hive", "init", "--store", store_s, "--hive", "research", "--budget", "1500",
    ]);
    assert!(ok, "init: {err}");
    assert!(stdout.contains("remaining 1500"), "{stdout}");

    // First spawn reserves 1000 of 1500.
    let spawn = |id: &str, budget: u64| {
        kernel_with_stdin(
            &[
                "hive-spawn",
                "--max-depth",
                "3",
                "--store",
                store_s,
                "--hive",
                "research",
                "--spawn-id",
                id,
                "--ledger",
                ledger_s,
            ],
            &spawn_json(budget, &format!("shard-{id}/")),
        )
    };
    let (ok, stdout, err) = spawn("w1", 1000);
    assert!(ok, "{err}");
    assert!(stdout.contains("500 remaining"), "{stdout}");

    // A second 1000 does NOT fit: the pool says so — no caller claim involved.
    let (ok, _, stderr) = spawn("w2", 1000);
    assert!(!ok, "the pool cannot be overshot");
    assert!(
        stderr.contains("exceeds the pool's remaining 500"),
        "{stderr}"
    );

    // Replaying w1's reservation is idempotent, not double-spending.
    let (ok, _, err) = spawn("w1", 1000);
    assert!(ok, "replay-safe: {err}");

    // w1 finishes having spent 200: 800 returns, and now w2 fits.
    let (ok, stdout, err) = kernel(&[
        "hive",
        "settle",
        "--store",
        store_s,
        "--hive",
        "research",
        "--spawn-id",
        "w1",
        "--spent",
        "200",
        "--ledger",
        ledger_s,
    ]);
    assert!(ok, "settle: {err}");
    assert!(stdout.contains("pool remaining 1300"), "{stdout}");
    let (ok, _, err) = spawn("w2", 1000);
    assert!(ok, "freed budget covers the retry: {err}");

    // Settling more than reserved was never authorized.
    let (ok, _, stderr) = kernel(&[
        "hive",
        "settle",
        "--store",
        store_s,
        "--hive",
        "research",
        "--spawn-id",
        "w2",
        "--spent",
        "5000",
        "--ledger",
        ledger_s,
    ]);
    assert!(!ok);
    assert!(stderr.contains("exceeds the 1000 reserved"), "{stderr}");

    // Every decision above is Ledger evidence: grants, the refusal, the
    // settlement, and the refused overspend.
    let text = std::fs::read_to_string(&ledger).unwrap();
    let count = |needle: &str| text.matches(needle).count();
    assert_eq!(count("\"transition\":\"hive.spawn\""), 4);
    assert_eq!(count("\"transition\":\"hive.settle\""), 2);
    assert!(
        text.contains("\"decision\":\"denied\""),
        "refusals recorded"
    );
}

#[test]
fn a_missing_pool_and_a_renegotiated_total_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("hive");
    let store_s = store.to_str().unwrap();

    // Spawning against a pool that was never created is refused outright —
    // pool mode never falls back to trusting the caller.
    let (ok, _, stderr) = kernel_with_stdin(
        &[
            "hive-spawn",
            "--max-depth",
            "3",
            "--store",
            store_s,
            "--hive",
            "ghost",
            "--spawn-id",
            "w",
        ],
        &spawn_json(10, "shard/"),
    );
    assert!(!ok);
    assert!(stderr.contains("no budget pool"), "{stderr}");

    // Re-declaring a pool with a different total is not a renegotiation.
    let (ok, _, _) = kernel(&[
        "hive", "init", "--store", store_s, "--hive", "h", "--budget", "100",
    ]);
    assert!(ok);
    let (ok, _, stderr) = kernel(&[
        "hive", "init", "--store", store_s, "--hive", "h", "--budget", "999",
    ]);
    assert!(!ok);
    assert!(stderr.contains("not renegotiated"), "{stderr}");
}

#[test]
fn stateless_mode_still_works_and_says_what_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let _ = dir; // no pool: purely caller-claimed
    let (ok, stdout, err) = kernel_with_stdin(
        &[
            "hive-spawn",
            "--max-depth",
            "3",
            "--budget-remaining",
            "5000",
        ],
        &spawn_json(1000, "shard-a/"),
    );
    assert!(ok, "{err}");
    assert!(
        stdout.contains("stateless"),
        "the weaker mode names itself: {stdout}"
    );
    // Mixing the modes is a usage error, not a silent choice.
    let (ok, _, stderr) = kernel_with_stdin(
        &[
            "hive-spawn",
            "--max-depth",
            "3",
            "--budget-remaining",
            "5000",
            "--store",
            "x",
            "--hive",
            "h",
            "--spawn-id",
            "s",
        ],
        &spawn_json(1000, "shard-a/"),
    );
    assert!(!ok);
    assert!(stderr.contains("either"), "{stderr}");
}
