//! Runtime-instance identity end-to-end: pattern kind → composition node →
//! runtime instance. The compiled positions registry makes the IR's
//! replication cardinality enforceable at runtime; per-instance Gates bind
//! approval to one occupant; instance-scoped obligations make a worker's debt
//! that worker's to clear.

use std::io::Write;
use std::path::{Path, PathBuf};
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

/// A registry as the compiler generates it: three workers, one deployer.
fn write_registry(dir: &Path) -> PathBuf {
    let path = dir.join("positions.json");
    std::fs::write(
        &path,
        r#"{"positions":[{"name":"worker","node":0,"kind":"Delegate","multiplicity":3},
                         {"name":"deployer","node":1,"kind":"Port","multiplicity":1}]}"#,
    )
    .unwrap();
    path
}

#[test]
fn the_registry_bounds_what_a_checkpoint_may_gate() {
    let dir = tempfile::tempdir().unwrap();
    let positions = write_registry(dir.path());
    let cp_dir = dir.path().join("cp");

    let request = |instance: &str| {
        kernel(&[
            "gate",
            "request",
            "--gate",
            "per-worker",
            "--run-id",
            "run-1",
            "--action-hash",
            "sha256:x",
            "--checkpoints",
            cp_dir.to_str().unwrap(),
            "--instance",
            instance,
            "--positions",
            positions.to_str().unwrap(),
        ])
    };

    // The full declared range is grantable...
    let (ok, _, err) = request("run-1/worker/3");
    assert!(ok, "{err}");
    // ...a slot beyond the declared multiplicity is not: the architecture
    // stands for exactly three workers, enforced at runtime.
    let (ok, _, stderr) = request("run-1/worker/4");
    assert!(!ok, "replication cardinality is enforceable now");
    assert!(stderr.contains("multiplicity 3"), "{stderr}");
    // ...and neither is an occupant of a position never declared.
    let (ok, _, stderr) = request("run-1/ghost/1");
    assert!(!ok);
    assert!(stderr.contains("not an addressable position"), "{stderr}");
}

#[test]
fn a_per_instance_approval_resumes_only_its_instance() {
    let dir = tempfile::tempdir().unwrap();
    let positions = write_registry(dir.path());
    let cp_dir = dir.path().join("cp");

    let (ok, stdout, err) = kernel(&[
        "gate",
        "request",
        "--gate",
        "per-worker",
        "--run-id",
        "run-1",
        "--action-hash",
        "sha256:x",
        "--checkpoints",
        cp_dir.to_str().unwrap(),
        "--instance",
        "run-1/worker/2",
        "--positions",
        positions.to_str().unwrap(),
    ]);
    assert!(ok, "{err}");
    let cp_path = stdout.trim().to_string();
    let cp: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cp_path).unwrap()).unwrap();
    assert_eq!(cp["instance"], "run-1/worker/2", "the binding is durable");

    let (ok, _, err) = kernel(&[
        "gate",
        "approve",
        "--checkpoint",
        &cp_path,
        "--approver",
        "alice",
    ]);
    assert!(ok, "{err}");

    let verify = |extra: &[&str]| {
        let mut args = vec![
            "gate",
            "verify",
            "--checkpoint",
            &cp_path,
            "--action-hash",
            "sha256:x",
        ];
        args.extend_from_slice(extra);
        kernel(&args)
    };
    // The bound instance resumes; its siblings and the anonymous do not.
    let (ok, _, err) = verify(&["--instance", "run-1/worker/2"]);
    assert!(ok, "the approved worker resumes: {err}");
    let (ok, _, stderr) = verify(&["--instance", "run-1/worker/3"]);
    assert!(!ok, "worker 2's approval never resumes worker 3");
    assert!(stderr.contains("bound to instance"), "{stderr}");
    let (ok, _, stderr) = verify(&[]);
    assert!(!ok, "resuming anonymously is refused too");
    assert!(stderr.contains("pass --instance"), "{stderr}");
}

#[test]
fn instance_scoped_debt_is_the_workers_own_to_clear() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let ledger_s = ledger.to_str().unwrap();
    let cp_dir = dir.path().join("cp");

    // Both workers edit under an instance-scoped obligation.
    for slot in ["1", "2"] {
        let (ok, _, err) = kernel_with_stdin(
            &[
                "post-tool",
                "--ledger",
                ledger_s,
                "--run-id",
                "run-1",
                "--scope",
                "instance",
                "--instance",
                &format!("run-1/worker/{slot}"),
            ],
            &serde_json::json!({"tool_input": {"file_path": format!("shard-{slot}/x.rs")}})
                .to_string(),
        );
        assert!(ok, "{err}");
    }
    // Worker 1 validates its own work; worker 2 does not.
    let (ok, _, err) = kernel(&[
        "validate",
        "--ledger",
        ledger_s,
        "--run-id",
        "run-1",
        "--scope",
        "instance",
        "--instance",
        "run-1/worker/1",
    ]);
    assert!(ok, "{err}");

    // Per-instance gates requiring the instance-scoped obligation.
    let mut paths = Vec::new();
    for slot in ["1", "2"] {
        let (ok, stdout, err) = kernel(&[
            "gate",
            "request",
            "--gate",
            "merge",
            "--run-id",
            "run-1",
            "--action-hash",
            "sha256:x",
            "--checkpoints",
            cp_dir.to_str().unwrap(),
            "--instance",
            &format!("run-1/worker/{slot}"),
            "--require-obligation",
            "require-validation:instance",
        ]);
        assert!(ok, "{err}");
        let cp_path = stdout.trim().to_string();
        let (ok, _, err) = kernel(&[
            "gate",
            "approve",
            "--checkpoint",
            &cp_path,
            "--approver",
            "alice",
        ]);
        assert!(ok, "{err}");
        paths.push(cp_path);
    }

    // Worker 1's gate resumes; worker 2's is refused by ITS outstanding debt.
    let (ok, _, err) = kernel(&[
        "gate",
        "verify",
        "--checkpoint",
        &paths[0],
        "--action-hash",
        "sha256:x",
        "--ledger",
        ledger_s,
        "--instance",
        "run-1/worker/1",
    ]);
    assert!(ok, "worker 1 cleared its own debt: {err}");
    let (ok, _, stderr) = kernel(&[
        "gate",
        "verify",
        "--checkpoint",
        &paths[1],
        "--action-hash",
        "sha256:x",
        "--ledger",
        ledger_s,
        "--instance",
        "run-1/worker/2",
    ]);
    assert!(!ok, "worker 2's debt is worker 2's");
    assert!(stderr.contains("require-validation"), "{stderr}");

    // A recording without its instance is refused outright.
    let (ok, _, stderr) = kernel_with_stdin(
        &[
            "post-tool",
            "--ledger",
            ledger_s,
            "--run-id",
            "run-1",
            "--scope",
            "instance",
        ],
        "{}",
    );
    assert!(!ok);
    assert!(stderr.contains("--instance"), "{stderr}");
}
