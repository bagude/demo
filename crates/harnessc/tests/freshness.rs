//! The checked-in Playbook must match what this compiler produces.
//!
//! Source provenance and executable provenance are different things: the spec
//! bytes can be unchanged while the compiler's semantics, the IR schema, or the
//! back-end's output have all moved. A generated tree committed by an older
//! compiler would then carry a matching spec hash while encoding a system this
//! compiler would never emit — and nothing in the artifact would say so.
//!
//! This test is the freshness proof. It compiles the repository's own spec in
//! memory and compares every generated file against the tree on disk, so a
//! stale artifact fails CI instead of shipping.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // crates/harnessc/ → repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
        .to_path_buf()
}

#[test]
fn the_checked_in_playbook_is_freshly_generated() {
    let root = repo_root();
    let spec_path = root.join("harness.patterns.yaml");
    let text = std::fs::read_to_string(&spec_path).expect("spec is readable");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_harnessc"))
        .arg("verify")
        .arg("--spec")
        .arg(&spec_path)
        .arg("--out")
        .arg(&root)
        .output()
        .expect("harnessc runs");

    assert!(
        output.status.success(),
        "the checked-in generated tree is stale — run `harnessc build --out .` and commit the \
         result.\nspec: {}\n{}{}",
        spec_path.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Sanity: the spec really is the one the Playbook claims to come from.
    assert!(text.contains("enablement-workbench"));
}

#[test]
fn verify_detects_a_tampered_artifact() {
    // The freshness check must actually be able to fail: point it at a tree
    // where one generated file has been altered.
    let root = repo_root();
    let spec_path = root.join("harness.patterns.yaml");
    let tmp = std::env::temp_dir().join(format!("harnessc-verify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);

    let built = std::process::Command::new(env!("CARGO_BIN_EXE_harnessc"))
        .args(["build", "--spec"])
        .arg(&spec_path)
        .arg("--out")
        .arg(&tmp)
        .output()
        .expect("harnessc runs");
    assert!(built.status.success(), "build into a temp tree succeeds");

    let victim = tmp.join("harness/playbook.json");
    let original = std::fs::read_to_string(&victim).expect("playbook exists");
    std::fs::write(
        &victim,
        original.replace("runtime-enforced", "kernel-mediated"),
    )
    .expect("tamper");

    let verified = std::process::Command::new(env!("CARGO_BIN_EXE_harnessc"))
        .args(["verify", "--spec"])
        .arg(&spec_path)
        .arg("--out")
        .arg(&tmp)
        .output()
        .expect("harnessc runs");
    assert!(
        !verified.status.success(),
        "a tampered enforcement claim must fail verification"
    );
    assert!(
        String::from_utf8_lossy(&verified.stderr).contains("playbook.json"),
        "the failure names the offending file"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
