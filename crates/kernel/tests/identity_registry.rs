//! The identity registry end-to-end: approver keys bound to organizational
//! identity by a signing authority, verified offline. Custody moves from
//! registry-file custody to authority-key custody — and revocation is
//! retroactive: a checkpoint approved by a since-revoked key stops resuming.

use std::path::{Path, PathBuf};
use std::process::Command;

fn kernel(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_kernel")))
        .args(args)
        .output()
        .expect("kernel runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn keygen(dir: &Path, name: &str) -> (PathBuf, String) {
    let seed = dir.join(format!("{name}.seed"));
    let (ok, stdout, err) = kernel(&["key", "generate", "--out", seed.to_str().unwrap()]);
    assert!(ok, "keygen: {err}");
    (seed, stdout.trim().to_string())
}

/// Write and authority-sign a registry document; returns its path.
fn issue_registry(dir: &Path, authority_seed: &Path, serial: u64, body: &str) -> PathBuf {
    let path = dir.join("approvers.toml");
    std::fs::write(
        &path,
        format!(
            "[registry]\nissuer = \"acme-security\"\nserial = {serial}\nexpires_at = \
             \"2099-01-01T00:00:00Z\"\n\n{body}"
        ),
    )
    .unwrap();
    let (ok, _, err) = kernel(&[
        "registry",
        "sign",
        "--registry",
        path.to_str().unwrap(),
        "--key",
        authority_seed.to_str().unwrap(),
    ]);
    assert!(ok, "registry sign: {err}");
    path
}

#[test]
fn authority_flow_with_retroactive_revocation_and_rollback_defense() {
    let dir = tempfile::tempdir().unwrap();
    let (authority_seed, authority_pub) = keygen(dir.path(), "authority");
    let (alice_seed, alice_pub) = keygen(dir.path(), "alice");

    // Serial 1: the authority binds alice's key to her principal.
    let registry = issue_registry(
        dir.path(),
        &authority_seed,
        1,
        &format!("[approvers]\nalice = \"{alice_pub}\"\n"),
    );
    let registry_s = registry.to_str().unwrap();
    // Keep copies for the rollback attempt later.
    let v1_bytes = std::fs::read(&registry).unwrap();
    let v1_sig = std::fs::read(dir.path().join("approvers.toml.sig")).unwrap();

    let (ok, stdout, err) = kernel(&[
        "registry",
        "verify",
        "--registry",
        registry_s,
        "--authority",
        &authority_pub,
    ]);
    assert!(ok, "registry verify: {err}");
    assert!(
        stdout.contains("issuer acme-security") && stdout.contains("serial 1"),
        "{stdout}"
    );

    // Anchored checkpoint, signed approval — resolved through the VERIFIED
    // registry this time (--authority on both approve and verify).
    let (ok, stdout, err) = kernel(&[
        "gate",
        "request",
        "--gate",
        "release",
        "--run-id",
        "run-1",
        "--action-hash",
        "sha256:action",
        "--checkpoints",
        dir.path().join("cp").to_str().unwrap(),
    ]);
    assert!(ok, "{err}");
    let cp_path = stdout.trim().to_string();
    let (ok, sig, err) = kernel(&[
        "gate",
        "sign",
        "--checkpoint",
        &cp_path,
        "--key",
        alice_seed.to_str().unwrap(),
    ]);
    assert!(ok, "{err}");
    let sig = sig.trim().to_string();
    let (ok, _, err) = kernel(&[
        "gate",
        "approve",
        "--checkpoint",
        &cp_path,
        "--approver",
        "alice",
        "--auth",
        "signature",
        "--signature",
        &sig,
        "--trusted-keys",
        registry_s,
        "--authority",
        &authority_pub,
    ]);
    assert!(ok, "approve through verified registry: {err}");
    let verify = || {
        kernel(&[
            "gate",
            "verify",
            "--checkpoint",
            &cp_path,
            "--action-hash",
            "sha256:action",
            "--trusted-keys",
            registry_s,
            "--authority",
            &authority_pub,
        ])
    };
    let (ok, _, err) = verify();
    assert!(ok, "verified registry resumes: {err}");

    // THE REVOCATION PAYOFF. The authority issues serial 2 withdrawing
    // alice's key. The checkpoint's approval was valid when minted — and
    // stops resuming NOW, because the approver is resolved through the
    // current identity document. That is what revocation means.
    issue_registry(
        dir.path(),
        &authority_seed,
        2,
        &format!(
            "[approvers]\nalice = \"{alice_pub}\"\n\n[revoked]\nalice = \"2099-01-01 key \
             compromise\"\n"
        ),
    );
    let (ok, _, stderr) = verify();
    assert!(!ok, "a revoked approver's checkpoint must not resume");
    assert!(stderr.contains("revoked"), "refused by name: {stderr}");

    // ROLLBACK DEFENSE. Replaying the serial-1 document (validly signed,
    // alice unrevoked) is refused: the kernel has accepted serial 2.
    std::fs::write(&registry, v1_bytes).unwrap();
    std::fs::write(dir.path().join("approvers.toml.sig"), v1_sig).unwrap();
    let (ok, _, stderr) = verify();
    assert!(
        !ok,
        "a rolled-back identity document must not resurrect alice"
    );
    assert!(stderr.contains("rolled-back"), "refused by name: {stderr}");
}

#[test]
fn an_edited_registry_refuses_wholesale_under_a_pinned_authority() {
    let dir = tempfile::tempdir().unwrap();
    let (authority_seed, authority_pub) = keygen(dir.path(), "authority");
    let (_mallory_seed, mallory_pub) = keygen(dir.path(), "mallory");

    let registry = issue_registry(dir.path(), &authority_seed, 1, "[approvers]\n");
    // The attack the signature exists for: appending an approver to the file
    // without the authority's key.
    let mut text = std::fs::read_to_string(&registry).unwrap();
    text.push_str(&format!("mallory = \"{mallory_pub}\"\n"));
    std::fs::write(&registry, text).unwrap();

    let (ok, _, stderr) = kernel(&[
        "registry",
        "verify",
        "--registry",
        registry.to_str().unwrap(),
        "--authority",
        &authority_pub,
    ]);
    assert!(!ok, "one edited byte refuses the whole document");
    assert!(stderr.contains("registry refused"), "{stderr}");

    // And an approval attempt through it is refused before recording.
    let (ok, stdout, _) = kernel(&[
        "gate",
        "request",
        "--gate",
        "g",
        "--run-id",
        "r",
        "--action-hash",
        "sha256:x",
        "--checkpoints",
        dir.path().join("cp").to_str().unwrap(),
    ]);
    assert!(ok);
    let cp_path = stdout.trim().to_string();
    let (ok, _, stderr) = kernel(&[
        "gate",
        "approve",
        "--checkpoint",
        &cp_path,
        "--approver",
        "mallory",
        "--auth",
        "signature",
        "--signature",
        "ed25519:00",
        "--trusted-keys",
        registry.to_str().unwrap(),
        "--authority",
        &authority_pub,
    ]);
    assert!(!ok);
    assert!(stderr.contains("NOT recorded"), "{stderr}");
}

#[test]
fn registry_sign_warns_when_validity_metadata_is_missing() {
    // The issuer should learn at signing time, not at the Gate, that a
    // pinned-authority load will refuse the document.
    let dir = tempfile::tempdir().unwrap();
    let (authority_seed, _) = keygen(dir.path(), "authority");
    let bare = dir.path().join("bare.toml");
    std::fs::write(&bare, "[approvers]\n").unwrap();
    let (ok, _, stderr) = kernel(&[
        "registry",
        "sign",
        "--registry",
        bare.to_str().unwrap(),
        "--key",
        authority_seed.to_str().unwrap(),
    ]);
    assert!(ok, "signing still succeeds");
    assert!(
        stderr.contains("warning") && stderr.contains("expires_at"),
        "{stderr}"
    );
}
