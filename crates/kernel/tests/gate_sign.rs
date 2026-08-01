//! Signature-authenticated approvals end-to-end: the custody boundary moves
//! from disk to key. A party who can rewrite the ledger AND the checkpoint
//! could formerly defeat file-level custody; with a signed approval covering
//! the action, preconditions, anchored ledger head, and expiry, that rewrite
//! invalidates the signature — forging a resumable approval now requires the
//! approver's private key.

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

fn append_event(ledger: &str, transition: &str) {
    let (ok, _, err) = kernel(&[
        "event",
        "--ledger",
        ledger,
        "--transition",
        transition,
        "--decision",
        "recorded",
    ]);
    assert!(ok, "append: {err}");
}

/// Generate a keypair; return (seed_path, public_key).
fn keygen(dir: &Path, name: &str) -> (PathBuf, String) {
    let seed = dir.join(format!("{name}.seed"));
    let (ok, stdout, err) = kernel(&["key", "generate", "--out", seed.to_str().unwrap()]);
    assert!(ok, "keygen: {err}");
    let public = stdout.trim().to_string();
    assert!(public.starts_with("ed25519:"), "public key on stdout");
    assert!(
        !stdout.contains(&std::fs::read_to_string(&seed).unwrap().trim().to_string()),
        "the private seed never reaches stdout"
    );
    (seed, public)
}

#[test]
fn signed_approval_survives_resume_and_defeats_checkpoint_rewrites() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("events.jsonl");
    let ledger_s = ledger.to_str().unwrap();

    // Alice's keypair, registered in the trusted-keys file.
    let (seed, public) = keygen(dir.path(), "alice");
    let trusted = dir.path().join("approvers.toml");
    std::fs::write(&trusted, format!("[approvers]\nalice = \"{public}\"\n")).unwrap();
    let trusted_s = trusted.to_str().unwrap();

    // Governed history, then an anchored checkpoint over it.
    append_event(ledger_s, "pre_tool.edit");
    append_event(ledger_s, "obligation.discharge.require-validation");
    let (ok, stdout, err) = kernel(&[
        "gate",
        "request",
        "--gate",
        "release",
        "--run-id",
        "run-1",
        "--action-hash",
        "sha256:action",
        "--precondition",
        "repository_revision=abc123",
        "--checkpoints",
        dir.path().join("cp").to_str().unwrap(),
        "--ledger",
        ledger_s,
    ]);
    assert!(ok, "request: {err}");
    let cp_path = stdout.trim().to_string();

    // Alice signs the canonical approval message offline; the kernel verifies
    // BEFORE recording, and the record says authenticated — provably.
    let (ok, sig, err) = kernel(&[
        "gate",
        "sign",
        "--checkpoint",
        &cp_path,
        "--key",
        seed.to_str().unwrap(),
    ]);
    assert!(ok, "sign: {err}");
    let sig = sig.trim().to_string();
    let (ok, stdout, err) = kernel(&[
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
        trusted_s,
    ]);
    assert!(ok, "approve: {err}");
    assert!(
        stdout.contains("authenticated"),
        "recorded as such: {stdout}"
    );

    // Resume re-proves everything: action, preconditions, anchor, signature.
    let verify = |extra: &[&str]| {
        let mut args = vec![
            "gate",
            "verify",
            "--checkpoint",
            &cp_path,
            "--action-hash",
            "sha256:action",
            "--precondition",
            "repository_revision=abc123",
            "--ledger",
            ledger_s,
            "--trusted-keys",
            trusted_s,
        ];
        args.extend_from_slice(extra);
        kernel(&args)
    };
    let (ok, _, err) = verify(&[]);
    assert!(ok, "intact world resumes: {err}");

    // THE CUSTODY SCENARIO. An attacker with write access to disk replaces
    // the ledger with a fresh, internally valid chain and updates the
    // checkpoint's anchored head to match — everything file-level custody
    // checks now passes. But the approval's signature covers the ledger head
    // Alice actually saw, so the rewrite invalidates it.
    std::fs::remove_file(&ledger).unwrap();
    append_event(ledger_s, "pre_tool.edit"); // a rewritten, valid history
    let (ok, stdout, _) = kernel(&["ledger", "verify", "--ledger", ledger_s]);
    assert!(ok, "the forged chain is internally valid");
    let new_head = stdout
        .split("head ")
        .nth(1)
        .expect("head printed")
        .trim()
        .to_string();
    let cp_text = std::fs::read_to_string(&cp_path).unwrap();
    let cp_json: serde_json::Value = serde_json::from_str(&cp_text).unwrap();
    let old_head = cp_json["ledger_head"].as_str().unwrap().to_string();
    std::fs::write(&cp_path, cp_text.replace(&old_head, &new_head)).unwrap();

    let (ok, _, stderr) = verify(&[]);
    assert!(!ok, "a rewritten world must not resume");
    assert!(
        stderr.contains("signature does not verify"),
        "the signature is what catches it: {stderr}"
    );
}

#[test]
fn an_unverifiable_signature_is_never_recorded() {
    let dir = tempfile::tempdir().unwrap();

    // Mallory holds a key, but the registry trusts only Alice's.
    let (_alice_seed, alice_public) = keygen(dir.path(), "alice");
    let (mallory_seed, _) = keygen(dir.path(), "mallory");
    let trusted = dir.path().join("approvers.toml");
    std::fs::write(
        &trusted,
        format!("[approvers]\nalice = \"{alice_public}\"\n"),
    )
    .unwrap();

    let (ok, stdout, err) = kernel(&[
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
    assert!(ok, "{err}");
    let cp_path = stdout.trim().to_string();

    // Mallory signs and claims to be Alice: the signature cannot verify
    // against Alice's registered key, and nothing is recorded.
    let (ok, sig, _) = kernel(&[
        "gate",
        "sign",
        "--checkpoint",
        &cp_path,
        "--key",
        mallory_seed.to_str().unwrap(),
    ]);
    assert!(ok);
    let (ok, _, stderr) = kernel(&[
        "gate",
        "approve",
        "--checkpoint",
        &cp_path,
        "--approver",
        "alice",
        "--auth",
        "signature",
        "--signature",
        sig.trim(),
        "--trusted-keys",
        trusted.to_str().unwrap(),
    ]);
    assert!(!ok, "a forged approval is refused");
    assert!(stderr.contains("NOT recorded"), "{stderr}");
    let cp: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cp_path).unwrap()).unwrap();
    assert!(
        cp.get("approval").is_none(),
        "the checkpoint carries no approval at all"
    );

    // An unregistered principal is refused by name.
    let (ok, sig, _) = kernel(&[
        "gate",
        "sign",
        "--checkpoint",
        &cp_path,
        "--key",
        mallory_seed.to_str().unwrap(),
    ]);
    assert!(ok);
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
        sig.trim(),
        "--trusted-keys",
        trusted.to_str().unwrap(),
    ]);
    assert!(!ok);
    assert!(stderr.contains("no key registered"), "{stderr}");
}

#[test]
fn a_claimed_approval_still_works_and_stays_honest() {
    // The unauthenticated path is unchanged: recorded, and recorded AS
    // unauthenticated — signature verification is opt-in strength, not a
    // breaking change.
    let dir = tempfile::tempdir().unwrap();
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
    let (ok, stdout, _) = kernel(&[
        "gate",
        "approve",
        "--checkpoint",
        &cp_path,
        "--approver",
        "bob",
    ]);
    assert!(ok);
    assert!(stdout.contains("claimed — unauthenticated"));
    let (ok, _, err) = kernel(&[
        "gate",
        "verify",
        "--checkpoint",
        &cp_path,
        "--action-hash",
        "sha256:x",
    ]);
    assert!(ok, "no trusted-keys needed for a claimed approval: {err}");
}
