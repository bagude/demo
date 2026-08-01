//! The bundle proof: `verify` must hold the tree to the exact generated set —
//! path set, bytes, file type, and mode — and `build` must retire files that
//! fell out of that set.
//!
//! Byte comparison of expected files proves each present file is right; it
//! cannot see a stale artifact an older compiler emitted (still live behavior
//! in the harness), a hook whose executable bit was stripped (it silently
//! stops running), or a path replaced by a symlink. These tests pin each of
//! those holes closed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A spec whose composition activates a Specialist — the Specialist's SKILL.md
/// is a per-component artifact, so dropping it from the spec shrinks the
/// generated path set. That is the "compiler no longer emits this file" case.
const SPEC_WITH_SPECIALIST: &str = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "(Port[staging] within Sandbox) -> Gate + Law + Ledger + Specialist[docs]"
bindings:
  sandbox: { workspace: branch, lineage: [source_revision, sandbox_id, merge_revision] }
  laws:
    - { id: enforce-file-scope, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: staging, server: deploy, write: [release], write_guard: enforce-file-scope, sandboxed: propose }
  specialists:
    - { id: docs, skill: harness/skills/docs/SKILL.md, description: docs domain knowledge }
  gate:
    id: g
    boundary: before_deploy
    checkpoint_schema: harness/schemas/checkpoint.schema.json
    bind: [action_hash, repository_revision, approver]
  ledger:
    event_schema: harness/schemas/event.schema.json
    destination: evidence/events.jsonl
    redact: [secrets, credentials]
platform: { type: claude-code }
"#;

/// The same harness with the Specialist retired.
const SPEC_WITHOUT_SPECIALIST: &str = r#"
harness: { name: n, version: 0.1.0 }
composition:
  expression: "(Port[staging] within Sandbox) -> Gate + Law + Ledger"
bindings:
  sandbox: { workspace: branch, lineage: [source_revision, sandbox_id, merge_revision] }
  laws:
    - { id: enforce-file-scope, kind: guard, event: pre_tool, applies_to: [edit] }
  ports:
    - { id: staging, server: deploy, write: [release], write_guard: enforce-file-scope, sandboxed: propose }
  gate:
    id: g
    boundary: before_deploy
    checkpoint_schema: harness/schemas/checkpoint.schema.json
    bind: [action_hash, repository_revision, approver]
  ledger:
    event_schema: harness/schemas/event.schema.json
    destination: evidence/events.jsonl
    redact: [secrets, credentials]
platform: { type: claude-code }
"#;

const SKILL_PATH: &str = "harness/skills/docs/SKILL.md";
const MANIFEST_PATH: &str = "harness/bundle.manifest.json";

fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("harnessc-bundle-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn write_spec(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("spec written");
    path
}

fn harnessc(args: &[&str], spec: &Path, out: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_harnessc"))
        .args(args)
        .arg("--spec")
        .arg(spec)
        .arg("--out")
        .arg(out)
        .output()
        .expect("harnessc runs")
}

fn tmp_litter(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.to_string_lossy().ends_with(".harnessc-tmp") {
                found.push(p);
            }
        }
    }
    found
}

#[test]
fn build_retires_files_the_new_playbook_no_longer_generates() {
    let dir = scratch("retire");
    let out = dir.join("out");
    let v1 = write_spec(&dir, "v1.yaml", SPEC_WITH_SPECIALIST);
    let v2 = write_spec(&dir, "v2.yaml", SPEC_WITHOUT_SPECIALIST);

    let built = harnessc(&["build"], &v1, &out);
    assert!(built.status.success(), "v1 builds");
    assert!(out.join(SKILL_PATH).exists(), "specialist artifact emitted");
    let manifest = std::fs::read_to_string(out.join(MANIFEST_PATH)).expect("manifest exists");
    assert!(manifest.contains(SKILL_PATH), "manifest lists the skill");
    assert!(tmp_litter(&out).is_empty(), "no staging litter after build");

    // Rebuild with the Specialist retired: the file must be REMOVED, not left
    // as live-but-unaccounted-for behavior.
    let rebuilt = harnessc(&["build"], &v2, &out);
    assert!(rebuilt.status.success(), "v2 builds");
    assert!(
        !out.join(SKILL_PATH).exists(),
        "a formerly generated file is retired by the next build"
    );
    assert!(
        String::from_utf8_lossy(&rebuilt.stdout).contains("removed"),
        "the removal is reported, never silent"
    );
    let manifest = std::fs::read_to_string(out.join(MANIFEST_PATH)).expect("manifest exists");
    assert!(
        !manifest.contains(SKILL_PATH),
        "manifest no longer lists it"
    );

    // And the tree now verifies clean against v2.
    let verified = harnessc(&["verify"], &v2, &out);
    assert!(verified.status.success(), "retired tree verifies fresh");
}

#[test]
fn verify_flags_a_formerly_generated_file_as_obsolete() {
    let dir = scratch("obsolete");
    let out = dir.join("out");
    let v1 = write_spec(&dir, "v1.yaml", SPEC_WITH_SPECIALIST);
    let v2 = write_spec(&dir, "v2.yaml", SPEC_WITHOUT_SPECIALIST);

    assert!(harnessc(&["build"], &v1, &out).status.success());
    assert!(harnessc(&["verify"], &v1, &out).status.success(), "sanity");

    // The v2 compiler no longer emits the skill file, but it is still on disk
    // and the on-disk manifest still lists it: exactly the stale-artifact
    // scenario a files-I-expect scan cannot see.
    let verified = harnessc(&["verify"], &v2, &out);
    assert!(!verified.status.success(), "obsolete artifact fails verify");
    let stderr = String::from_utf8_lossy(&verified.stderr);
    assert!(stderr.contains("obsolete"), "named as obsolete: {stderr}");
    assert!(stderr.contains(SKILL_PATH), "the exact path is named");
}

#[cfg(unix)]
#[test]
fn verify_detects_a_stripped_executable_bit() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch("mode");
    let out = dir.join("out");
    let v1 = write_spec(&dir, "v1.yaml", SPEC_WITH_SPECIALIST);
    assert!(harnessc(&["build"], &v1, &out).status.success());

    // Identical bytes, stripped executable bit: the hook silently stops
    // running, which is a behavioral change verification must catch.
    let hook = out.join("harness/hooks/enforce_file_scope.sh");
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o644)).unwrap();

    let verified = harnessc(&["verify"], &v1, &out);
    assert!(!verified.status.success(), "mode drift fails verify");
    let stderr = String::from_utf8_lossy(&verified.stderr);
    assert!(stderr.contains("mode"), "named as a mode problem: {stderr}");
    assert!(stderr.contains("enforce_file_scope.sh"));
}

#[cfg(unix)]
#[test]
fn verify_detects_a_file_replaced_by_a_symlink() {
    let dir = scratch("type");
    let out = dir.join("out");
    let v1 = write_spec(&dir, "v1.yaml", SPEC_WITH_SPECIALIST);
    assert!(harnessc(&["build"], &v1, &out).status.success());

    // Same bytes through the link — but the artifact's content is now
    // controlled from outside the managed path, so the type must fail.
    let victim = out.join("harness/gates/g.json");
    let aside = out.join("harness/gates/g.aside.json");
    std::fs::rename(&victim, &aside).unwrap();
    std::os::unix::fs::symlink("g.aside.json", &victim).unwrap();

    let verified = harnessc(&["verify"], &v1, &out);
    assert!(!verified.status.success(), "type change fails verify");
    let stderr = String::from_utf8_lossy(&verified.stderr);
    assert!(
        stderr.contains("type") && stderr.contains("g.json"),
        "named as a type problem: {stderr}"
    );
}

fn current_pointer(out: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(out.join(".harnessc/current")).unwrap()).unwrap()
}

#[test]
fn build_materializes_a_versioned_bundle_and_switches_current() {
    let dir = scratch("versioned");
    let out = dir.join("out");
    let v1 = write_spec(&dir, "v1.yaml", SPEC_WITH_SPECIALIST);
    assert!(harnessc(&["build"], &v1, &out).status.success());

    // The pointer names the promoted playbook and its versioned copy...
    let ptr = current_pointer(&out);
    let playbook_ref = ptr["playbook_ref"].as_str().unwrap();
    assert!(playbook_ref.starts_with("sha256:"));
    let bundle = out.join(ptr["bundle"].as_str().unwrap());
    assert!(
        bundle.ends_with(format!(
            ".harnessc/bundles/{}",
            playbook_ref.trim_start_matches("sha256:")
        )),
        "the bundle directory is addressed by the playbook ref"
    );
    // ...and that copy is the COMPLETE coherent bundle, not a mirror of
    // whatever landed: spot-check both ends of the set.
    assert!(bundle.join("CLAUDE.md").exists());
    assert!(bundle.join(MANIFEST_PATH).exists());
    assert!(bundle.join(SKILL_PATH).exists());

    // The live tree verifies, pointer included.
    assert!(harnessc(&["verify"], &v1, &out).status.success());
}

#[test]
fn previous_bundle_is_retained_for_rollback_and_older_pruned() {
    let dir = scratch("prune");
    let out = dir.join("out");
    let v1 = write_spec(&dir, "v1.yaml", SPEC_WITH_SPECIALIST);
    let v2 = write_spec(&dir, "v2.yaml", SPEC_WITHOUT_SPECIALIST);

    assert!(harnessc(&["build"], &v1, &out).status.success());
    let ref_a = current_pointer(&out)["playbook_ref"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(harnessc(&["build"], &v2, &out).status.success());
    let ref_b = current_pointer(&out)["playbook_ref"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(ref_a, ref_b);

    let bundles = out.join(".harnessc/bundles");
    let dirs = |bundles: &Path| -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(bundles)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    };
    // Current + previous retained: the previous bundle is the rollback source.
    let hex = |r: &str| r.trim_start_matches("sha256:").to_string();
    assert_eq!(dirs(&bundles), {
        let mut v = vec![hex(&ref_a), hex(&ref_b)];
        v.sort();
        v
    });

    // A third build (back to v1) keeps {new, previous}: nothing unbounded.
    assert!(harnessc(&["build"], &v1, &out).status.success());
    assert_eq!(dirs(&bundles).len(), 2, "retention is exactly two versions");
    assert_eq!(current_pointer(&out)["playbook_ref"], ref_a.as_str());
}

#[test]
fn verify_flags_a_stale_current_pointer() {
    let dir = scratch("pointer");
    let out = dir.join("out");
    let v1 = write_spec(&dir, "v1.yaml", SPEC_WITH_SPECIALIST);
    assert!(harnessc(&["build"], &v1, &out).status.success());

    // A pointer naming some other promotion: live tree and recorded promotion
    // now disagree, which verification must surface.
    let pointer = out.join(".harnessc/current");
    let doctored = std::fs::read_to_string(&pointer)
        .unwrap()
        .replace("sha256:", "sha256:0000");
    std::fs::write(&pointer, doctored).unwrap();

    let verified = harnessc(&["verify"], &v1, &out);
    assert!(!verified.status.success(), "a stale pointer fails verify");
    assert!(
        String::from_utf8_lossy(&verified.stderr).contains("pointer"),
        "named as a pointer problem"
    );
}

/// Run `harnessc restore` (no --spec: restore works from the retained copy).
fn restore(args: &[&str], out: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_harnessc"))
        .arg("restore")
        .arg("--out")
        .arg(out)
        .args(args)
        .output()
        .expect("harnessc runs")
}

#[test]
fn restore_rolls_the_live_tree_back_and_forward() {
    let dir = scratch("restore");
    let out = dir.join("out");
    let v1 = write_spec(&dir, "v1.yaml", SPEC_WITH_SPECIALIST);
    let v2 = write_spec(&dir, "v2.yaml", SPEC_WITHOUT_SPECIALIST);

    assert!(harnessc(&["build"], &v1, &out).status.success());
    let ref_a = current_pointer(&out)["playbook_ref"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(harnessc(&["build"], &v2, &out).status.success());
    let ref_b = current_pointer(&out)["playbook_ref"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!out.join(SKILL_PATH).exists(), "v2 retired the skill");

    // --list shows both retained versions and marks the current one.
    let listed = restore(&["--list"], &out);
    assert!(listed.status.success());
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(stdout.contains(&ref_a) && stdout.contains(&ref_b));
    assert!(
        stdout
            .lines()
            .any(|l| l.contains(&ref_b) && l.contains("(current)")),
        "the active version is marked: {stdout}"
    );

    // Roll BACK to v1 by unique prefix: the retired artifact returns, the
    // pointer follows, and the tree verifies against the v1 spec again.
    let prefix = &ref_a.trim_start_matches("sha256:")[..12];
    let rolled = restore(&["--playbook", prefix], &out);
    assert!(
        rolled.status.success(),
        "{}",
        String::from_utf8_lossy(&rolled.stderr)
    );
    assert!(out.join(SKILL_PATH).exists(), "the rollback restored it");
    assert_eq!(current_pointer(&out)["playbook_ref"], ref_a.as_str());
    assert!(harnessc(&["verify"], &v1, &out).status.success());

    // Roll FORWARD to v2 again: restore retires what the restored bundle
    // lacks, exactly as a build would.
    let rolled = restore(&["--playbook", &ref_b], &out);
    assert!(rolled.status.success());
    assert!(
        !out.join(SKILL_PATH).exists(),
        "restore retires files outside the restored set"
    );
    assert!(harnessc(&["verify"], &v2, &out).status.success());
}

#[test]
fn restore_refuses_a_corrupt_retained_bundle() {
    let dir = scratch("restore-corrupt");
    let out = dir.join("out");
    let v1 = write_spec(&dir, "v1.yaml", SPEC_WITH_SPECIALIST);
    let v2 = write_spec(&dir, "v2.yaml", SPEC_WITHOUT_SPECIALIST);

    assert!(harnessc(&["build"], &v1, &out).status.success());
    let ref_a = current_pointer(&out)["playbook_ref"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(harnessc(&["build"], &v2, &out).status.success());

    // Tamper the retained copy of v1: a rollback source that cannot prove
    // itself is not a rollback source.
    let retained_skill = out
        .join(".harnessc/bundles")
        .join(ref_a.trim_start_matches("sha256:"))
        .join(SKILL_PATH);
    let text = std::fs::read_to_string(&retained_skill).unwrap();
    std::fs::write(&retained_skill, text + "tampered\n").unwrap();

    let rolled = restore(&["--playbook", &ref_a], &out);
    assert!(
        !rolled.status.success(),
        "a corrupt bundle must not restore"
    );
    assert!(
        String::from_utf8_lossy(&rolled.stderr).contains("corrupt"),
        "the refusal names the corruption"
    );
    // The live tree was never touched: still v2, still verifying.
    assert!(harnessc(&["verify"], &v2, &out).status.success());
}

#[test]
fn manifest_inventories_every_file_except_itself() {
    let dir = scratch("inventory");
    let out = dir.join("out");
    let v1 = write_spec(&dir, "v1.yaml", SPEC_WITH_SPECIALIST);
    assert!(harnessc(&["build"], &v1, &out).status.success());

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join(MANIFEST_PATH)).unwrap()).unwrap();
    let files = manifest["files"].as_array().unwrap();
    assert!(!files.is_empty());
    for f in files {
        let path = f["path"].as_str().unwrap();
        assert_ne!(path, MANIFEST_PATH, "the manifest cannot list itself");
        assert!(f["digest"].as_str().unwrap().starts_with("sha256:"));
        let mode = f["mode"].as_str().unwrap();
        if path.ends_with(".sh") {
            assert_eq!(mode, "0755", "{path}");
        } else {
            assert_eq!(mode, "0644", "{path}");
        }
        assert_eq!(f["type"], "regular");
    }
    // The set is exactly the rest of the bundle: spot-check both a hook and
    // the playbook manifest are inventoried.
    let paths: Vec<&str> = files.iter().map(|f| f["path"].as_str().unwrap()).collect();
    assert!(paths.contains(&"harness/hooks/enforce_file_scope.sh"));
    assert!(paths.contains(&"harness/playbook.json"));
}
