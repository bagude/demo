//! Crash-consistent file writes.
//!
//! A durable checkpoint or evidence artifact must survive a process or host
//! failure mid-write. `fs::write` does neither: it can leave a truncated file,
//! and the bytes may still be in the page cache when the machine dies. This
//! module provides the standard write-temp → fsync → atomic-rename → fsync-dir
//! sequence so a reader only ever sees a complete file.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Atomically write `bytes` to `path`, creating parent directories as needed.
///
/// The data lands via a **uniquely named** temporary sibling opened with
/// `create_new` (so two concurrent writers never share a temp file), fsynced,
/// then renamed over the target (rename is atomic on POSIX). On Unix the parent
/// directory is fsynced so the rename is durable, and that fsync's failure is
/// propagated — the durability guarantee is not silently dropped. A concurrent
/// or crashed writer can never leave a half-written target.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = parent {
        fs::create_dir_all(dir)?;
    }

    let tmp = unique_tmp_sibling(path);
    let write_result = (|| {
        let mut f = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // Durably record the rename by fsyncing the containing directory (Unix).
    #[cfg(unix)]
    if let Some(dir) = parent {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// A same-directory temp name unique to this process and call, so concurrent
/// writers to the same target never collide on the temp file.
fn unique_tmp_sibling(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{}.{}.tmp", std::process::id(), n));
    PathBuf::from(s)
}

/// A path-authority refusal: a stable machine-readable `code` (recorded to
/// the Ledger as `policy:<code>`) plus the human-readable reason. The code is
/// what makes denials analyzable; the prose is what makes them explainable.
pub type PathDenial = (&'static str, String);

/// Stable denial codes for path-authority failures.
pub mod codes {
    /// Absolute, `..`-escaping, or Windows-shaped path — never authorized.
    pub const PATH_INVALID: &str = "path.invalid";
    /// A platform-absolute path pointing outside the workspace root.
    pub const PATH_OUTSIDE_WORKSPACE: &str = "path.outside_workspace";
    /// The path resolves (through a symlink) outside the workspace root.
    pub const PATH_SYMLINK_ESCAPE: &str = "path.symlink_escape";
    /// The path writes through a dangling symlink.
    pub const PATH_DANGLING_SYMLINK: &str = "path.dangling_symlink";
    /// The workspace root itself could not be resolved.
    pub const WORKSPACE_UNRESOLVABLE: &str = "workspace.unresolvable";
}

/// Rebind a platform-shaped (absolute) path to its workspace-relative form,
/// or pass a relative path through untouched.
///
/// Tool harnesses hand the kernel absolute host paths
/// (`/home/user/ws/docs/notes.md`); policy is written over workspace-relative
/// ones (`docs/notes.md`). This is the boundary where the platform shape is
/// converted — an absolute path *inside* the workspace becomes its relative
/// form and is judged by the same Laws as any other, while an absolute path
/// *outside* the workspace is refused outright. Without this, every
/// platform-shaped edit is denied as "absolute", which reads as governance
/// but is actually an interface defect (the self-trial's first finding).
pub fn workspace_relative(root: &Path, path: &str) -> Result<String, PathDenial> {
    if !Path::new(path).is_absolute() && !path.starts_with('/') {
        return Ok(path.to_string());
    }
    let root_canon = fs::canonicalize(root).map_err(|e| {
        (
            codes::WORKSPACE_UNRESOLVABLE,
            format!("workspace root cannot be canonicalized: {e}"),
        )
    })?;
    // The supplied prefix may spell the root through a symlink; canonicalize
    // the deepest existing prefix of the path so the comparison is between
    // real locations, not spellings.
    let supplied = Path::new(path);
    let (existing, tail) = deepest_existing_prefix(supplied);
    let existing_canon = fs::canonicalize(&existing).unwrap_or(existing);
    let real = existing_canon.join(tail);
    match real.strip_prefix(&root_canon) {
        Ok(rel) => Ok(rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")),
        Err(_) => Err((
            codes::PATH_OUTSIDE_WORKSPACE,
            format!(
                "'{path}' is outside the workspace root ({}); the Guard only ever \
                 authorizes workspace files",
                root_canon.display()
            ),
        )),
    }
}

/// Split a path into its deepest existing ancestor and the non-existing tail.
fn deepest_existing_prefix(path: &Path) -> (PathBuf, PathBuf) {
    let mut existing = path.to_path_buf();
    let mut tail = PathBuf::new();
    while !existing.exists() {
        let Some(parent) = existing.parent() else {
            break;
        };
        let name = existing.file_name().map(PathBuf::from).unwrap_or_default();
        tail = if tail.as_os_str().is_empty() {
            name
        } else {
            name.join(&tail)
        };
        existing = parent.to_path_buf();
    }
    (existing, tail)
}

/// Resolve a workspace-relative path to its **canonical** workspace-relative
/// form: the existing portion is walked component by component with symlinks
/// followed fully, and the non-existing tail (already lexically normalized —
/// no `..`, no absolute) is appended as-is. Returns `Err` with a stable
/// denial code and reason when the path resolves outside the workspace root
/// (a symlink escape) or writes through a dangling symlink (the write would
/// land at an unvetted target).
///
/// This is what makes scope authority hold on the *real* filesystem rather
/// than on spelling: lexical checks alone cannot see that `src/link.rs` IS
/// `harness/hooks/x.sh`. Case aliasing is normalized where the platform's
/// `canonicalize` reports on-disk casing (best-effort by construction; on
/// case-sensitive filesystems there is nothing to normalize).
pub fn canonical_workspace_rel(root: &Path, path: &str) -> Result<String, PathDenial> {
    let Some(components) = crate::packet::normalize_components(path) else {
        return Err((
            codes::PATH_INVALID,
            format!(
                "'{path}' is absolute or escapes the workspace root; such paths are never authorized"
            ),
        ));
    };
    let root_canon = fs::canonicalize(root).map_err(|e| {
        (
            codes::WORKSPACE_UNRESOLVABLE,
            format!("workspace root cannot be canonicalized: {e}"),
        )
    })?;

    // Walk the deepest existing prefix, following symlinks as they appear so
    // every later component is resolved relative to the REAL directory.
    let mut existing = root_canon.clone();
    let mut resolved_upto = 0;
    for (i, comp) in components.iter().enumerate() {
        let next = existing.join(comp);
        match fs::symlink_metadata(&next) {
            Ok(md) if md.file_type().is_symlink() => {
                existing = fs::canonicalize(&next).map_err(|_| {
                    (
                        codes::PATH_DANGLING_SYMLINK,
                        format!(
                            "'{}' is a dangling symlink; refusing to write through it",
                            components[..=i].join("/")
                        ),
                    )
                })?;
                resolved_upto = i + 1;
            }
            Ok(_) => {
                existing = next;
                resolved_upto = i + 1;
            }
            Err(_) => break,
        }
    }
    // One more canonicalize of the existing prefix: fixes on-disk casing on
    // platforms that report it (no-op elsewhere; the prefix exists).
    if resolved_upto > 0 {
        if let Ok(c) = fs::canonicalize(&existing) {
            existing = c;
        }
    }

    let mut target = existing;
    for comp in &components[resolved_upto..] {
        target = target.join(comp);
    }
    let rel = target.strip_prefix(&root_canon).map_err(|_| {
        (
            codes::PATH_SYMLINK_ESCAPE,
            format!(
                "'{path}' resolves outside the workspace ({}); a symlink must not launder an \
                 out-of-scope target into an authorized name",
                target.display()
            ),
        )
    })?;
    Ok(rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_persists_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        let target = sub.join("checkpoint.json");
        atomic_write(&target, b"durable").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"durable");
        // No stray temp files of any name remain.
        let leftovers: Vec<_> = std::fs::read_dir(&sub)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[test]
    fn atomic_write_overwrites_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("x");
        atomic_write(&target, b"first").unwrap();
        atomic_write(&target, b"second").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second");
    }

    #[test]
    fn workspace_relative_rebinds_an_absolute_path_inside_the_root() {
        // The self-trial's first finding: the platform hands the kernel
        // absolute paths, and refusing them as "absolute" blocks every
        // legitimate edit. Inside the root, the platform shape rebinds to the
        // workspace-relative name policy is written over.
        let ws = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(ws.path().join("docs")).unwrap();
        let abs = ws.path().join("docs/notes.md");
        let rel = workspace_relative(ws.path(), abs.to_str().unwrap()).unwrap();
        assert_eq!(rel, "docs/notes.md");
        // A not-yet-existing target rebinds the same way.
        let abs_new = ws.path().join("docs/new/deep.md");
        let rel = workspace_relative(ws.path(), abs_new.to_str().unwrap()).unwrap();
        assert_eq!(rel, "docs/new/deep.md");
    }

    #[test]
    fn workspace_relative_refuses_an_absolute_path_outside_the_root() {
        let ws = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("x.rs");
        let (code, reason) =
            workspace_relative(ws.path(), target.to_str().unwrap()).unwrap_err();
        assert_eq!(code, codes::PATH_OUTSIDE_WORKSPACE);
        assert!(reason.contains("outside the workspace root"));
    }

    #[test]
    fn workspace_relative_passes_relative_paths_through() {
        let ws = tempfile::tempdir().unwrap();
        assert_eq!(
            workspace_relative(ws.path(), "src/lib.rs").unwrap(),
            "src/lib.rs"
        );
        // Even a `..`-escape passes through untouched here: shape conversion
        // is not authority — normalize_components / canonical_workspace_rel
        // still refuse it downstream.
        assert_eq!(workspace_relative(ws.path(), "../x").unwrap(), "../x");
    }

    #[test]
    fn canonical_errors_carry_stable_codes() {
        let ws = tempfile::tempdir().unwrap();
        let (code, _) = canonical_workspace_rel(ws.path(), "/etc/passwd").unwrap_err();
        assert_eq!(code, codes::PATH_INVALID);
        let (code, _) = canonical_workspace_rel(ws.path(), "a/../../x").unwrap_err();
        assert_eq!(code, codes::PATH_INVALID);
    }
}
