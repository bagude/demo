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

/// Re-express an absolute path as workspace-relative, or `None` if it lies
/// outside the root. The textual prefix may differ from the canonical root
/// (a symlinked working directory), so after the cheap lexical strip this
/// resolves the path's own canonical form — or its parent's, for a
/// not-yet-existing target — before giving up. Symlink *content* is not
/// trusted here: the caller's component walk re-resolves every link.
fn rebase_into_root(root_canon: &Path, path: &str) -> Option<String> {
    let p = Path::new(path);
    let to_rel = |rel: &Path| -> String {
        rel.components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    };
    if let Ok(rel) = p.strip_prefix(root_canon) {
        return Some(to_rel(rel));
    }
    if let Ok(canon) = fs::canonicalize(p) {
        if let Ok(rel) = canon.strip_prefix(root_canon) {
            return Some(to_rel(rel));
        }
    }
    if let (Some(parent), Some(name)) = (p.parent(), p.file_name()) {
        if let Ok(parent_canon) = fs::canonicalize(parent) {
            if let Ok(rel) = parent_canon.join(name).strip_prefix(root_canon) {
                return Some(to_rel(rel));
            }
        }
    }
    None
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

/// Resolve a workspace-relative path to its **canonical** workspace-relative
/// form: the existing portion is walked component by component with symlinks
/// followed fully, and the non-existing tail (already lexically normalized —
/// no `..`, no absolute) is appended as-is. Returns `Err` with the denial
/// reason when the path resolves outside the workspace root (a symlink
/// escape) or writes through a dangling symlink (the write would land at an
/// unvetted target).
///
/// This is what makes scope authority hold on the *real* filesystem rather
/// than on spelling: lexical checks alone cannot see that `src/link.rs` IS
/// `harness/hooks/x.sh`. Case aliasing is normalized where the platform's
/// `canonicalize` reports on-disk casing (best-effort by construction; on
/// case-sensitive filesystems there is nothing to normalize).
pub fn canonical_workspace_rel(root: &Path, path: &str) -> Result<String, String> {
    let root_canon = fs::canonicalize(root)
        .map_err(|e| format!("workspace root cannot be canonicalized: {e}"))?;

    // Platform file tools address their targets ABSOLUTELY. An absolute path
    // inside the workspace root asks the same authority question as its
    // relative form — rebase it and judge normally; one outside the root is
    // refused. Found live, not mechanically: the first armed session blocked
    // every legitimate edit because the platform's payloads are absolute
    // while this judgment was relative-only — and the conformance suite,
    // driving relative payloads, stayed green throughout. (The suite now
    // drives absolute payloads too.)
    let rebased;
    let path = if Path::new(path).is_absolute() {
        match rebase_into_root(&root_canon, path) {
            Some(rel) => {
                rebased = rel;
                rebased.as_str()
            }
            None => {
                return Err(format!(
                    "'{path}' is outside the workspace root; such paths are never authorized"
                ))
            }
        }
    } else {
        path
    };

    let Some(components) = crate::packet::normalize_components(path) else {
        return Err(format!(
            "'{path}' is absolute or escapes the workspace root; such paths are never authorized"
        ));
    };

    // Walk the deepest existing prefix, following symlinks as they appear so
    // every later component is resolved relative to the REAL directory.
    let mut existing = root_canon.clone();
    let mut resolved_upto = 0;
    for (i, comp) in components.iter().enumerate() {
        let next = existing.join(comp);
        match fs::symlink_metadata(&next) {
            Ok(md) if md.file_type().is_symlink() => {
                existing = fs::canonicalize(&next).map_err(|_| {
                    format!(
                        "'{}' is a dangling symlink; refusing to write through it",
                        components[..=i].join("/")
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
        format!(
            "'{path}' resolves outside the workspace ({}); a symlink must not launder an \
             out-of-scope target into an authorized name",
            target.display()
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
    fn absolute_paths_inside_the_root_are_rebased_not_refused() {
        // The platform's file tools speak absolute paths. Judged authority
        // must be identical for the absolute and relative spellings of the
        // same target — the live trial found the absolute form refused
        // wholesale while the relative-only mechanical suite stayed green.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("docs")).unwrap();
        std::fs::write(dir.path().join("docs/notes.md"), b"x").unwrap();

        let abs = dir.path().join("docs/notes.md");
        let via_abs = canonical_workspace_rel(dir.path(), abs.to_str().unwrap()).unwrap();
        let via_rel = canonical_workspace_rel(dir.path(), "docs/notes.md").unwrap();
        assert_eq!(via_abs, "docs/notes.md");
        assert_eq!(via_abs, via_rel, "one target, one judgment");

        // A not-yet-existing target rebases through its parent.
        let abs_new = dir.path().join("docs/new.md");
        assert_eq!(
            canonical_workspace_rel(dir.path(), abs_new.to_str().unwrap()).unwrap(),
            "docs/new.md"
        );
    }

    #[test]
    fn absolute_paths_outside_the_root_stay_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = canonical_workspace_rel(dir.path(), "/etc/hostname").unwrap_err();
        assert!(err.contains("outside the workspace root"), "{err}");
    }

    #[test]
    fn an_absolute_symlink_name_still_resolves_to_its_real_target() {
        // Rebasing must not launder: the in-root NAME is rebased, then the
        // component walk resolves the link and the out-of-root target is
        // refused exactly as with a relative spelling.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("docs")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", dir.path().join("docs/link.md")).unwrap();
        let abs = dir.path().join("docs/link.md");
        let err = canonical_workspace_rel(dir.path(), abs.to_str().unwrap()).unwrap_err();
        assert!(err.contains("resolves outside the workspace"), "{err}");
    }
}
