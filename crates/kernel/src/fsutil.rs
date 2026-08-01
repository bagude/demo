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
}
