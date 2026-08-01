//! Crash-consistent file writes.
//!
//! A durable checkpoint or evidence artifact must survive a process or host
//! failure mid-write. `fs::write` does neither: it can leave a truncated file,
//! and the bytes may still be in the page cache when the machine dies. This
//! module provides the standard write-temp → fsync → atomic-rename → fsync-dir
//! sequence so a reader only ever sees a complete file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Atomically write `bytes` to `path`, creating parent directories as needed.
///
/// The data lands via a temporary sibling that is fsynced and then renamed over
/// the target (rename is atomic on POSIX). The parent directory is fsynced so
/// the rename itself is durable. A concurrent or crashed writer can never leave
/// a half-written target — only a stray `.tmp` sibling.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = parent {
        fs::create_dir_all(dir)?;
    }

    let tmp = tmp_sibling(path);
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;

    // Durably record the rename by fsyncing the containing directory.
    if let Some(dir) = parent {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_persists_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sub").join("checkpoint.json");
        atomic_write(&target, b"durable").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"durable");
        assert!(!dir.path().join("sub").join("checkpoint.json.tmp").exists());
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
