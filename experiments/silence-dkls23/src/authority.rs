//! Cooperating processes on one honest, local Unix filesystem only.
//! Advisory locks do not fence hostile hosts, independent replicas or snapshots.
use anyhow::{ensure, Context, Result};
use std::{
    fs::{self, File, OpenOptions},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

/// A fresh open-file description per operation is essential: sharing a descriptor
/// would allow threads to share a flock instead of excluding each other.
pub(crate) struct AuthorityLock {
    // Closing this owned descriptor releases the lock, including unwind/SIGKILL.
    _file: File,
}
impl AuthorityLock {
    pub(crate) fn acquire(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        // Never unlink/replace this file. All processes must lock the same inode.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir.join(".authority.lock"))
            .context("open local authority lock")?;
        ensure!(file.metadata()?.is_file(), "invalid authority lock file");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            // SAFETY: file owns a valid descriptor for this entire operation.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self { _file: file });
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock
                && error.kind() != std::io::ErrorKind::Interrupted
            {
                return Err(error).context("lock local authority");
            }
            ensure!(Instant::now() < deadline, "local authority lock timed out");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
