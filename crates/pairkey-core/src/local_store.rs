//! Single-host persistence only. This is not authority, replica fencing or rollback protection.
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
};

pub struct LocalStore {
    path: PathBuf,
    _lock: File,
    max_bytes: usize,
}
impl LocalStore {
    pub fn open(path: impl AsRef<Path>, max_bytes: usize) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(lock_path)?;
        // SAFETY: the descriptor is owned by `lock`, and is retained for this store's lifetime.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            path,
            _lock: lock,
            max_bytes,
        })
    }
    pub fn read(&self) -> io::Result<Option<Vec<u8>>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("store must be a regular file"));
        }
        let mut bytes = Vec::new();
        file.take(self.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > self.max_bytes {
            return Err(io::Error::other("store size limit"));
        }
        Ok(Some(bytes))
    }
    pub fn write(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > self.max_bytes {
            return Err(io::Error::other("store size limit"));
        }
        let mut temp = self.path.as_os_str().to_os_string();
        temp.push(".next");
        // The exclusive store lock owns this staging name, including after a crash.
        match std::fs::remove_file(&temp) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, &self.path)?;
        File::open(
            self.path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()
    }
}
