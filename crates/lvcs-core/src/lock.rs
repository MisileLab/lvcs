use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use fs2::FileExt;

pub struct RepoLock {
    file: File,
    _path: PathBuf,
}

impl RepoLock {
    pub fn acquire(repo_dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(repo_dir)?;
        let path = repo_dir.join("LOCK");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        file.lock_exclusive()?;
        Ok(Self { file, _path: path })
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
