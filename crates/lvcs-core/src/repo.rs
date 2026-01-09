use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::util::atomic_write;

pub const REPO_DIR_NAME: &str = ".lvcs";
pub const LEGACY_REPO_DIR_NAME: &str = ".repo";
pub const OBJECTS_DIR: &str = "objects";
pub const REFS_DIR: &str = "refs";
pub const HEADS_DIR: &str = "heads";
pub const PACK_DIR: &str = "pack";
pub const TMP_DIR: &str = "tmp";
pub const HEAD_FILE: &str = "HEAD";
pub const MERGE_STATE_FILE: &str = "MERGE_STATE";
pub const DEFAULT_HEAD_REF: &str = "ref: refs/heads/main\n";

#[derive(Debug, Error)]
pub enum RepoError {
    #[error("repository already initialized at {0}")]
    AlreadyInitialized(PathBuf),
    #[error("no repository found at {0}")]
    NotFound(PathBuf),
}

#[derive(Clone, Debug)]
pub struct Repo {
    worktree: PathBuf,
    repo_dir: PathBuf,
}

impl Repo {
    pub fn init(worktree: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = worktree.as_ref();
        if !root.exists() {
            fs::create_dir_all(root)?;
        }

        let repo_dir = root.join(REPO_DIR_NAME);
        if repo_dir.exists() {
            return Err(RepoError::AlreadyInitialized(repo_dir).into());
        }

        fs::create_dir_all(repo_dir.join(OBJECTS_DIR))?;
        fs::create_dir_all(repo_dir.join(REFS_DIR).join(HEADS_DIR))?;
        fs::create_dir_all(repo_dir.join(PACK_DIR))?;
        fs::create_dir_all(repo_dir.join(TMP_DIR))?;
        atomic_write(&repo_dir.join(HEAD_FILE), DEFAULT_HEAD_REF.as_bytes())?;

        Ok(Self {
            worktree: root.to_path_buf(),
            repo_dir,
        })
    }

    pub fn open(worktree: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = worktree.as_ref();

        let repo_dir = root.join(REPO_DIR_NAME);
        let legacy_repo_dir = root.join(LEGACY_REPO_DIR_NAME);

        if repo_dir.exists() {
            return Ok(Self {
                worktree: root.to_path_buf(),
                repo_dir,
            });
        }

        if legacy_repo_dir.exists() {
            fs::rename(&legacy_repo_dir, &repo_dir)?;
            return Ok(Self {
                worktree: root.to_path_buf(),
                repo_dir,
            });
        }

        Err(RepoError::NotFound(repo_dir).into())
    }

    pub fn worktree(&self) -> &Path {
        &self.worktree
    }

    pub fn repo_dir(&self) -> &Path {
        &self.repo_dir
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.repo_dir.join(OBJECTS_DIR)
    }

    pub fn pack_dir(&self) -> PathBuf {
        self.repo_dir.join(PACK_DIR)
    }

    pub fn refs_dir(&self) -> PathBuf {
        self.repo_dir.join(REFS_DIR)
    }

    pub fn heads_dir(&self) -> PathBuf {
        self.repo_dir.join(REFS_DIR).join(HEADS_DIR)
    }

    pub fn head_path(&self) -> PathBuf {
        self.repo_dir.join(HEAD_FILE)
    }
}

pub fn init_repo(worktree: impl AsRef<Path>) -> anyhow::Result<()> {
    Repo::init(worktree).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_creates_repo_layout() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let root = temp_dir.path();

        Repo::init(root).expect("init repo");

        assert!(root.join(REPO_DIR_NAME).is_dir());
        assert!(root.join(REPO_DIR_NAME).join(OBJECTS_DIR).is_dir());
        assert!(root
            .join(REPO_DIR_NAME)
            .join(REFS_DIR)
            .join(HEADS_DIR)
            .is_dir());
        assert!(root.join(REPO_DIR_NAME).join(PACK_DIR).is_dir());
        assert!(root.join(REPO_DIR_NAME).join(TMP_DIR).is_dir());
        assert_eq!(
            fs::read(root.join(REPO_DIR_NAME).join(HEAD_FILE)).expect("head file"),
            DEFAULT_HEAD_REF.as_bytes()
        );
    }

    #[test]
    fn open_migrates_legacy_repo_dir_name() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let root = temp_dir.path();

        Repo::init(root).expect("init repo");

        let new_dir = root.join(REPO_DIR_NAME);
        let legacy_dir = root.join(LEGACY_REPO_DIR_NAME);
        fs::rename(&new_dir, &legacy_dir).expect("rename to legacy");

        let repo = Repo::open(root).expect("open repo");
        assert_eq!(repo.repo_dir(), root.join(REPO_DIR_NAME));
        assert!(!legacy_dir.exists());
        assert!(new_dir.exists());
    }

    #[test]
    fn init_fails_if_repo_exists() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let root = temp_dir.path();

        Repo::init(root).expect("init repo");
        let err = Repo::init(root).expect_err("should fail");

        let message = format!("{err}");
        assert!(message.contains("already initialized"));
    }
}
