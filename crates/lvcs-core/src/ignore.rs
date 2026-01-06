use std::path::{Component, Path, PathBuf};

use ignore::gitignore::{Gitignore, GitignoreBuilder};

pub struct LvcsIgnore {
    root: PathBuf,
    gitignore: Gitignore,
}

impl LvcsIgnore {
    pub fn load(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = root.as_ref().to_path_buf();
        let mut builder = GitignoreBuilder::new(&root);
        builder.add(root.join(".lvcsignore"));
        let gitignore = builder.build()?;
        Ok(Self { root, gitignore })
    }

    pub fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        if let Ok(rel) = path.strip_prefix(&self.root) {
            if contains_repo_dir(rel) {
                return true;
            }
            self.gitignore.matched(rel, is_dir).is_ignore()
        } else {
            false
        }
    }
}

fn contains_repo_dir(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component,
            Component::Normal(name) if name == crate::repo::REPO_DIR_NAME
        )
    })
}
