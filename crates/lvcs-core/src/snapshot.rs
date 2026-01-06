use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use crate::chunking::{chunk_file, CHUNK_SIZE};
use crate::ignore::LvcsIgnore;
use crate::object::{Commit, Manifest, ObjectData, Tree, TreeEntry, TreeEntryKind};
use crate::oid::Oid;
use crate::repo::Repo;
use crate::store::Store;

pub fn snapshot_worktree(repo: &Repo, store: &Store) -> anyhow::Result<Oid> {
    let ignore = LvcsIgnore::load(repo.worktree())?;
    build_tree(repo.worktree(), store, &ignore)
}

fn build_tree(dir: &Path, store: &Store, ignore: &LvcsIgnore) -> anyhow::Result<Oid> {
    let mut entries = Vec::new();
    let mut dir_entries = Vec::new();
    for entry in fs::read_dir(dir)? {
        dir_entries.push(entry?);
    }

    dir_entries.sort_by(|a, b| cmp_os(a.file_name().as_ref(), b.file_name().as_ref()));

    for entry in dir_entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if ignore.is_ignored(&path, file_type.is_dir()) {
            continue;
        }
        let name = entry.file_name();
        let name_bytes = os_bytes(name.as_os_str());

        if file_type.is_dir() {
            let oid = build_tree(&path, store, ignore)?;
            let mode = dir_mode(&path)?;
            entries.push(TreeEntry {
                name: name_bytes,
                kind: TreeEntryKind::Dir,
                mode,
                oid,
            });
        } else if file_type.is_symlink() {
            let target = fs::read_link(&path)?;
            let target_bytes = os_bytes(target.as_os_str());
            let oid = store.write_object(&ObjectData::Chunk(target_bytes))?;
            let mode = symlink_mode(&path)?;
            entries.push(TreeEntry {
                name: name_bytes,
                kind: TreeEntryKind::Symlink,
                mode,
                oid,
            });
        } else if file_type.is_file() {
            let manifest = build_manifest(&path, store)?;
            let oid = store.write_object(&ObjectData::Manifest(manifest))?;
            let mode = file_mode(&path)?;
            entries.push(TreeEntry {
                name: name_bytes,
                kind: TreeEntryKind::File,
                mode,
                oid,
            });
        }
    }

    let tree = Tree { entries };
    store.write_object(&ObjectData::Tree(tree))
}

fn build_manifest(path: &Path, store: &Store) -> anyhow::Result<Manifest> {
    let mut chunks = Vec::new();
    let file_len = chunk_file(path, |chunk| {
        let oid = store.write_object(&ObjectData::Chunk(chunk.to_vec()))?;
        chunks.push(oid);
        Ok(())
    })?;
    let mode = file_mode(path)?;
    Ok(Manifest {
        file_len,
        mode,
        chunk_size: CHUNK_SIZE as u32,
        chunks,
    })
}

pub fn build_commit(
    root: Oid,
    parents: Vec<Oid>,
    author: String,
    timestamp: i64,
    message: String,
) -> Commit {
    Commit {
        root,
        parents,
        author,
        timestamp,
        message,
    }
}

fn cmp_os(a: &OsStr, b: &OsStr) -> Ordering {
    os_bytes(a).cmp(&os_bytes(b))
}

fn os_bytes(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        value.to_string_lossy().as_bytes().to_vec()
    }
}

fn file_mode(path: &Path) -> anyhow::Result<u32> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(metadata.mode())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(0)
    }
}

fn dir_mode(path: &Path) -> anyhow::Result<u32> {
    file_mode(path)
}

fn symlink_mode(path: &Path) -> anyhow::Result<u32> {
    file_mode(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectData;
    use crate::repo::Repo;
    use crate::store::Store;

    #[test]
    fn snapshot_respects_ignore() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        Repo::init(root).expect("init");
        fs::write(root.join("keep.txt"), b"ok").expect("write");
        fs::write(root.join("ignore.txt"), b"no").expect("write");
        fs::write(root.join(".lvcsignore"), b"ignore.txt\n").expect("ignore");

        let repo = Repo::open(root).expect("open");
        let store = Store::new(repo.clone());
        let tree_oid = snapshot_worktree(&repo, &store).expect("snapshot");
        let (_kind, data) = store.read_object(&tree_oid).expect("read");
        let tree = match data {
            ObjectData::Tree(tree) => tree,
            _ => panic!("expected tree"),
        };
        let names: Vec<Vec<u8>> = tree.entries.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&b"keep.txt".to_vec()));
        assert!(!names.contains(&b"ignore.txt".to_vec()));
    }
}
