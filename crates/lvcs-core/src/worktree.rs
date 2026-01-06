use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crate::ignore::LvcsIgnore;
use crate::object::{Manifest, ObjectData, Tree, TreeEntry, TreeEntryKind};
use crate::oid::Oid;
use crate::repo::Repo;
use crate::store::Store;

pub fn checkout(repo: &Repo, store: &Store, root: &Oid, force: bool) -> anyhow::Result<()> {
    let tree = read_tree(store, root)?;
    let target = build_tree_map(&tree, store, PathBuf::new())?;
    let ignore = LvcsIgnore::load(repo.worktree())?;

    if !force && is_dirty(repo.worktree(), &target, store, &ignore)? {
        anyhow::bail!("worktree has uncommitted changes");
    }

    if force {
        remove_untracked(repo.worktree(), &target, &ignore)?;
    }

    restore_tree(repo.worktree(), &target, store)?;
    Ok(())
}

pub fn is_dirty(
    root: &Path,
    target: &HashMap<PathBuf, TreeEntry>,
    store: &Store,
    ignore: &LvcsIgnore,
) -> anyhow::Result<bool> {
    let mut seen = BTreeSet::new();
    for (path, entry) in target {
        seen.insert(path.clone());
        let full = root.join(path);
        if !full.exists() {
            return Ok(true);
        }
        match entry.kind {
            TreeEntryKind::Dir => {
                if !full.is_dir() {
                    return Ok(true);
                }
            }
            TreeEntryKind::File => {
                if !full.is_file() {
                    return Ok(true);
                }
                if !file_matches(store, entry, &full)? {
                    return Ok(true);
                }
            }
            TreeEntryKind::Symlink => {
                if !full.is_symlink() {
                    return Ok(true);
                }
                if !symlink_matches(store, entry, &full)? {
                    return Ok(true);
                }
            }
        }
    }

    for path in walk_paths(root, ignore)? {
        if !seen.contains(&path) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn remove_untracked(
    root: &Path,
    target: &HashMap<PathBuf, TreeEntry>,
    ignore: &LvcsIgnore,
) -> anyhow::Result<()> {
    let mut paths: Vec<PathBuf> = walk_paths(root, ignore)?
        .into_iter()
        .filter(|path| !target.contains_key(path))
        .collect();
    paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for rel in paths {
        let full = root.join(&rel);
        if full.is_dir() {
            fs::remove_dir(&full)?;
        } else {
            fs::remove_file(&full)?;
        }
    }
    Ok(())
}

fn restore_tree(
    root: &Path,
    target: &HashMap<PathBuf, TreeEntry>,
    store: &Store,
) -> anyhow::Result<()> {
    let mut entries: Vec<_> = target.iter().collect();
    entries.sort_by(|(a, _), (b, _)| a.components().count().cmp(&b.components().count()));

    for (path, entry) in entries {
        let full = root.join(path);
        match entry.kind {
            TreeEntryKind::Dir => {
                fs::create_dir_all(&full)?;
            }
            TreeEntryKind::File => {
                if let Some(parent) = full.parent() {
                    fs::create_dir_all(parent)?;
                }
                let bytes = read_manifest_bytes(store, &entry.oid)?;
                fs::write(&full, &bytes)?;
                apply_mode(&full, entry.mode)?;
            }
            TreeEntryKind::Symlink => {
                if let Some(parent) = full.parent() {
                    fs::create_dir_all(parent)?;
                }
                if full.exists() {
                    fs::remove_file(&full)?;
                }
                let target = read_chunk_bytes(store, &entry.oid)?;
                let os_target = os_string_from_bytes(&target);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::symlink;
                    symlink(os_target, &full)?;
                }
                #[cfg(not(unix))]
                {
                    let _ = os_target;
                    anyhow::bail!("symlinks are unsupported on this platform");
                }
            }
        }
    }

    Ok(())
}

fn read_tree(store: &Store, oid: &Oid) -> anyhow::Result<Tree> {
    let (_kind, data) = store.read_object(oid)?;
    match data {
        ObjectData::Tree(tree) => Ok(tree),
        _ => anyhow::bail!("expected tree"),
    }
}

fn read_manifest(store: &Store, oid: &Oid) -> anyhow::Result<Manifest> {
    let (_kind, data) = store.read_object(oid)?;
    match data {
        ObjectData::Manifest(manifest) => Ok(manifest),
        _ => anyhow::bail!("expected manifest"),
    }
}

fn read_chunk_bytes(store: &Store, oid: &Oid) -> anyhow::Result<Vec<u8>> {
    let (_kind, data) = store.read_object(oid)?;
    match data {
        ObjectData::Chunk(bytes) => Ok(bytes),
        _ => anyhow::bail!("expected chunk"),
    }
}

fn read_manifest_bytes(store: &Store, oid: &Oid) -> anyhow::Result<Vec<u8>> {
    let manifest = read_manifest(store, oid)?;
    let mut out = Vec::with_capacity(manifest.file_len as usize);
    for chunk in &manifest.chunks {
        let bytes = read_chunk_bytes(store, chunk)?;
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

fn file_matches(store: &Store, entry: &TreeEntry, path: &Path) -> anyhow::Result<bool> {
    let manifest = read_manifest(store, &entry.oid)?;
    let metadata = fs::metadata(path)?;
    if metadata.len() != manifest.file_len {
        return Ok(false);
    }
    let bytes = fs::read(path)?;
    let mut offset = 0usize;
    for chunk in manifest.chunks {
        let chunk_bytes = read_chunk_bytes(store, &chunk)?;
        let end = offset + chunk_bytes.len();
        if bytes.get(offset..end) != Some(&chunk_bytes[..]) {
            return Ok(false);
        }
        offset = end;
    }
    Ok(true)
}

fn symlink_matches(store: &Store, entry: &TreeEntry, path: &Path) -> anyhow::Result<bool> {
    let target = fs::read_link(path)?;
    let target_bytes = os_string_to_bytes(&target.into_os_string());
    let stored = read_chunk_bytes(store, &entry.oid)?;
    Ok(target_bytes == stored)
}

fn build_tree_map(
    tree: &Tree,
    store: &Store,
    prefix: PathBuf,
) -> anyhow::Result<HashMap<PathBuf, TreeEntry>> {
    let mut out = HashMap::new();
    for entry in &tree.entries {
        let name = os_string_from_bytes(&entry.name);
        let mut path = prefix.clone();
        path.push(name);
        out.insert(path.clone(), entry.clone());
        if entry.kind == TreeEntryKind::Dir {
            let subtree = read_tree(store, &entry.oid)?;
            let nested = build_tree_map(&subtree, store, path)?;
            out.extend(nested);
        }
    }
    Ok(out)
}

fn walk_paths(root: &Path, ignore: &LvcsIgnore) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in walk_dir(root)? {
        let path = entry;
        if ignore.is_ignored(&path, path.is_dir()) {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        if rel.components().count() == 0 {
            continue;
        }
        out.push(rel);
    }
    Ok(out)
}

fn walk_dir(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.file_name() == Some(std::ffi::OsStr::new(".repo")) {
            continue;
        }
        out.push(path.clone());
        if path.is_dir() {
            out.extend(walk_dir(&path)?);
        }
    }
    Ok(out)
}

fn os_string_from_bytes(bytes: &[u8]) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(bytes.to_vec())
    }
    #[cfg(not(unix))]
    {
        OsString::from(String::from_utf8_lossy(bytes).to_string())
    }
}

fn os_string_to_bytes(value: &OsString) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        value.clone().into_vec()
    }
    #[cfg(not(unix))]
    {
        value.to_string_lossy().as_bytes().to_vec()
    }
}

fn apply_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::commit_worktree;
    use crate::repo::Repo;
    use crate::store::Store;

    #[test]
    fn checkout_restores_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = Repo::init(temp.path()).expect("init");
        let path = temp.path().join("file.txt");
        fs::write(&path, b"one").expect("write");
        let store = Store::new(repo.clone());
        let result = commit_worktree(&repo, &store, "tester".to_string(), 1, "msg".to_string())
            .expect("commit");

        fs::write(&path, b"two").expect("write2");
        checkout(&repo, &store, &result.root, true).expect("checkout");
        let contents = fs::read(&path).expect("read");
        assert_eq!(contents, b"one");
    }
}
