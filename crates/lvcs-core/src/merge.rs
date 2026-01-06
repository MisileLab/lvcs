use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crate::commit::load_commit;
use crate::object::{ObjectData, Tree, TreeEntryKind};
use crate::oid::Oid;
use crate::repo::{Repo, MERGE_STATE_FILE};
use crate::store::Store;

pub enum MergeOutcome {
    Clean,
    Conflicts(Vec<PathBuf>),
}

pub fn merge(repo: &Repo, store: &Store, other: &Oid) -> anyhow::Result<MergeOutcome> {
    let head = crate::rev::resolve_rev(repo, Some("HEAD"))?;
    let base = lowest_common_ancestor(store, &head, other)?.unwrap_or(head);

    let base_tree = read_commit_tree(store, &base)?;
    let ours_tree = read_commit_tree(store, &head)?;
    let theirs_tree = read_commit_tree(store, other)?;

    let base_map = tree_files(store, &base_tree, PathBuf::new())?;
    let ours_map = tree_files(store, &ours_tree, PathBuf::new())?;
    let theirs_map = tree_files(store, &theirs_tree, PathBuf::new())?;

    let mut paths: HashSet<PathBuf> = HashSet::new();
    for path in base_map.keys() {
        paths.insert(path.clone());
    }
    for path in ours_map.keys() {
        paths.insert(path.clone());
    }
    for path in theirs_map.keys() {
        paths.insert(path.clone());
    }

    let mut conflicts = Vec::new();
    for path in paths {
        let base = base_map.get(&path);
        let ours = ours_map.get(&path);
        let theirs = theirs_map.get(&path);

        if ours == theirs {
            if let Some(data) = ours {
                write_worktree(repo.worktree(), &path, data)?;
            }
            continue;
        }
        if base == ours {
            if let Some(data) = theirs {
                write_worktree(repo.worktree(), &path, data)?;
            } else {
                remove_path(repo.worktree(), &path)?;
            }
            continue;
        }
        if base == theirs {
            if let Some(data) = ours {
                write_worktree(repo.worktree(), &path, data)?;
            } else {
                remove_path(repo.worktree(), &path)?;
            }
            continue;
        }

        match (base, ours, theirs) {
            (Some(base), Some(ours), Some(theirs)) => {
                if ours.kind == theirs.kind && ours.kind == base.kind {
                    let merged = merge_text_3way(&base.bytes, &ours.bytes, &theirs.bytes);
                    match merged {
                        Some(bytes) => write_worktree(
                            repo.worktree(),
                            &path,
                            &FileData {
                                bytes,
                                mode: ours.mode,
                                kind: ours.kind,
                            },
                        )?,
                        None => {
                            let conflict = conflict_bytes(&ours.bytes, &theirs.bytes);
                            write_worktree(
                                repo.worktree(),
                                &path,
                                &FileData {
                                    bytes: conflict,
                                    mode: ours.mode,
                                    kind: ours.kind,
                                },
                            )?;
                            conflicts.push(path.clone());
                        }
                    }
                } else {
                    conflicts.push(path.clone());
                }
            }
            (Some(base), Some(ours), None) => {
                if ours.kind == base.kind && ours.bytes == base.bytes {
                    remove_path(repo.worktree(), &path)?;
                } else {
                    conflicts.push(path.clone());
                }
            }
            (Some(base), None, Some(theirs)) => {
                if theirs.kind == base.kind && theirs.bytes == base.bytes {
                    remove_path(repo.worktree(), &path)?;
                } else {
                    conflicts.push(path.clone());
                }
            }
            (None, Some(ours), Some(theirs)) => {
                if ours.kind == theirs.kind && ours.bytes == theirs.bytes {
                    write_worktree(repo.worktree(), &path, ours)?;
                } else {
                    let conflict = conflict_bytes(&ours.bytes, &theirs.bytes);
                    write_worktree(
                        repo.worktree(),
                        &path,
                        &FileData {
                            bytes: conflict,
                            mode: ours.mode,
                            kind: ours.kind,
                        },
                    )?;
                    conflicts.push(path.clone());
                }
            }
            _ => {
                conflicts.push(path.clone());
            }
        }
    }

    if !conflicts.is_empty() {
        write_merge_state(repo, &base, other)?;
        Ok(MergeOutcome::Conflicts(conflicts))
    } else {
        clear_merge_state(repo)?;
        Ok(MergeOutcome::Clean)
    }
}

pub fn read_merge_state(repo: &Repo) -> anyhow::Result<Option<(Oid, Oid)>> {
    let path = repo.repo_dir().join(MERGE_STATE_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(path)?;
    let text = String::from_utf8_lossy(&data);
    let mut base = None;
    let mut other = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("base ") {
            base = Oid::from_hex(value.trim());
        } else if let Some(value) = line.strip_prefix("other ") {
            other = Oid::from_hex(value.trim());
        }
    }
    match (base, other) {
        (Some(base), Some(other)) => Ok(Some((base, other))),
        _ => Ok(None),
    }
}

pub fn clear_merge_state(repo: &Repo) -> anyhow::Result<()> {
    let path = repo.repo_dir().join(MERGE_STATE_FILE);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn write_merge_state(repo: &Repo, base: &Oid, other: &Oid) -> anyhow::Result<()> {
    let path = repo.repo_dir().join(MERGE_STATE_FILE);
    let data = format!("base {}\nother {}\n", base.to_hex(), other.to_hex());
    crate::util::atomic_write(&path, data.as_bytes())
}

fn read_commit_tree(store: &Store, oid: &Oid) -> anyhow::Result<Tree> {
    let commit = load_commit(store, oid)?;
    let (_kind, data) = store.read_object(&commit.root)?;
    match data {
        ObjectData::Tree(tree) => Ok(tree),
        _ => anyhow::bail!("expected tree"),
    }
}

fn tree_files(
    store: &Store,
    tree: &Tree,
    prefix: PathBuf,
) -> anyhow::Result<BTreeMap<PathBuf, FileData>> {
    let mut out = BTreeMap::new();
    for entry in &tree.entries {
        let name = os_string_from_bytes(&entry.name);
        let mut path = prefix.clone();
        path.push(name);
        match entry.kind {
            TreeEntryKind::Dir => {
                let subtree = read_tree(store, &entry.oid)?;
                out.extend(tree_files(store, &subtree, path)?);
            }
            TreeEntryKind::File => {
                let bytes = read_manifest_bytes(store, &entry.oid)?;
                out.insert(
                    path,
                    FileData {
                        bytes,
                        mode: entry.mode,
                        kind: entry.kind,
                    },
                );
            }
            TreeEntryKind::Symlink => {
                let bytes = read_chunk_bytes(store, &entry.oid)?;
                out.insert(
                    path,
                    FileData {
                        bytes,
                        mode: entry.mode,
                        kind: entry.kind,
                    },
                );
            }
        }
    }
    Ok(out)
}

fn read_tree(store: &Store, oid: &Oid) -> anyhow::Result<Tree> {
    let (_kind, data) = store.read_object(oid)?;
    match data {
        ObjectData::Tree(tree) => Ok(tree),
        _ => anyhow::bail!("expected tree"),
    }
}

fn read_manifest_bytes(store: &Store, oid: &Oid) -> anyhow::Result<Vec<u8>> {
    let (_kind, data) = store.read_object(oid)?;
    let manifest = match data {
        ObjectData::Manifest(manifest) => manifest,
        _ => anyhow::bail!("expected manifest"),
    };
    let mut out = Vec::with_capacity(manifest.file_len as usize);
    for chunk in manifest.chunks {
        out.extend_from_slice(&read_chunk_bytes(store, &chunk)?);
    }
    Ok(out)
}

fn read_chunk_bytes(store: &Store, oid: &Oid) -> anyhow::Result<Vec<u8>> {
    let (_kind, data) = store.read_object(oid)?;
    match data {
        ObjectData::Chunk(bytes) => Ok(bytes),
        _ => anyhow::bail!("expected chunk"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileData {
    bytes: Vec<u8>,
    mode: u32,
    kind: TreeEntryKind,
}

fn write_worktree(root: &Path, path: &Path, data: &FileData) -> anyhow::Result<()> {
    let full = root.join(path);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent)?;
    }
    match data.kind {
        TreeEntryKind::Symlink => {
            if full.exists() {
                fs::remove_file(&full)?;
            }
            let target = os_string_from_bytes(&data.bytes);
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                symlink(target, &full)?;
            }
            #[cfg(not(unix))]
            {
                let _ = target;
                anyhow::bail!("symlinks are unsupported on this platform");
            }
        }
        _ => {
            fs::write(&full, &data.bytes)?;
            apply_mode(&full, data.mode)?;
        }
    }
    Ok(())
}

fn remove_path(root: &Path, path: &Path) -> anyhow::Result<()> {
    let full = root.join(path);
    if full.is_dir() {
        fs::remove_dir_all(full)?;
    } else if full.exists() {
        fs::remove_file(full)?;
    }
    Ok(())
}

fn merge_text_3way(base: &[u8], ours: &[u8], theirs: &[u8]) -> Option<Vec<u8>> {
    let base_str = std::str::from_utf8(base).ok()?;
    let ours_str = std::str::from_utf8(ours).ok()?;
    let theirs_str = std::str::from_utf8(theirs).ok()?;

    if ours_str == theirs_str {
        return Some(ours.to_vec());
    }
    if base_str == ours_str {
        return Some(theirs.to_vec());
    }
    if base_str == theirs_str {
        return Some(ours.to_vec());
    }

    let merged = diffy::MergeOptions::new()
        .merge(base_str, ours_str, theirs_str)
        .ok()?;

    if merged.contains("<<<<<<<") {
        return None;
    }

    Some(merged.into_bytes())
}

fn conflict_bytes(ours: &[u8], theirs: &[u8]) -> Vec<u8> {
    let ours_text = std::str::from_utf8(ours).ok();
    let theirs_text = std::str::from_utf8(theirs).ok();
    let mut out = Vec::new();
    out.extend_from_slice(b"<<<<<<< ours\n");
    match ours_text {
        Some(text) => out.extend_from_slice(text.as_bytes()),
        None => out.extend_from_slice(b"<BINARY>\n"),
    }
    if !out.ends_with(b"\n") {
        out.extend_from_slice(b"\n");
    }
    out.extend_from_slice(b"=======\n");
    match theirs_text {
        Some(text) => out.extend_from_slice(text.as_bytes()),
        None => out.extend_from_slice(b"<BINARY>\n"),
    }
    if !out.ends_with(b"\n") {
        out.extend_from_slice(b"\n");
    }
    out.extend_from_slice(b">>>>>>> theirs\n");
    out
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

fn lowest_common_ancestor(store: &Store, left: &Oid, right: &Oid) -> anyhow::Result<Option<Oid>> {
    let left_ancestors = collect_ancestors(store, left)?;
    let right_ancestors = collect_ancestors(store, right)?;
    for oid in left_ancestors {
        if right_ancestors.contains(&oid) {
            return Ok(Some(oid));
        }
    }
    Ok(None)
}

fn collect_ancestors(store: &Store, start: &Oid) -> anyhow::Result<Vec<Oid>> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(*start);
    let mut order = Vec::new();
    while let Some(oid) = queue.pop_front() {
        if !visited.insert(oid) {
            continue;
        }
        order.push(oid);
        let commit = load_commit(store, &oid)?;
        for parent in commit.parents {
            queue.push_back(parent);
        }
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::commit_worktree;
    use crate::refs::Head;
    use crate::repo::Repo;
    use crate::store::Store;

    #[test]
    fn merge_clean_three_way() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = Repo::init(temp.path()).expect("init");
        let store = Store::new(repo.clone());
        let path = temp.path().join("file.txt");

        fs::write(&path, b"a\nb\nc\n").expect("write");
        let base = commit_worktree(&repo, &store, "tester".to_string(), 1, "base".to_string())
            .expect("commit");

        fs::write(&path, b"a\nb\nOURS\n").expect("write");
        let ours = commit_worktree(&repo, &store, "tester".to_string(), 2, "ours".to_string())
            .expect("commit");

        crate::write_head(&repo, &Head::Detached(base.oid)).expect("head");
        fs::write(&path, b"THEIRS\nb\nc\n").expect("write");
        let theirs = commit_worktree(&repo, &store, "tester".to_string(), 3, "theirs".to_string())
            .expect("commit");

        crate::write_head(&repo, &Head::Detached(ours.oid)).expect("head");

        let result = merge(&repo, &store, &theirs.oid).expect("merge");
        match result {
            MergeOutcome::Clean => {}
            MergeOutcome::Conflicts(_) => panic!("expected clean merge"),
        }

        let merged = fs::read(&path).expect("read");
        assert_eq!(merged, b"THEIRS\nb\nOURS\n");

        let state = read_merge_state(&repo).expect("state");
        assert!(state.is_none());
    }

    #[test]
    fn merge_conflict_modify_delete_marks_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = Repo::init(temp.path()).expect("init");
        let store = Store::new(repo.clone());
        let path = temp.path().join("file.txt");

        fs::write(&path, b"one\n").expect("write");
        let base = commit_worktree(&repo, &store, "tester".to_string(), 1, "base".to_string())
            .expect("commit");

        fs::write(&path, b"ours\n").expect("write");
        let ours = commit_worktree(&repo, &store, "tester".to_string(), 2, "ours".to_string())
            .expect("commit");

        crate::write_head(&repo, &Head::Detached(base.oid)).expect("head");
        fs::remove_file(&path).expect("rm");
        let theirs = commit_worktree(&repo, &store, "tester".to_string(), 3, "theirs".to_string())
            .expect("commit");

        crate::write_head(&repo, &Head::Detached(ours.oid)).expect("head");
        let result = merge(&repo, &store, &theirs.oid).expect("merge");
        match result {
            MergeOutcome::Conflicts(paths) => {
                assert!(paths.iter().any(|p| p == Path::new("file.txt")));
            }
            MergeOutcome::Clean => panic!("expected conflicts"),
        }

        let state = read_merge_state(&repo).expect("state");
        assert!(state.is_some());
    }
}
