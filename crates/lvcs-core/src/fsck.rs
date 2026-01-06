use std::collections::{HashSet, VecDeque};

use crate::object::{ObjectData, TreeEntryKind};
use crate::oid::Oid;
use crate::pack::{list_pack_indexes, pack_index_entries, verify_pack_hash};
use crate::refs::{list_refs, read_head, read_ref, Head};
use crate::repo::Repo;
use crate::store::Store;

pub struct FsckResult {
    pub issues: Vec<String>,
}

pub fn fsck(repo: &Repo, store: &Store) -> anyhow::Result<FsckResult> {
    let mut issues = Vec::new();

    for oid in store.list_loose_objects()? {
        match store.read_object(&oid) {
            Err(err) => {
                issues.push(format!("object {oid} failed: {err}"));
            }
            Ok((_kind, data)) => {
                if let ObjectData::Tree(tree) = data {
                    if !tree_entries_sorted(&tree.entries) {
                        issues.push(format!("tree {oid} entries not sorted"));
                    }
                }
            }
        }
    }

    for idx_path in list_pack_indexes(repo.pack_dir().as_path())? {
        if let Err(err) = verify_pack_hash(
            &idx_path
                .with_file_name(
                    idx_path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(|name| name.trim_end_matches(".idx"))
                        .ok_or_else(|| anyhow::anyhow!("invalid idx name"))?,
                )
                .with_extension("pack"),
        ) {
            issues.push(format!("pack hash failed: {err}"));
            continue;
        }
        for (oid, offset, pack_path) in pack_index_entries(&idx_path)? {
            if let Err(err) = crate::pack::read_pack_entry(&pack_path, offset) {
                issues.push(format!("pack object {oid} failed: {err}"));
            }
        }
    }

    let refs = list_refs(repo)?;
    let mut roots = Vec::new();
    for (_path, oid) in refs {
        roots.push(oid);
    }
    if let Ok(head) = read_head(repo) {
        match head {
            Head::Symbolic(path) => {
                if let Some(oid) = read_ref(repo, &path)? {
                    roots.push(oid);
                }
            }
            Head::Detached(oid) => roots.push(oid),
        }
    }

    let mut seen = HashSet::new();
    let mut queue: VecDeque<Oid> = roots.into_iter().collect();
    while let Some(oid) = queue.pop_front() {
        if !seen.insert(oid) {
            continue;
        }
        let (_kind, data) = match store.read_object(&oid) {
            Ok(data) => data,
            Err(err) => {
                issues.push(format!("missing object {oid}: {err}"));
                continue;
            }
        };
        match data {
            ObjectData::Commit(commit) => {
                queue.push_back(commit.root);
                for parent in commit.parents {
                    queue.push_back(parent);
                }
            }
            ObjectData::Tree(tree) => {
                for entry in tree.entries {
                    queue.push_back(entry.oid);
                }
            }
            ObjectData::Manifest(manifest) => {
                for chunk in manifest.chunks {
                    queue.push_back(chunk);
                }
            }
            ObjectData::Chunk(_) => {}
        }
    }

    Ok(FsckResult { issues })
}

fn tree_entries_sorted(entries: &[crate::object::TreeEntry]) -> bool {
    let mut prev: Option<&[u8]> = None;
    for entry in entries {
        if let Some(prev_name) = prev {
            if prev_name > entry.name.as_slice() {
                return false;
            }
        }
        prev = Some(entry.name.as_slice());
        match entry.kind {
            TreeEntryKind::File | TreeEntryKind::Dir | TreeEntryKind::Symlink => {}
        }
    }
    true
}

pub fn reachable_objects(repo: &Repo, store: &Store) -> anyhow::Result<HashSet<Oid>> {
    let mut roots = Vec::new();
    let refs = list_refs(repo)?;
    for (_path, oid) in refs {
        roots.push(oid);
    }
    if let Ok(head) = read_head(repo) {
        match head {
            Head::Symbolic(path) => {
                if let Some(oid) = read_ref(repo, &path)? {
                    roots.push(oid);
                }
            }
            Head::Detached(oid) => roots.push(oid),
        }
    }
    reachable_from(store, &roots)
}

pub fn reachable_from(store: &Store, roots: &[Oid]) -> anyhow::Result<HashSet<Oid>> {
    let mut seen = HashSet::new();
    let mut queue: VecDeque<Oid> = roots.iter().copied().collect();
    while let Some(oid) = queue.pop_front() {
        if !seen.insert(oid) {
            continue;
        }
        let (_kind, data) = store.read_object(&oid)?;
        match data {
            ObjectData::Commit(commit) => {
                queue.push_back(commit.root);
                for parent in commit.parents {
                    queue.push_back(parent);
                }
            }
            ObjectData::Tree(tree) => {
                for entry in tree.entries {
                    queue.push_back(entry.oid);
                }
            }
            ObjectData::Manifest(manifest) => {
                for chunk in manifest.chunks {
                    queue.push_back(chunk);
                }
            }
            ObjectData::Chunk(_) => {}
        }
    }

    Ok(seen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::object::{Tree, TreeEntry, TreeEntryKind};
    use crate::repo::Repo;
    use crate::store::Store;

    #[test]
    fn fsck_flags_unsorted_tree() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = Repo::init(temp.path()).expect("init");
        let store = Store::new(repo.clone());
        let tree = Tree {
            entries: vec![
                TreeEntry {
                    name: b"b.txt".to_vec(),
                    kind: TreeEntryKind::File,
                    mode: 0o100644,
                    oid: crate::Oid::new([0x11; 32]),
                },
                TreeEntry {
                    name: b"a.txt".to_vec(),
                    kind: TreeEntryKind::File,
                    mode: 0o100644,
                    oid: crate::Oid::new([0x22; 32]),
                },
            ],
        };
        let tree_oid = store.write_object(&ObjectData::Tree(tree)).expect("write");
        crate::write_ref(&repo, Path::new("refs/heads/main"), &tree_oid).expect("ref");
        let result = fsck(&repo, &store).expect("fsck");
        assert!(result
            .issues
            .iter()
            .any(|issue| issue.contains("entries not sorted")));
    }
}
