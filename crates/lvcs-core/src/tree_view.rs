use std::path::PathBuf;

use crate::object::{ObjectData, Tree, TreeEntry, TreeEntryKind};
use crate::oid::Oid;
use crate::store::Store;

#[derive(Clone, Debug)]
pub struct TreeItem {
    pub path: PathBuf,
    pub entry: TreeEntry,
    pub size: Option<u64>,
}

pub fn list_tree(store: &Store, root: &Oid) -> anyhow::Result<Vec<TreeItem>> {
    let tree = read_tree(store, root)?;
    let mut out = Vec::new();
    collect_tree(store, &tree, PathBuf::new(), &mut out)?;
    Ok(out)
}

fn collect_tree(
    store: &Store,
    tree: &Tree,
    prefix: PathBuf,
    out: &mut Vec<TreeItem>,
) -> anyhow::Result<()> {
    for entry in &tree.entries {
        let name = os_string_from_bytes(&entry.name);
        let mut path = prefix.clone();
        path.push(name);
        let size = match entry.kind {
            TreeEntryKind::File => Some(manifest_size(store, &entry.oid)?),
            _ => None,
        };
        out.push(TreeItem {
            path: path.clone(),
            entry: entry.clone(),
            size,
        });
        if entry.kind == TreeEntryKind::Dir {
            let subtree = read_tree(store, &entry.oid)?;
            collect_tree(store, &subtree, path, out)?;
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

fn manifest_size(store: &Store, oid: &Oid) -> anyhow::Result<u64> {
    let (_kind, data) = store.read_object(oid)?;
    match data {
        ObjectData::Manifest(manifest) => Ok(manifest.file_len),
        _ => anyhow::bail!("expected manifest"),
    }
}

fn os_string_from_bytes(bytes: &[u8]) -> std::ffi::OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(bytes.to_vec())
    }
    #[cfg(not(unix))]
    {
        std::ffi::OsString::from(String::from_utf8_lossy(bytes).to_string())
    }
}
