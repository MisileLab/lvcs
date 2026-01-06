use std::fs;

use crate::fsck::reachable_objects;
use crate::pack::{list_pack_objects, write_pack, PackInfo};
use crate::repo::Repo;
use crate::store::{list_loose_objects, object_path, Store};

pub struct GcResult {
    pub packed: usize,
    pub removed_loose: usize,
    pub removed_packs: usize,
    pub pack_info: Option<PackInfo>,
}

pub fn gc(repo: &Repo, store: &Store) -> anyhow::Result<GcResult> {
    let reachable = reachable_objects(repo, store)?;
    let pack_targets: Vec<_> = reachable.iter().copied().collect();
    let pack_info = if !pack_targets.is_empty() {
        Some(write_pack(repo, store, &pack_targets)?)
    } else {
        None
    };

    let mut removed_loose = 0usize;
    for oid in list_loose_objects(&repo.objects_dir())? {
        if !reachable.contains(&oid) {
            let path = object_path(&repo.objects_dir(), &oid);
            if path.exists() {
                fs::remove_file(path)?;
                removed_loose += 1;
            }
        }
    }

    let mut removed_packs = 0usize;
    if repo.pack_dir().exists() {
        for entry in fs::read_dir(repo.pack_dir())? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(info) = &pack_info {
                    if path == info.pack_path || path == info.idx_path {
                        continue;
                    }
                }
                fs::remove_file(path)?;
                removed_packs += 1;
            }
        }
    }

    let packed = list_pack_objects(&repo.pack_dir())?.len();

    Ok(GcResult {
        packed,
        removed_loose,
        removed_packs,
        pack_info,
    })
}
