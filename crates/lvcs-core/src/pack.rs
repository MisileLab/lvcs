use std::cmp::Ordering;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::object::{decode_object, encode_object, hash_object, ObjectData, ObjectKind};
use crate::oid::Oid;
use crate::repo::Repo;
use crate::store::Store;
use crate::util::sync_dir;

const PACK_MAGIC: &[u8; 8] = b"LVCSPACK";
const IDX_MAGIC: &[u8; 8] = b"LVCSPIDX";
const PACK_VERSION: u32 = 1;
const IDX_VERSION: u32 = 1;

pub struct PackInfo {
    pub pack_path: PathBuf,
    pub idx_path: PathBuf,
}

pub fn write_pack(repo: &Repo, store: &Store, oids: &[Oid]) -> anyhow::Result<PackInfo> {
    fs::create_dir_all(repo.pack_dir())?;

    let mut entries = Vec::new();
    let pack_temp = repo.pack_dir().join("pack.tmp");
    let mut pack = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&pack_temp)?;

    let mut hasher = blake3::Hasher::new();
    let mut offset = 0u64;

    offset += write_all(&mut pack, &mut hasher, PACK_MAGIC)?;
    offset += write_all(&mut pack, &mut hasher, &PACK_VERSION.to_be_bytes())?;
    offset += write_all(&mut pack, &mut hasher, &(oids.len() as u64).to_be_bytes())?;

    for oid in oids {
        let (kind, data) = store.read_object(oid)?;
        let payload = encode_object(&data);
        let recomputed = hash_object(kind, &payload);
        if &recomputed != oid {
            anyhow::bail!("object hash mismatch for {oid}");
        }
        let compressed = zstd::encode_all(&payload[..], 10)?;
        let entry_offset = offset;
        offset += write_all(&mut pack, &mut hasher, &[kind as u8])?;
        offset += write_all(&mut pack, &mut hasher, oid.as_bytes())?;
        offset += write_all(
            &mut pack,
            &mut hasher,
            &(payload.len() as u64).to_be_bytes(),
        )?;
        offset += write_all(
            &mut pack,
            &mut hasher,
            &(compressed.len() as u64).to_be_bytes(),
        )?;
        offset += write_all(&mut pack, &mut hasher, &compressed)?;
        entries.push(PackIndexEntry {
            oid: *oid,
            offset: entry_offset,
        });
    }

    let pack_hash = hasher.finalize();
    pack.write_all(pack_hash.as_bytes())?;
    pack.sync_all()?;

    let pack_name = format!("pack-{}.pack", Oid::new(*pack_hash.as_bytes()).to_hex());
    let pack_path = repo.pack_dir().join(pack_name);
    fs::rename(&pack_temp, &pack_path)?;
    sync_dir(repo.pack_dir().as_path())?;

    let idx_path = write_index(&repo.pack_dir(), &pack_path, &entries)?;

    Ok(PackInfo {
        pack_path,
        idx_path,
    })
}

pub fn read_object_from_packs(
    pack_dir: &Path,
    oid: &Oid,
) -> anyhow::Result<Option<(ObjectKind, ObjectData)>> {
    let mut packs = Vec::new();
    if pack_dir.exists() {
        for entry in fs::read_dir(pack_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("idx") {
                packs.push(path);
            }
        }
    }
    for idx_path in packs {
        if let Some((pack_path, offset)) = lookup_index(&idx_path, oid)? {
            let data = read_pack_entry(&pack_path, offset)?;
            return Ok(Some(data));
        }
    }
    Ok(None)
}

pub fn import_pack(pack_path: &Path, store: &Store) -> anyhow::Result<()> {
    let mut file = File::open(pack_path)?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != PACK_MAGIC {
        anyhow::bail!("invalid pack header");
    }
    let mut version_buf = [0u8; 4];
    file.read_exact(&mut version_buf)?;
    let version = u32::from_be_bytes(version_buf);
    if version != PACK_VERSION {
        anyhow::bail!("unsupported pack version");
    }
    let mut count_buf = [0u8; 8];
    file.read_exact(&mut count_buf)?;
    let count = u64::from_be_bytes(count_buf) as usize;

    for _ in 0..count {
        let mut kind_buf = [0u8; 1];
        file.read_exact(&mut kind_buf)?;
        let kind = match kind_buf[0] {
            1 => ObjectKind::Chunk,
            2 => ObjectKind::Manifest,
            3 => ObjectKind::Tree,
            4 => ObjectKind::Commit,
            _ => anyhow::bail!("unknown kind"),
        };
        let mut oid_buf = [0u8; 32];
        file.read_exact(&mut oid_buf)?;
        let oid = Oid::new(oid_buf);
        let mut len_buf = [0u8; 8];
        file.read_exact(&mut len_buf)?;
        let payload_len = u64::from_be_bytes(len_buf) as usize;
        let mut comp_len_buf = [0u8; 8];
        file.read_exact(&mut comp_len_buf)?;
        let comp_len = u64::from_be_bytes(comp_len_buf) as usize;
        let mut compressed = vec![0u8; comp_len];
        file.read_exact(&mut compressed)?;
        let payload = zstd::decode_all(&compressed[..])?;
        if payload.len() != payload_len {
            anyhow::bail!("pack length mismatch");
        }
        let computed = hash_object(kind, &payload);
        if computed != oid {
            anyhow::bail!("pack object checksum mismatch");
        }
        store.write_raw(kind, &payload, &oid)?;
    }

    Ok(())
}

pub fn list_pack_objects(pack_dir: &Path) -> anyhow::Result<Vec<Oid>> {
    let mut out = Vec::new();
    if !pack_dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(pack_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("idx") {
            continue;
        }
        let idx = read_index(&path)?;
        out.extend(idx.entries.into_iter().map(|entry| entry.oid));
    }
    Ok(out)
}

pub fn list_pack_indexes(pack_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !pack_dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(pack_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("idx") {
            out.push(path);
        }
    }
    Ok(out)
}

pub fn pack_index_entries(idx_path: &Path) -> anyhow::Result<Vec<(Oid, u64, PathBuf)>> {
    let idx = read_index(idx_path)?;
    Ok(idx
        .entries
        .into_iter()
        .map(|entry| (entry.oid, entry.offset, idx.pack_path.clone()))
        .collect())
}

pub fn verify_pack_hash(pack_path: &Path) -> anyhow::Result<()> {
    let mut file = File::open(pack_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    if data.len() < 32 {
        anyhow::bail!("pack too small");
    }
    let (payload, hash_bytes) = data.split_at(data.len() - 32);
    let mut hasher = blake3::Hasher::new();
    hasher.update(payload);
    let computed = hasher.finalize();
    if computed.as_bytes() != hash_bytes {
        anyhow::bail!("pack hash mismatch");
    }
    Ok(())
}

fn write_index(
    pack_dir: &Path,
    pack_path: &Path,
    entries: &[PackIndexEntry],
) -> anyhow::Result<PathBuf> {
    let mut entries = entries.to_vec();
    entries.sort_by(|a, b| a.oid.as_bytes().cmp(b.oid.as_bytes()));

    let idx_temp = pack_dir.join("pack.tmp.idx");
    let mut idx = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&idx_temp)?;
    idx.write_all(IDX_MAGIC)?;
    idx.write_all(&IDX_VERSION.to_be_bytes())?;
    idx.write_all(&(entries.len() as u64).to_be_bytes())?;
    for entry in &entries {
        idx.write_all(entry.oid.as_bytes())?;
        idx.write_all(&entry.offset.to_be_bytes())?;
    }
    idx.sync_all()?;

    let idx_name = pack_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.idx"))
        .ok_or_else(|| anyhow::anyhow!("invalid pack name"))?;
    let idx_path = pack_dir.join(idx_name);
    fs::rename(&idx_temp, &idx_path)?;
    sync_dir(pack_dir)?;
    Ok(idx_path)
}

fn lookup_index(idx_path: &Path, oid: &Oid) -> anyhow::Result<Option<(PathBuf, u64)>> {
    let idx = read_index(idx_path)?;
    let mut left = 0usize;
    let mut right = idx.entries.len();
    while left < right {
        let mid = (left + right) / 2;
        match idx.entries[mid].oid.as_bytes().cmp(oid.as_bytes()) {
            Ordering::Equal => return Ok(Some((idx.pack_path.clone(), idx.entries[mid].offset))),
            Ordering::Less => left = mid + 1,
            Ordering::Greater => right = mid,
        }
    }
    Ok(None)
}

fn read_index(idx_path: &Path) -> anyhow::Result<PackIndex> {
    let mut file = File::open(idx_path)?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != IDX_MAGIC {
        anyhow::bail!("invalid index header");
    }
    let mut version_buf = [0u8; 4];
    file.read_exact(&mut version_buf)?;
    let version = u32::from_be_bytes(version_buf);
    if version != IDX_VERSION {
        anyhow::bail!("unsupported index version");
    }
    let mut count_buf = [0u8; 8];
    file.read_exact(&mut count_buf)?;
    let count = u64::from_be_bytes(count_buf) as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let mut oid = [0u8; 32];
        file.read_exact(&mut oid)?;
        let mut offset_buf = [0u8; 8];
        file.read_exact(&mut offset_buf)?;
        let offset = u64::from_be_bytes(offset_buf);
        entries.push(PackIndexEntry {
            oid: Oid::new(oid),
            offset,
        });
    }
    let pack_path = idx_path
        .with_file_name(
            idx_path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.trim_end_matches(".idx"))
                .ok_or_else(|| anyhow::anyhow!("invalid idx name"))?,
        )
        .with_extension("pack");
    Ok(PackIndex { pack_path, entries })
}

pub fn read_pack_entry(pack_path: &Path, offset: u64) -> anyhow::Result<(ObjectKind, ObjectData)> {
    let mut file = File::open(pack_path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut kind_buf = [0u8; 1];
    file.read_exact(&mut kind_buf)?;
    let kind = match kind_buf[0] {
        1 => ObjectKind::Chunk,
        2 => ObjectKind::Manifest,
        3 => ObjectKind::Tree,
        4 => ObjectKind::Commit,
        _ => anyhow::bail!("unknown kind"),
    };
    let mut oid_buf = [0u8; 32];
    file.read_exact(&mut oid_buf)?;
    let oid = Oid::new(oid_buf);
    let mut len_buf = [0u8; 8];
    file.read_exact(&mut len_buf)?;
    let payload_len = u64::from_be_bytes(len_buf) as usize;
    let mut comp_len_buf = [0u8; 8];
    file.read_exact(&mut comp_len_buf)?;
    let comp_len = u64::from_be_bytes(comp_len_buf) as usize;
    let mut compressed = vec![0u8; comp_len];
    file.read_exact(&mut compressed)?;
    let payload = zstd::decode_all(&compressed[..])?;
    if payload.len() != payload_len {
        anyhow::bail!("pack length mismatch");
    }
    let computed = hash_object(kind, &payload);
    if computed != oid {
        anyhow::bail!("pack object checksum mismatch");
    }
    let data = decode_object(kind, &payload).ok_or_else(|| anyhow::anyhow!("decode failed"))?;
    Ok((kind, data))
}

fn write_all(file: &mut File, hasher: &mut blake3::Hasher, bytes: &[u8]) -> anyhow::Result<u64> {
    file.write_all(bytes)?;
    hasher.update(bytes);
    Ok(bytes.len() as u64)
}

#[derive(Clone, Debug)]
struct PackIndexEntry {
    oid: Oid,
    offset: u64,
}

struct PackIndex {
    pack_path: PathBuf,
    entries: Vec<PackIndexEntry>,
}
