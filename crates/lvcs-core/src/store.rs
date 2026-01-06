use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::object::{decode_object, encode_object, hash_object, ObjectData, ObjectKind};
use crate::oid::Oid;
use crate::repo::Repo;
use crate::util::atomic_write;

const OBJ_MAGIC: &[u8; 8] = b"LVCSOBJ1";

pub struct Store {
    repo: Repo,
}

impl Store {
    pub fn list_loose_objects(&self) -> anyhow::Result<Vec<Oid>> {
        list_loose_objects(&self.repo.objects_dir())
    }
}

impl Store {
    pub fn new(repo: Repo) -> Self {
        Self { repo }
    }

    pub fn write_object(&self, data: &ObjectData) -> anyhow::Result<Oid> {
        let payload = encode_object(data);
        let oid = hash_object(data.kind(), &payload);
        self.write_raw(data.kind(), &payload, &oid)?;
        Ok(oid)
    }

    pub fn write_raw(&self, kind: ObjectKind, payload: &[u8], oid: &Oid) -> anyhow::Result<()> {
        let path = self.object_path(oid);
        if path.exists() {
            return Ok(());
        }

        let compressed = zstd::encode_all(payload, 10)?;
        let mut out = Vec::with_capacity(OBJ_MAGIC.len() + 1 + 8 + compressed.len());
        out.extend_from_slice(OBJ_MAGIC);
        out.push(kind as u8);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        out.extend_from_slice(&compressed);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        atomic_write(&path, &out)?;
        Ok(())
    }

    pub fn read_object(&self, oid: &Oid) -> anyhow::Result<(ObjectKind, ObjectData)> {
        let path = self.object_path(oid);
        match File::open(&path) {
            Ok(mut file) => {
                let mut header = [0u8; 8];
                file.read_exact(&mut header)?;
                if &header != OBJ_MAGIC {
                    anyhow::bail!("invalid object header");
                }
                let mut kind_buf = [0u8; 1];
                file.read_exact(&mut kind_buf)?;
                let kind = match kind_buf[0] {
                    1 => ObjectKind::Chunk,
                    2 => ObjectKind::Manifest,
                    3 => ObjectKind::Tree,
                    4 => ObjectKind::Commit,
                    _ => anyhow::bail!("unknown object kind"),
                };
                let mut len_buf = [0u8; 8];
                file.read_exact(&mut len_buf)?;
                let payload_len = u64::from_be_bytes(len_buf) as usize;
                let mut compressed = Vec::new();
                file.read_to_end(&mut compressed)?;
                let payload = zstd::decode_all(&compressed[..])?;
                if payload.len() != payload_len {
                    anyhow::bail!("object length mismatch");
                }
                let data = decode_object(kind, &payload)
                    .ok_or_else(|| anyhow::anyhow!("decode failed"))?;
                let computed = hash_object(kind, &payload);
                if &computed != oid {
                    anyhow::bail!("object checksum mismatch");
                }
                Ok((kind, data))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if let Some(found) =
                    crate::pack::read_object_from_packs(&self.repo.pack_dir(), oid)?
                {
                    Ok(found)
                } else {
                    Err(err.into())
                }
            }
            Err(err) => Err(err.into()),
        }
    }

    pub fn object_path(&self, oid: &Oid) -> PathBuf {
        object_path(&self.repo.objects_dir(), oid)
    }

    pub fn repo(&self) -> &Repo {
        &self.repo
    }
}

pub fn object_path(objects_dir: &Path, oid: &Oid) -> PathBuf {
    let hex = oid.to_hex();
    let (dir, rest) = hex.split_at(2);
    objects_dir.join(dir).join(rest)
}

pub fn list_loose_objects(objects_dir: &Path) -> anyhow::Result<Vec<Oid>> {
    let mut out = Vec::new();
    if !objects_dir.exists() {
        return Ok(out);
    }
    for dir_entry in fs::read_dir(objects_dir)? {
        let dir_entry = dir_entry?;
        if !dir_entry.file_type()?.is_dir() {
            continue;
        }
        let dir_name = dir_entry.file_name().to_string_lossy().to_string();
        if dir_name.len() != 2 {
            continue;
        }
        for file_entry in fs::read_dir(dir_entry.path())? {
            let file_entry = file_entry?;
            if !file_entry.file_type()?.is_file() {
                continue;
            }
            let file_name = file_entry.file_name().to_string_lossy().to_string();
            if file_name.len() != 62 {
                continue;
            }
            let hex = format!("{dir_name}{file_name}");
            if let Some(oid) = Oid::from_hex(&hex) {
                out.push(oid);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::ObjectData;
    use crate::repo::Repo;

    #[test]
    fn write_and_read_chunk() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = Repo::init(temp.path()).expect("init");
        let store = Store::new(repo);
        let data = ObjectData::Chunk(b"hello".to_vec());
        let oid = store.write_object(&data).expect("write");
        let (_kind, read) = store.read_object(&oid).expect("read");
        assert_eq!(data, read);
    }
}
