use std::io::{Cursor, Read};

use crate::oid::Oid;

const DOMAIN_CHUNK: &[u8] = b"lvcs:chunk\0";
const DOMAIN_MANIFEST: &[u8] = b"lvcs:manifest\0";
const DOMAIN_TREE: &[u8] = b"lvcs:tree\0";
const DOMAIN_COMMIT: &[u8] = b"lvcs:commit\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectKind {
    Chunk = 1,
    Manifest = 2,
    Tree = 3,
    Commit = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub file_len: u64,
    pub mode: u32,
    pub chunk_size: u32,
    pub chunks: Vec<Oid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TreeEntryKind {
    File = 1,
    Dir = 2,
    Symlink = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeEntry {
    pub name: Vec<u8>,
    pub kind: TreeEntryKind,
    pub mode: u32,
    pub oid: Oid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree {
    pub entries: Vec<TreeEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub root: Oid,
    pub parents: Vec<Oid>,
    pub author: String,
    pub timestamp: i64,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectData {
    Chunk(Vec<u8>),
    Manifest(Manifest),
    Tree(Tree),
    Commit(Commit),
}

impl ObjectData {
    pub fn kind(&self) -> ObjectKind {
        match self {
            Self::Chunk(_) => ObjectKind::Chunk,
            Self::Manifest(_) => ObjectKind::Manifest,
            Self::Tree(_) => ObjectKind::Tree,
            Self::Commit(_) => ObjectKind::Commit,
        }
    }
}

pub fn hash_object(kind: ObjectKind, payload: &[u8]) -> Oid {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain_for(kind));
    hasher.update(payload);
    let hash = hasher.finalize();
    Oid::new(*hash.as_bytes())
}

pub fn encode_object(data: &ObjectData) -> Vec<u8> {
    match data {
        ObjectData::Chunk(bytes) => bytes.clone(),
        ObjectData::Manifest(manifest) => encode_manifest(manifest),
        ObjectData::Tree(tree) => encode_tree(tree),
        ObjectData::Commit(commit) => encode_commit(commit),
    }
}

pub fn decode_object(kind: ObjectKind, payload: &[u8]) -> Option<ObjectData> {
    match kind {
        ObjectKind::Chunk => Some(ObjectData::Chunk(payload.to_vec())),
        ObjectKind::Manifest => decode_manifest(payload).map(ObjectData::Manifest),
        ObjectKind::Tree => decode_tree(payload).map(ObjectData::Tree),
        ObjectKind::Commit => decode_commit(payload).map(ObjectData::Commit),
    }
}

pub fn encode_manifest(manifest: &Manifest) -> Vec<u8> {
    let mut out = Vec::new();
    write_u64(&mut out, manifest.file_len);
    write_u32(&mut out, manifest.mode);
    write_u32(&mut out, manifest.chunk_size);
    write_u64(&mut out, manifest.chunks.len() as u64);
    for chunk in &manifest.chunks {
        out.extend_from_slice(chunk.as_bytes());
    }
    out
}

pub fn decode_manifest(data: &[u8]) -> Option<Manifest> {
    let mut cursor = Cursor::new(data);
    let file_len = read_u64(&mut cursor)?;
    let mode = read_u32(&mut cursor)?;
    let chunk_size = read_u32(&mut cursor)?;
    let count = read_u64(&mut cursor)? as usize;
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        let mut buf = [0u8; 32];
        cursor.read_exact(&mut buf).ok()?;
        chunks.push(Oid::new(buf));
    }
    if cursor.position() as usize != data.len() {
        return None;
    }
    Some(Manifest {
        file_len,
        mode,
        chunk_size,
        chunks,
    })
}

pub fn encode_tree(tree: &Tree) -> Vec<u8> {
    let mut out = Vec::new();
    write_u64(&mut out, tree.entries.len() as u64);
    for entry in &tree.entries {
        write_bytes(&mut out, &entry.name);
        out.push(entry.kind as u8);
        write_u32(&mut out, entry.mode);
        out.extend_from_slice(entry.oid.as_bytes());
    }
    out
}

pub fn decode_tree(data: &[u8]) -> Option<Tree> {
    let mut cursor = Cursor::new(data);
    let count = read_u64(&mut cursor)? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let name = read_bytes(&mut cursor)?;
        let kind = read_u8(&mut cursor)?;
        let kind = match kind {
            1 => TreeEntryKind::File,
            2 => TreeEntryKind::Dir,
            3 => TreeEntryKind::Symlink,
            _ => return None,
        };
        let mode = read_u32(&mut cursor)?;
        let mut oid = [0u8; 32];
        cursor.read_exact(&mut oid).ok()?;
        entries.push(TreeEntry {
            name,
            kind,
            mode,
            oid: Oid::new(oid),
        });
    }
    if cursor.position() as usize != data.len() {
        return None;
    }
    Some(Tree { entries })
}

pub fn encode_commit(commit: &Commit) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(commit.root.as_bytes());
    write_u64(&mut out, commit.parents.len() as u64);
    for parent in &commit.parents {
        out.extend_from_slice(parent.as_bytes());
    }
    write_string(&mut out, &commit.author);
    write_i64(&mut out, commit.timestamp);
    write_string(&mut out, &commit.message);
    out
}

pub fn decode_commit(data: &[u8]) -> Option<Commit> {
    let mut cursor = Cursor::new(data);
    let mut root = [0u8; 32];
    cursor.read_exact(&mut root).ok()?;
    let count = read_u64(&mut cursor)? as usize;
    let mut parents = Vec::with_capacity(count);
    for _ in 0..count {
        let mut buf = [0u8; 32];
        cursor.read_exact(&mut buf).ok()?;
        parents.push(Oid::new(buf));
    }
    let author = read_string(&mut cursor)?;
    let timestamp = read_i64(&mut cursor)?;
    let message = read_string(&mut cursor)?;
    if cursor.position() as usize != data.len() {
        return None;
    }
    Some(Commit {
        root: Oid::new(root),
        parents,
        author,
        timestamp,
        message,
    })
}

pub fn domain_for(kind: ObjectKind) -> &'static [u8] {
    match kind {
        ObjectKind::Chunk => DOMAIN_CHUNK,
        ObjectKind::Manifest => DOMAIN_MANIFEST,
        ObjectKind::Tree => DOMAIN_TREE,
        ObjectKind::Commit => DOMAIN_COMMIT,
    }
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    write_bytes(out, value.as_bytes());
}

fn read_u8(cursor: &mut Cursor<&[u8]>) -> Option<u8> {
    let mut buf = [0u8; 1];
    cursor.read_exact(&mut buf).ok()?;
    Some(buf[0])
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Option<u64> {
    let mut buf = [0u8; 8];
    cursor.read_exact(&mut buf).ok()?;
    Some(u64::from_be_bytes(buf))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Option<u32> {
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf).ok()?;
    Some(u32::from_be_bytes(buf))
}

fn read_i64(cursor: &mut Cursor<&[u8]>) -> Option<i64> {
    let mut buf = [0u8; 8];
    cursor.read_exact(&mut buf).ok()?;
    Some(i64::from_be_bytes(buf))
}

fn read_bytes(cursor: &mut Cursor<&[u8]>) -> Option<Vec<u8>> {
    let len = read_u64(cursor)? as usize;
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn read_string(cursor: &mut Cursor<&[u8]>) -> Option<String> {
    let bytes = read_bytes(cursor)?;
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip() {
        let manifest = Manifest {
            file_len: 12,
            mode: 0o100644,
            chunk_size: 1024,
            chunks: vec![Oid::new([0x11; 32]), Oid::new([0x22; 32])],
        };
        let encoded = encode_manifest(&manifest);
        let decoded = decode_manifest(&encoded).expect("decode");
        assert_eq!(manifest, decoded);
    }

    #[test]
    fn tree_roundtrip() {
        let tree = Tree {
            entries: vec![TreeEntry {
                name: b"file.txt".to_vec(),
                kind: TreeEntryKind::File,
                mode: 0o100644,
                oid: Oid::new([0x33; 32]),
            }],
        };
        let encoded = encode_tree(&tree);
        let decoded = decode_tree(&encoded).expect("decode");
        assert_eq!(tree, decoded);
    }

    #[test]
    fn commit_roundtrip() {
        let commit = Commit {
            root: Oid::new([0x44; 32]),
            parents: vec![Oid::new([0x55; 32])],
            author: "Test <test@example.com>".to_string(),
            timestamp: 42,
            message: "hello".to_string(),
        };
        let encoded = encode_commit(&commit);
        let decoded = decode_commit(&encoded).expect("decode");
        assert_eq!(commit, decoded);
    }
}
