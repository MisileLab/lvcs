use std::fs;
use std::path::{Path, PathBuf};

use crate::oid::Oid;
use crate::repo::Repo;
use crate::util::atomic_write;

pub enum Head {
    Symbolic(PathBuf),
    Detached(Oid),
}

pub fn read_head(repo: &Repo) -> anyhow::Result<Head> {
    let data = fs::read(repo.head_path())?;
    let text = String::from_utf8_lossy(&data);
    if let Some(rest) = text.strip_prefix("ref: ") {
        let ref_path = rest.trim_end();
        Ok(Head::Symbolic(PathBuf::from(ref_path)))
    } else {
        let oid = Oid::from_hex(text.trim_end()).ok_or_else(|| anyhow::anyhow!("invalid HEAD"))?;
        Ok(Head::Detached(oid))
    }
}

pub fn write_head(repo: &Repo, head: &Head) -> anyhow::Result<()> {
    let data = match head {
        Head::Symbolic(path) => format!("ref: {}\n", path.display()),
        Head::Detached(oid) => format!("{}\n", oid.to_hex()),
    };
    atomic_write(&repo.head_path(), data.as_bytes())
}

pub fn read_ref(repo: &Repo, path: &Path) -> anyhow::Result<Option<Oid>> {
    let full = repo.repo_dir().join(path);
    if !full.exists() {
        return Ok(None);
    }
    let data = fs::read(full)?;
    let text = String::from_utf8_lossy(&data);
    let oid = Oid::from_hex(text.trim_end()).ok_or_else(|| anyhow::anyhow!("invalid ref"))?;
    Ok(Some(oid))
}

pub fn write_ref(repo: &Repo, path: &Path, oid: &Oid) -> anyhow::Result<()> {
    let full = repo.repo_dir().join(path);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = format!("{}\n", oid.to_hex());
    atomic_write(&full, data.as_bytes())
}

pub fn list_refs(repo: &Repo) -> anyhow::Result<Vec<(PathBuf, Oid)>> {
    let mut out = Vec::new();
    let refs_dir = repo.refs_dir();
    if !refs_dir.exists() {
        return Ok(out);
    }
    collect_refs(&refs_dir, PathBuf::new(), &mut out)?;
    Ok(out)
}

fn collect_refs(root: &Path, prefix: PathBuf, out: &mut Vec<(PathBuf, Oid)>) -> anyhow::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let mut rel = prefix.clone();
        rel.push(name);
        if entry.file_type()?.is_dir() {
            collect_refs(&path, rel, out)?;
        } else if entry.file_type()?.is_file() {
            let data = fs::read(&path)?;
            let text = String::from_utf8_lossy(&data);
            if let Some(oid) = Oid::from_hex(text.trim_end()) {
                out.push((rel, oid));
            }
        }
    }
    Ok(())
}
