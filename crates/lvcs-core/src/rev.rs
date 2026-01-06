use std::path::PathBuf;

use crate::oid::Oid;
use crate::refs::{read_head, read_ref, Head};
use crate::repo::Repo;

pub fn resolve_rev(repo: &Repo, rev: Option<&str>) -> anyhow::Result<Oid> {
    match rev {
        None | Some("HEAD") => resolve_head(repo),
        Some(rev) => resolve_name(repo, rev),
    }
}

fn resolve_head(repo: &Repo) -> anyhow::Result<Oid> {
    match read_head(repo)? {
        Head::Symbolic(path) => {
            read_ref(repo, &path)?.ok_or_else(|| anyhow::anyhow!("unborn branch"))
        }
        Head::Detached(oid) => Ok(oid),
    }
}

fn resolve_name(repo: &Repo, rev: &str) -> anyhow::Result<Oid> {
    if let Some(oid) = Oid::from_hex(rev) {
        return Ok(oid);
    }
    if rev.starts_with("refs/") {
        let path = PathBuf::from(rev);
        return read_ref(repo, &path)?.ok_or_else(|| anyhow::anyhow!("unknown ref"));
    }
    let head_path = PathBuf::from(format!("refs/heads/{rev}"));
    if let Some(oid) = read_ref(repo, &head_path)? {
        return Ok(oid);
    }
    let tag_path = PathBuf::from(format!("refs/tags/{rev}"));
    if let Some(oid) = read_ref(repo, &tag_path)? {
        return Ok(oid);
    }
    Err(anyhow::anyhow!("unknown revision"))
}
