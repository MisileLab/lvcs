use crate::object::{Commit, ObjectData};
use crate::oid::Oid;
use crate::refs::{read_head, read_ref, write_head, write_ref, Head};
use crate::repo::Repo;
use crate::snapshot::{build_commit, snapshot_worktree};
use crate::store::Store;

pub struct CommitResult {
    pub oid: Oid,
    pub root: Oid,
    pub parents: Vec<Oid>,
}

pub fn commit_worktree(
    repo: &Repo,
    store: &Store,
    author: String,
    timestamp: i64,
    message: String,
) -> anyhow::Result<CommitResult> {
    let head = read_head(repo)?;
    let mut parents = resolve_parents(repo, &head)?;
    if let Some((_base, other)) = crate::merge::read_merge_state(repo)? {
        parents.push(other);
    }
    let root = snapshot_worktree(repo, store)?;
    let commit = build_commit(root, parents.clone(), author, timestamp, message);
    let oid = store.write_object(&ObjectData::Commit(commit))?;
    update_head(repo, &head, &oid)?;
    crate::merge::clear_merge_state(repo)?;
    Ok(CommitResult { oid, root, parents })
}

fn resolve_parents(repo: &Repo, head: &Head) -> anyhow::Result<Vec<Oid>> {
    match head {
        Head::Symbolic(path) => Ok(read_ref(repo, path)?.into_iter().collect()),
        Head::Detached(oid) => Ok(vec![*oid]),
    }
}

fn update_head(repo: &Repo, head: &Head, oid: &Oid) -> anyhow::Result<()> {
    match head {
        Head::Symbolic(path) => write_ref(repo, path, oid),
        Head::Detached(_) => write_head(repo, &Head::Detached(*oid)),
    }
}

pub fn load_commit(store: &Store, oid: &Oid) -> anyhow::Result<Commit> {
    let (_kind, data) = store.read_object(oid)?;
    match data {
        ObjectData::Commit(commit) => Ok(commit),
        _ => anyhow::bail!("not a commit"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refs::read_ref;

    #[test]
    fn commit_updates_head_ref() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = Repo::init(temp.path()).expect("init");
        std::fs::write(temp.path().join("file.txt"), b"data").expect("write");
        let store = Store::new(repo.clone());
        let result = commit_worktree(&repo, &store, "tester".to_string(), 1, "msg".to_string())
            .expect("commit");

        let head = read_head(&repo).expect("head");
        let head_oid = match head {
            Head::Symbolic(path) => read_ref(&repo, &path).expect("ref").expect("oid"),
            Head::Detached(oid) => oid,
        };
        assert_eq!(head_oid, result.oid);
    }
}
