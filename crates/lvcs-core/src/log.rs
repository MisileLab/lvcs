use crate::commit::load_commit;
use crate::oid::Oid;
use crate::store::Store;

pub struct LogEntry {
    pub oid: Oid,
    pub commit: crate::object::Commit,
}

pub fn walk_commits(store: &Store, start: &Oid, max: usize) -> anyhow::Result<Vec<LogEntry>> {
    let mut out = Vec::new();
    let mut current = *start;
    let mut remaining = max;
    while remaining > 0 {
        let commit = load_commit(store, &current)?;
        out.push(LogEntry {
            oid: current,
            commit: commit.clone(),
        });
        remaining -= 1;
        if let Some(next) = commit.parents.first() {
            current = *next;
        } else {
            break;
        }
    }
    Ok(out)
}
