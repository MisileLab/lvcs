use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing parent"))?;
    fs::create_dir_all(parent)?;

    let mut attempt = 0u32;
    let temp_path = loop {
        let candidate = temp_name(path, attempt);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                file.write_all(bytes)?;
                file.sync_all()?;
                drop(file);
                break candidate;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt = attempt.saturating_add(1);
                continue;
            }
            Err(err) => return Err(err.into()),
        }
    };

    fs::rename(&temp_path, path)?;
    sync_dir(parent)?;
    Ok(())
}

pub fn sync_dir(path: &Path) -> anyhow::Result<()> {
    let dir = File::open(path)?;
    dir.sync_all()?;
    Ok(())
}

fn temp_name(path: &Path, attempt: u32) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "temp".to_string());
    let candidate = format!(".{file_name}.tmp.{nanos}.{attempt}");
    path.with_file_name(candidate)
}
