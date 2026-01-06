use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const CHUNK_SIZE: usize = 1024 * 1024;

pub fn chunk_file<F>(path: &Path, mut handler: F) -> anyhow::Result<u64>
where
    F: FnMut(&[u8]) -> anyhow::Result<()>,
{
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        handler(&buf[..read])?;
    }
    Ok(total)
}
