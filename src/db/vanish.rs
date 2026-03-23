use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use crate::db::store::{FILE_HEADER, HEADER_SIZE};
use crate::error::Error;

pub const PUBKEY_SIZE: usize = 32;

/// Load all vanished pubkeys from file into a HashSet (deduplicates on load).
/// Skips the 4-byte file header. Migrates headerless files on first load.
pub fn load(path: &Path) -> Result<HashSet<[u8; 32]>, Error> {
    let mut set = HashSet::new();
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(set),
        Err(e) => return Err(e.into()),
    };
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    if buf.is_empty() {
        return Ok(set);
    }

    // Migrate headerless files.
    let data = if buf.len() >= HEADER_SIZE && buf[..HEADER_SIZE] == FILE_HEADER {
        &buf[HEADER_SIZE..]
    } else {
        // Old file without header — migrate in place.
        drop(file);
        let mut tmp = Vec::with_capacity(HEADER_SIZE + buf.len());
        tmp.extend_from_slice(&FILE_HEADER);
        tmp.extend_from_slice(&buf);
        std::fs::write(path, &tmp)?;
        &buf[..]
    };

    for chunk in data.chunks_exact(PUBKEY_SIZE) {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(chunk);
        set.insert(pk);
    }
    Ok(set)
}

/// Open or create the vanished file for appending, writing the header if new.
pub fn open_append(path: &Path) -> Result<File, Error> {
    use std::fs::OpenOptions;
    let exists = path.exists();
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    if !exists || file.metadata()?.len() == 0 {
        (&file).write_all(&FILE_HEADER)?;
    }
    Ok(file)
}

/// Append a pubkey to the vanished file.
pub fn append(file: &mut File, pubkey: &[u8; 32]) -> Result<(), Error> {
    file.write_all(pubkey)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanished.r");
        File::create(&path).unwrap();
        let set = load(&path).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn test_load_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanished.r");
        let set = load(&path).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn test_append_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanished.r");
        let mut f = open_append(&path).unwrap();
        let pk1 = [0xAA; 32];
        let pk2 = [0xBB; 32];
        append(&mut f, &pk1).unwrap();
        append(&mut f, &pk2).unwrap();
        let set = load(&path).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains(&pk1));
        assert!(set.contains(&pk2));
    }

    #[test]
    fn test_load_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanished.r");
        let mut f = open_append(&path).unwrap();
        let pk = [0xCC; 32];
        append(&mut f, &pk).unwrap();
        append(&mut f, &pk).unwrap();
        let set = load(&path).unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_migrate_headerless_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vanished.r");
        // Write a pubkey without header (old format).
        let pk = [0xDD; 32];
        std::fs::write(&path, pk).unwrap();
        let set = load(&path).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&pk));
        // Verify file now has header.
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(&raw[..4], &FILE_HEADER);
        assert_eq!(&raw[4..], &pk);
    }
}
