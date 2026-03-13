use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use crate::error::Error;

pub const PUBKEY_SIZE: usize = 32;

/// Load all vanished pubkeys from file into a HashSet (deduplicates on load).
pub fn load(path: &Path) -> Result<HashSet<[u8; 32]>, Error> {
    let mut set = HashSet::new();
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(set),
        Err(e) => return Err(e.into()),
    };
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    for chunk in buf.chunks_exact(PUBKEY_SIZE) {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(chunk);
        set.insert(pk);
    }
    Ok(set)
}

/// Append a pubkey to the vanished file.
pub fn append(file: &mut File, pubkey: &[u8; 32]) -> Result<(), Error> {
    file.write_all(pubkey)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

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
        let mut f = OpenOptions::new().create(true).append(true).open(&path).unwrap();
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
        let mut f = OpenOptions::new().create(true).append(true).open(&path).unwrap();
        let pk = [0xCC; 32];
        append(&mut f, &pk).unwrap();
        append(&mut f, &pk).unwrap();
        let set = load(&path).unwrap();
        assert_eq!(set.len(), 1);
    }
}
