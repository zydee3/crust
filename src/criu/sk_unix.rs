use std::sync::{Mutex, OnceLock};

use crate::proto::UnixSkEntry;

const SK_INFO_HASH_SIZE: usize = 32;

pub struct UnixSkInfo {
    pub ue: UnixSkEntry,
}

impl UnixSkInfo {
    pub fn new(ue: UnixSkEntry) -> Self {
        Self { ue }
    }
}

struct SkInfoHash {
    buckets: Vec<Vec<UnixSkInfo>>,
}

impl SkInfoHash {
    const fn new() -> Self {
        Self { buckets: Vec::new() }
    }

    fn init(&mut self) {
        self.buckets = (0..SK_INFO_HASH_SIZE).map(|_| Vec::new()).collect();
    }

    fn add(&mut self, entry: UnixSkInfo) {
        let bucket = (entry.ue.ino as usize) % SK_INFO_HASH_SIZE;
        self.buckets[bucket].push(entry);
    }

    fn find(&self, ino: u32) -> Option<&UnixSkInfo> {
        let bucket = (ino as usize) % SK_INFO_HASH_SIZE;
        self.buckets[bucket].iter().find(|e| e.ue.ino == ino)
    }
}

static SK_INFO_HASH: OnceLock<Mutex<SkInfoHash>> = OnceLock::new();

fn get_sk_info_hash() -> &'static Mutex<SkInfoHash> {
    SK_INFO_HASH.get_or_init(|| Mutex::new(SkInfoHash::new()))
}

pub fn init_sk_info_hash() {
    let mut hash = get_sk_info_hash().lock().unwrap();
    hash.init();
}

pub fn sk_info_add(entry: UnixSkInfo) {
    let mut hash = get_sk_info_hash().lock().unwrap();
    hash.add(entry);
}

pub fn sk_info_find(ino: u32) -> bool {
    let hash = get_sk_info_hash().lock().unwrap();
    hash.find(ino).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_sk_info_hash() {
        init_sk_info_hash();
        // Should not panic
    }
}
