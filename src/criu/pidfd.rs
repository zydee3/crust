use std::sync::{Mutex, OnceLock};

const DEAD_PIDFD_HASH_SIZE: usize = 32;

pub struct DeadPidfd {
    pub ino: u32,
}

struct DeadPidfdHash {
    buckets: Vec<Vec<DeadPidfd>>,
}

impl DeadPidfdHash {
    const fn new() -> Self {
        Self { buckets: Vec::new() }
    }

    fn init(&mut self) {
        self.buckets = (0..DEAD_PIDFD_HASH_SIZE).map(|_| Vec::new()).collect();
    }

    fn add(&mut self, entry: DeadPidfd) {
        let bucket = (entry.ino as usize) % DEAD_PIDFD_HASH_SIZE;
        self.buckets[bucket].push(entry);
    }

    fn find(&self, ino: u32) -> Option<&DeadPidfd> {
        let bucket = (ino as usize) % DEAD_PIDFD_HASH_SIZE;
        self.buckets[bucket].iter().find(|e| e.ino == ino)
    }
}

static DEAD_PIDFD_HASH: OnceLock<Mutex<DeadPidfdHash>> = OnceLock::new();

fn get_dead_pidfd_hash() -> &'static Mutex<DeadPidfdHash> {
    DEAD_PIDFD_HASH.get_or_init(|| Mutex::new(DeadPidfdHash::new()))
}

pub fn init_dead_pidfd_hash() {
    let mut hash = get_dead_pidfd_hash().lock().unwrap();
    // Only init if not already initialized
    if hash.buckets.is_empty() {
        hash.init();
    }
}

pub fn dead_pidfd_add(entry: DeadPidfd) {
    let mut hash = get_dead_pidfd_hash().lock().unwrap();
    hash.add(entry);
}

pub fn dead_pidfd_find(ino: u32) -> bool {
    let hash = get_dead_pidfd_hash().lock().unwrap();
    hash.find(ino).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_dead_pidfd_hash() {
        init_dead_pidfd_hash();
        // Should not panic
    }

    #[test]
    fn test_dead_pidfd_add_and_find() {
        // Use a unique ino to avoid interference with other tests
        let test_ino = 999123u32;

        init_dead_pidfd_hash();
        dead_pidfd_add(DeadPidfd { ino: test_ino });
        assert!(dead_pidfd_find(test_ino));
        assert!(!dead_pidfd_find(888888));
    }
}
