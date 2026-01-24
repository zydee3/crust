use std::sync::atomic::{AtomicI32, Ordering};

pub const FUTEX_ABORT_FLAG: u32 = 0x80000000;
pub const FUTEX_ABORT_RAW: u32 = u32::MAX;

#[derive(Debug)]
#[repr(C)]
pub struct Futex {
    pub raw: AtomicI32,
}

impl Default for Futex {
    fn default() -> Self {
        Self::new()
    }
}

impl Futex {
    pub const fn new() -> Self {
        Self {
            raw: AtomicI32::new(0),
        }
    }

    pub fn get(&self) -> u32 {
        self.raw.load(Ordering::SeqCst) as u32
    }

    pub fn set(&self, v: u32) {
        self.raw.store(v as i32, Ordering::SeqCst);
    }

    pub fn set_and_wake(&self, v: u32) {
        self.set(v);
        self.wake();
    }

    pub fn wake(&self) {
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                &self.raw as *const AtomicI32,
                libc::FUTEX_WAKE,
                i32::MAX,
                std::ptr::null::<libc::timespec>(),
                std::ptr::null::<u32>(),
                0u32,
            );
        }
    }

    pub fn abort_and_wake(&self) {
        self.set_and_wake(FUTEX_ABORT_RAW);
    }

    pub fn dec_and_wake(&self) {
        self.raw.fetch_sub(1, Ordering::SeqCst);
        self.wake();
    }

    pub fn inc_and_wake(&self) {
        self.raw.fetch_add(1, Ordering::SeqCst);
        self.wake();
    }

    pub fn inc(&self) {
        self.raw.fetch_add(1, Ordering::SeqCst);
    }

    pub fn dec(&self) {
        self.raw.fetch_sub(1, Ordering::SeqCst);
    }

    fn sys_futex_wait(&self, expected: u32, timeout: Option<&libc::timespec>) -> i32 {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_futex,
                &self.raw as *const AtomicI32,
                libc::FUTEX_WAIT,
                expected as i32,
                timeout.map_or(std::ptr::null(), |t| t as *const _),
                std::ptr::null::<u32>(),
                0u32,
            )
        };
        if ret == -1 {
            -unsafe { *libc::__errno_location() }
        } else {
            ret as i32
        }
    }

    pub fn wait_until(&self, v: u32) {
        let timeout = libc::timespec {
            tv_sec: 120,
            tv_nsec: 0,
        };
        loop {
            let tmp = self.get();
            if (tmp & FUTEX_ABORT_FLAG) != 0 || tmp == v {
                break;
            }
            let ret = self.sys_futex_wait(tmp, Some(&timeout));
            if ret == -libc::ETIMEDOUT || ret == -libc::EINTR || ret == -libc::EWOULDBLOCK {
                continue;
            }
            if ret < 0 {
                panic!("futex_wait_until failed: {}", ret);
            }
        }
    }

    pub fn wait_while_gt(&self, v: u32) {
        let timeout = libc::timespec {
            tv_sec: 120,
            tv_nsec: 0,
        };
        loop {
            let tmp = self.get();
            if (tmp & FUTEX_ABORT_FLAG) != 0 || tmp <= v {
                break;
            }
            let ret = self.sys_futex_wait(tmp, Some(&timeout));
            if ret == -libc::ETIMEDOUT || ret == -libc::EINTR || ret == -libc::EWOULDBLOCK {
                continue;
            }
            if ret < 0 {
                panic!("futex_wait_while_gt failed: {}", ret);
            }
        }
    }

    pub fn wait_while_lt(&self, v: u32) {
        let timeout = libc::timespec {
            tv_sec: 120,
            tv_nsec: 0,
        };
        loop {
            let tmp = self.get();
            if (tmp & FUTEX_ABORT_FLAG) != 0 || tmp >= v {
                break;
            }
            let ret = self.sys_futex_wait(tmp, Some(&timeout));
            if ret == -libc::ETIMEDOUT || ret == -libc::EINTR || ret == -libc::EWOULDBLOCK {
                continue;
            }
            if ret < 0 {
                panic!("futex_wait_while_lt failed: {}", ret);
            }
        }
    }

    pub fn wait_while_eq(&self, v: u32) {
        let timeout = libc::timespec {
            tv_sec: 120,
            tv_nsec: 0,
        };
        loop {
            let tmp = self.get();
            if (tmp & FUTEX_ABORT_FLAG) != 0 || tmp != v {
                break;
            }
            let ret = self.sys_futex_wait(tmp, Some(&timeout));
            if ret == -libc::ETIMEDOUT || ret == -libc::EINTR || ret == -libc::EWOULDBLOCK {
                continue;
            }
            if ret < 0 {
                panic!("futex_wait_while_eq failed: {}", ret);
            }
        }
    }

    pub fn wait_while(&self, v: u32) {
        while self.get() == v {
            let ret = self.sys_futex_wait(v, None);
            if ret < 0 && ret != -libc::EWOULDBLOCK {
                panic!("futex_wait_while failed: {}", ret);
            }
        }
    }
}

#[repr(C)]
pub struct Mutex {
    pub raw: AtomicI32,
}

impl Default for Mutex {
    fn default() -> Self {
        Self::new()
    }
}

impl Mutex {
    pub const fn new() -> Self {
        Self {
            raw: AtomicI32::new(0),
        }
    }

    pub fn init(&self) {
        self.raw.store(0, Ordering::SeqCst);
    }

    pub fn lock(&self) {
        loop {
            let c = self.raw.fetch_add(1, Ordering::SeqCst) + 1;
            if c == 1 {
                break;
            }
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    &self.raw as *const AtomicI32,
                    libc::FUTEX_WAIT,
                    c,
                    std::ptr::null::<libc::timespec>(),
                    std::ptr::null::<u32>(),
                    0u32,
                )
            };
            if ret == -1 {
                let errno = unsafe { *libc::__errno_location() };
                if errno != libc::EWOULDBLOCK {
                    panic!("mutex_lock futex failed: {}", errno);
                }
            }
        }
    }

    pub fn trylock(&self) -> bool {
        self.raw.fetch_add(1, Ordering::SeqCst) + 1 == 1
    }

    pub fn unlock(&self) {
        self.raw.store(0, Ordering::SeqCst);
        let ret = unsafe {
            libc::syscall(
                libc::SYS_futex,
                &self.raw as *const AtomicI32,
                libc::FUTEX_WAKE,
                1,
                std::ptr::null::<libc::timespec>(),
                std::ptr::null::<u32>(),
                0u32,
            )
        };
        if ret == -1 {
            panic!("mutex_unlock futex wake failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_futex_set_get() {
        let f = Futex::new();
        assert_eq!(f.get(), 0);
        f.set(42);
        assert_eq!(f.get(), 42);
    }

    #[test]
    fn test_futex_inc_dec() {
        let f = Futex::new();
        f.set(10);
        f.inc();
        assert_eq!(f.get(), 11);
        f.dec();
        assert_eq!(f.get(), 10);
    }

    #[test]
    fn test_mutex_init() {
        let m = Mutex::new();
        assert_eq!(m.raw.load(Ordering::SeqCst), 0);
        m.init();
        assert_eq!(m.raw.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_mutex_lock_unlock() {
        let m = Mutex::new();
        m.lock();
        assert_eq!(m.raw.load(Ordering::SeqCst), 1);
        m.unlock();
        assert_eq!(m.raw.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_mutex_trylock() {
        let m = Mutex::new();
        assert!(m.trylock());
        assert!(!m.trylock()); // Second trylock should fail
        m.unlock();
        assert!(m.trylock()); // Should succeed after unlock
    }
}
