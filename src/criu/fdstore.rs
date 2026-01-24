use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};

use super::rst_malloc::shmalloc;
use super::scm::{recv_fds, send_fd};
use super::servicefd::{ServiceFdState, SfdType};
use super::sockets::sk_setbufs;

#[repr(C)]
pub struct Mutex {
    raw: AtomicI32,
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
                // We got the lock
                return;
            }
            // Contended - wait on futex
            unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    &self.raw as *const AtomicI32 as *const u32,
                    libc::FUTEX_WAIT,
                    c as u32,
                    ptr::null::<libc::timespec>(),
                    ptr::null::<u32>(),
                    0u32,
                );
            }
        }
    }

    pub fn unlock(&self) {
        self.raw.store(0, Ordering::SeqCst);
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                &self.raw as *const AtomicI32 as *const u32,
                libc::FUTEX_WAKE,
                1,
                ptr::null::<libc::timespec>(),
                ptr::null::<u32>(),
                0u32,
            );
        }
    }
}

impl Default for Mutex {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
pub struct FdstoreDesc {
    pub next_id: i32,
    pub lock: Mutex,
}

impl FdstoreDesc {
    pub const fn new() -> Self {
        Self {
            next_id: 0,
            lock: Mutex::new(),
        }
    }

    pub fn init(&mut self) {
        self.next_id = 0;
        self.lock.init();
    }
}

impl Default for FdstoreDesc {
    fn default() -> Self {
        Self::new()
    }
}

pub fn fdstore_add(sfd_state: &ServiceFdState, desc: &mut FdstoreDesc, fd: RawFd) -> Result<i32, i32> {
    let sk = sfd_state.get_service_fd(SfdType::FdstoreSkOff);
    if sk < 0 {
        return Err(-1);
    }

    desc.lock.lock();

    let ret = send_fd(sk, None, 0, fd);
    if let Err(e) = ret {
        // pr_perror equivalent - caller should log
        desc.lock.unlock();
        return Err(e);
    }

    let id = desc.next_id;
    desc.next_id += 1;

    desc.lock.unlock();

    Ok(id)
}

pub fn fdstore_get(sfd_state: &ServiceFdState, desc: &FdstoreDesc, id: i32) -> Result<RawFd, i32> {
    let sk = sfd_state.get_service_fd(SfdType::FdstoreSkOff);
    if sk < 0 {
        return Err(-1);
    }

    desc.lock.lock();

    // Set the peek offset to the id
    let ret = unsafe {
        libc::setsockopt(
            sk,
            libc::SOL_SOCKET,
            libc::SO_PEEK_OFF,
            &id as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        desc.lock.unlock();
        return Err(unsafe { *libc::__errno_location() });
    }

    // Receive the fd with MSG_PEEK
    let mut fd: i32 = -1;
    let ret = recv_fds(sk, std::slice::from_mut(&mut fd), None, 0, libc::MSG_PEEK);
    if ret < 0 {
        desc.lock.unlock();
        return Err(ret);
    }

    desc.lock.unlock();

    Ok(fd)
}

pub fn fdstore_init(
    sfd_state: &mut ServiceFdState,
    criu_run_id: &str,
) -> Result<*mut FdstoreDesc, i32> {
    // In kernel a bufsize has type int and a value is doubled.
    let buf: [u32; 2] = [i32::MAX as u32 / 2, i32::MAX as u32 / 2];

    let desc = shmalloc(std::mem::size_of::<FdstoreDesc>()) as *mut FdstoreDesc;
    if desc.is_null() {
        return Err(-1);
    }

    unsafe {
        (*desc).next_id = 0;
        (*desc).lock.init();
    }

    let sk = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
    if sk < 0 {
        log::error!("Unable to create a socket");
        return Err(-1);
    }

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(sk, &mut st) } != 0 {
        log::error!("Unable to stat a file descriptor");
        unsafe { libc::close(sk) };
        return Err(-1);
    }

    if sk_setbufs(sk, buf[0], buf[1], false) != 0 {
        unsafe { libc::close(sk) };
        return Err(-1);
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;

    // Format the socket path: X/criu-fdstore-<inode>-<run_id>
    // The X will be replaced with null byte (abstract socket)
    let path = format!("X/criu-fdstore-{:x}-{}", st.st_ino, criu_run_id);
    let path_bytes = path.as_bytes();
    let copy_len = std::cmp::min(path_bytes.len(), addr.sun_path.len() - 1);
    for (i, &b) in path_bytes[..copy_len].iter().enumerate() {
        addr.sun_path[i] = b as i8;
    }
    // Set abstract namespace (first byte = 0)
    addr.sun_path[0] = 0;

    let addrlen = (std::mem::size_of::<libc::sa_family_t>() + copy_len) as libc::socklen_t;

    if unsafe { libc::bind(sk, &addr as *const _ as *const libc::sockaddr, addrlen) } != 0 {
        log::error!("Unable to bind a socket");
        unsafe { libc::close(sk) };
        return Err(-1);
    }

    if unsafe { libc::connect(sk, &addr as *const _ as *const libc::sockaddr, addrlen) } != 0 {
        log::error!("Unable to connect a socket");
        unsafe { libc::close(sk) };
        return Err(-1);
    }

    let ret = sfd_state.install_service_fd(SfdType::FdstoreSkOff, sk);
    if ret < 0 {
        return Err(-1);
    }

    Ok(desc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutex_new() {
        let m = Mutex::new();
        assert_eq!(m.raw.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_fdstore_desc_new() {
        let desc = FdstoreDesc::new();
        assert_eq!(desc.next_id, 0);
    }

    #[test]
    fn test_mutex_lock_unlock() {
        let m = Mutex::new();
        m.lock();
        // We have the lock
        m.unlock();
        // Lock released
        assert_eq!(m.raw.load(Ordering::SeqCst), 0);
    }
}
