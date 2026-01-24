use std::mem;
use std::sync::atomic::{AtomicI32, Ordering};

use super::fdstore::{fdstore_add, fdstore_get, FdstoreDesc};
use super::lock::Mutex;
use super::options::opts;
use super::rst_malloc::shmalloc;
use super::servicefd::ServiceFdState;

pub const LAZY_PAGES_SOCK_NAME: &str = "lazy-pages.socket";
pub const LAZY_PAGES_RESTORE_FINISHED: u32 = 0x52535446; // ReSTore Finished

static LAZY_PAGES_SK_ID: AtomicI32 = AtomicI32::new(-1);
static mut LAZY_SOCK_MUTEX: *mut Mutex = std::ptr::null_mut();

pub fn prepare_sock_addr(saddr: &mut libc::sockaddr_un) -> i32 {
    *saddr = unsafe { mem::zeroed() };

    saddr.sun_family = libc::AF_UNIX as libc::sa_family_t;

    let name = LAZY_PAGES_SOCK_NAME;
    let max_len = saddr.sun_path.len();

    if name.len() >= max_len {
        log::error!("Wrong UNIX socket name: {}", name);
        return -1;
    }

    for (i, byte) in name.bytes().enumerate() {
        saddr.sun_path[i] = byte as i8;
    }

    0
}

pub fn prepare_lazy_pages_socket(
    sfd_state: &ServiceFdState,
    fdstore_desc: &mut FdstoreDesc,
) -> i32 {
    if !opts().lazy_pages {
        return 0;
    }

    let mut sun: libc::sockaddr_un = unsafe { mem::zeroed() };
    if prepare_sock_addr(&mut sun) != 0 {
        return -1;
    }

    let mutex = shmalloc(mem::size_of::<Mutex>()) as *mut Mutex;
    if mutex.is_null() {
        return -1;
    }
    unsafe {
        (*mutex).init();
        LAZY_SOCK_MUTEX = mutex;
    }

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return -1;
    }

    let len = mem::offset_of!(libc::sockaddr_un, sun_path)
        + LAZY_PAGES_SOCK_NAME.len();
    let ret = unsafe {
        libc::connect(
            fd,
            &sun as *const libc::sockaddr_un as *const libc::sockaddr,
            len as libc::socklen_t,
        )
    };
    if ret < 0 {
        log::error!("connect to {} failed", LAZY_PAGES_SOCK_NAME);
        unsafe { libc::close(fd) };
        return -1;
    }

    match fdstore_add(sfd_state, fdstore_desc, fd) {
        Ok(id) => {
            LAZY_PAGES_SK_ID.store(id, Ordering::SeqCst);
        }
        Err(_) => {
            log::error!("Can't add fd to fdstore");
            unsafe { libc::close(fd) };
            return -1;
        }
    }

    unsafe { libc::close(fd) };
    0
}

pub fn lazy_pages_finish_restore(
    sfd_state: &ServiceFdState,
    fdstore_desc: &FdstoreDesc,
) -> i32 {
    if !opts().lazy_pages {
        return 0;
    }

    let id = LAZY_PAGES_SK_ID.load(Ordering::SeqCst);
    let fd = match fdstore_get(sfd_state, fdstore_desc, id) {
        Ok(f) => f,
        Err(_) => {
            log::error!("No lazy-pages socket");
            return -1;
        }
    };

    let fin: u32 = LAZY_PAGES_RESTORE_FINISHED;
    let ret = unsafe {
        libc::send(
            fd,
            &fin as *const u32 as *const libc::c_void,
            mem::size_of::<u32>(),
            0,
        )
    };

    if ret != mem::size_of::<u32>() as isize {
        log::error!("Failed sending restore finished indication");
    }

    unsafe { libc::close(fd) };

    if ret < 0 { ret as i32 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_sock_addr() {
        let mut saddr: libc::sockaddr_un = unsafe { mem::zeroed() };
        let result = prepare_sock_addr(&mut saddr);
        assert_eq!(result, 0);
        assert_eq!(saddr.sun_family, libc::AF_UNIX as libc::sa_family_t);

        // Check that the path is set correctly
        let path_bytes: Vec<u8> = saddr
            .sun_path
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as u8)
            .collect();
        let path = String::from_utf8(path_bytes).unwrap();
        assert_eq!(path, LAZY_PAGES_SOCK_NAME);
    }
}
