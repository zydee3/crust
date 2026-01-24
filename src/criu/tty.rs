//! TTY restore functionality

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::criu::fdstore::{fdstore_add, FdstoreDesc};
use crate::criu::lock::Mutex;
use crate::criu::options::opts;
use crate::criu::rst_malloc::shmalloc;
use crate::criu::servicefd::ServiceFdState;

static mut TTY_MUTEX: Option<*mut Mutex> = None;
static STDIN_ISATTY: AtomicBool = AtomicBool::new(false);
static SELF_STDIN_FDID: AtomicI32 = AtomicI32::new(-1);

pub fn tty_init_restore() -> i32 {
    let ptr = shmalloc(std::mem::size_of::<Mutex>()) as *mut Mutex;
    if ptr.is_null() {
        log::error!("Can't create ptmx index mutex");
        return -1;
    }

    unsafe {
        (*ptr).init();
        TTY_MUTEX = Some(ptr);
    }

    0
}

pub fn tty_mutex() -> Option<&'static Mutex> {
    unsafe { TTY_MUTEX.map(|p| &*p) }
}

pub fn stdin_isatty() -> bool {
    STDIN_ISATTY.load(Ordering::Relaxed)
}

pub fn self_stdin_fdid() -> i32 {
    SELF_STDIN_FDID.load(Ordering::Relaxed)
}

pub fn tty_prep_fds(sfd_state: &ServiceFdState, fdstore_desc: &mut FdstoreDesc) -> i32 {
    if opts().shell_job == 0 {
        return 0;
    }

    if unsafe { libc::isatty(libc::STDIN_FILENO) } == 0 {
        log::info!("Standard stream is not a terminal, may fail later");
    } else {
        STDIN_ISATTY.store(true, Ordering::Relaxed);
    }

    match fdstore_add(sfd_state, fdstore_desc, libc::STDIN_FILENO) {
        Ok(id) => {
            SELF_STDIN_FDID.store(id, Ordering::Relaxed);
            0
        }
        Err(_) => {
            log::error!("Can't place stdin fd to fdstore");
            -1
        }
    }
}
