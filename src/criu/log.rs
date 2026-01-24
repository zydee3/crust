use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::criu::options::opts;

pub const DEFAULT_LOGFD: RawFd = libc::STDERR_FILENO;

static LOG_FD: AtomicI32 = AtomicI32::new(libc::STDERR_FILENO);
static INIT_DONE: AtomicBool = AtomicBool::new(false);

pub fn log_get_fd() -> RawFd {
    LOG_FD.load(Ordering::Relaxed)
}

fn reset_buf_off() {
    // In Rust port, we use the log crate which handles buffering.
    // This is a no-op but maintains interface compatibility.
}

pub fn log_init(output: Option<&str>) -> i32 {
    reset_buf_off();

    let new_logfd = match output {
        Some("-") => unsafe { libc::dup(libc::STDOUT_FILENO) },
        Some(path) => {
            let c_path = match CString::new(path) {
                Ok(p) => p,
                Err(_) => return -1,
            };
            unsafe {
                libc::open(
                    c_path.as_ptr(),
                    libc::O_CREAT | libc::O_TRUNC | libc::O_WRONLY | libc::O_APPEND,
                    0o600,
                )
            }
        }
        None => unsafe { libc::dup(DEFAULT_LOGFD) },
    };

    if new_logfd < 0 {
        log::error!("Log engine failure, can't create log fd");
        return -1;
    }

    LOG_FD.store(new_logfd, Ordering::Relaxed);
    INIT_DONE.store(true, Ordering::Relaxed);

    0
}

pub fn log_init_by_pid(pid: libc::pid_t) -> i32 {
    /*
     * reset buf_off as this fn is called on each fork while
     * restoring process tree
     */
    reset_buf_off();

    let opts = opts();
    if opts.log_file_per_pid == 0 {
        return 0;
    }

    let output = match &opts.output {
        Some(o) => o.clone(),
        None => return 0,
    };

    let path = format!("{}.{}", output, pid);
    log_init(Some(&path))
}
