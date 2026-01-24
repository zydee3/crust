use std::ffi::CString;
use std::io::{self, Error, ErrorKind};
use std::os::unix::io::RawFd;
use std::sync::OnceLock;

use std::ffi::c_void;

use crate::criu::clone::clone_noasan_raw;
use crate::criu::log::log_get_fd;
use crate::criu::servicefd::{ServiceFdState, SfdType};

pub const CRS_CAN_FAIL: u32 = 0x1;
pub const PROC_NONE: libc::pid_t = -2;
pub const PROC_SELF: libc::pid_t = 0;
pub const PROC_GEN: libc::pid_t = -1;

/// Run ID hash length (UUID format: 8-4-4-4-12 = 36 chars + null = 37).
pub const RUN_ID_HASH_LENGTH: usize = 37;

/// Sentinel value indicating no dump run ID available.
pub const NO_DUMP_CRIU_RUN_ID: u8 = 0x7f;

/// Global CRIU run ID (generated at startup).
static CRIU_RUN_ID: OnceLock<String> = OnceLock::new();

/// Global dump CRIU run ID (read from checkpoint images).
static DUMP_CRIU_RUN_ID: OnceLock<String> = OnceLock::new();

/// Initializes the CRIU run ID with a UUID.
pub fn util_init() {
    let uuid = uuid::Uuid::new_v4();
    let run_id = uuid.to_string();
    let _ = CRIU_RUN_ID.set(run_id.clone());
    log::info!("CRIU run id = {}", run_id);
}

/// Gets the current CRIU run ID.
pub fn criu_run_id() -> Option<&'static str> {
    CRIU_RUN_ID.get().map(|s| s.as_str())
}

/// Sets the dump CRIU run ID (from checkpoint images).
pub fn set_dump_criu_run_id(id: &str) {
    let _ = DUMP_CRIU_RUN_ID.set(id.to_string());
}

/// Gets the dump CRIU run ID, or None if not set.
pub fn dump_criu_run_id() -> Option<&'static str> {
    DUMP_CRIU_RUN_ID.get().map(|s| s.as_str())
}

/// Checks if dump_criu_run_id indicates no dump run ID available.
pub fn dump_criu_run_id_unavailable() -> bool {
    match DUMP_CRIU_RUN_ID.get() {
        Some(s) => s.as_bytes().first().copied() == Some(NO_DUMP_CRIU_RUN_ID),
        None => true,
    }
}

pub fn write_all(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    let mut written = 0usize;
    let mut remaining = buf;

    while !remaining.is_empty() {
        let ret = unsafe {
            libc::write(fd, remaining.as_ptr() as *const libc::c_void, remaining.len())
        };

        if ret == -1 {
            let err = Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            /*
             * The caller should use standard write() for
             * non-blocking I/O.
             */
            if err.kind() == ErrorKind::WouldBlock {
                return Err(Error::from_raw_os_error(libc::EINVAL));
            }
            return Err(err);
        }

        let n = ret as usize;
        written += n;
        remaining = &remaining[n..];
    }

    Ok(written)
}

pub fn read_all(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0usize;
    let mut remaining = buf;

    while !remaining.is_empty() {
        let ret = unsafe {
            libc::read(fd, remaining.as_mut_ptr() as *mut libc::c_void, remaining.len())
        };

        if ret == -1 {
            let err = Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            /*
             * The caller should use standard read() for
             * non-blocking I/O.
             */
            if err.kind() == ErrorKind::WouldBlock {
                return Err(Error::from_raw_os_error(libc::EINVAL));
            }
            return Err(err);
        }

        if ret == 0 {
            break;
        }

        let n = ret as usize;
        total += n;
        remaining = &mut remaining[n..];
    }

    Ok(total)
}

pub fn cr_close_range(fd: u32, max_fd: u32, flags: u32) -> io::Result<()> {
    let ret = unsafe { libc::syscall(libc::SYS_close_range, fd, max_fd, flags) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn move_fd_from(img_fd: &mut RawFd, want_fd: RawFd) -> io::Result<()> {
    if *img_fd == want_fd {
        let tmp = unsafe { libc::dup(*img_fd) };
        if tmp < 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe { libc::close(*img_fd) };
        *img_fd = tmp;
    }

    Ok(())
}

pub fn close_fds(minfd: RawFd) -> io::Result<()> {
    if cr_close_range(minfd as u32, u32::MAX, 0).is_ok() {
        return Ok(());
    }

    let dir = std::fs::read_dir("/proc/self/fd")?;
    let dir_fd = {
        let path = std::ffi::CString::new("/proc/self/fd").unwrap();
        let dfd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        if dfd < 0 {
            return Err(io::Error::last_os_error());
        }
        dfd
    };

    for entry in dir {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if name_str == "." || name_str == ".." {
            continue;
        }

        if let Ok(fd) = name_str.parse::<RawFd>() {
            if fd == dir_fd {
                continue;
            }
            if fd < minfd {
                continue;
            }
            unsafe { libc::close(fd) };
        }
    }

    unsafe { libc::close(dir_fd) };
    Ok(())
}

pub fn reopen_fd_as(new_fd: RawFd, old_fd: RawFd) -> io::Result<()> {
    if old_fd != new_fd {
        let tmp = unsafe { libc::dup2(old_fd, new_fd) };
        if tmp < 0 {
            return Err(io::Error::last_os_error());
        }
        if tmp != new_fd {
            unsafe { libc::close(tmp) };
            return Err(io::Error::new(ErrorKind::AddrInUse, "fd already in use"));
        }
        unsafe { libc::close(old_fd) };
    }
    Ok(())
}

fn dup_safe(fd: RawFd) -> io::Result<RawFd> {
    let new_fd = unsafe { libc::dup(fd) };
    if new_fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(new_fd)
    }
}

pub fn cr_system(
    in_fd: RawFd,
    out_fd: RawFd,
    err_fd: RawFd,
    cmd: &str,
    argv: &[&str],
    flags: u32,
) -> i32 {
    cr_system_userns(in_fd, out_fd, err_fd, cmd, argv, flags, -1)
}

pub fn cr_system_userns(
    in_fd: RawFd,
    mut out_fd: RawFd,
    mut err_fd: RawFd,
    cmd: &str,
    argv: &[&str],
    flags: u32,
    userns_pid: i32,
) -> i32 {
    let mut blockmask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut oldmask: libc::sigset_t = unsafe { std::mem::zeroed() };

    unsafe {
        libc::sigemptyset(&mut blockmask);
        libc::sigaddset(&mut blockmask, libc::SIGCHLD);
        if libc::sigprocmask(libc::SIG_BLOCK, &blockmask, &mut oldmask) == -1 {
            return -1;
        }
    }

    let pid = unsafe { libc::fork() };
    if pid == -1 {
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &oldmask, std::ptr::null_mut()) };
        return -1;
    }

    if pid == 0 {
        unsafe {
            libc::sigemptyset(&mut blockmask);
            if libc::sigprocmask(libc::SIG_SETMASK, &blockmask, std::ptr::null_mut()) == -1 {
                libc::_exit(1);
            }
        }

        if userns_pid > 0 {
            unsafe { libc::_exit(1) };
        }

        let log_fd = log_get_fd();
        if out_fd < 0 {
            out_fd = dup_safe(log_fd).unwrap_or_else(|_| {
                unsafe { libc::_exit(1) };
            });
        }
        if err_fd < 0 {
            err_fd = dup_safe(log_fd).unwrap_or_else(|_| {
                unsafe { libc::_exit(1) };
            });
        }

        /*
         * out, err, in should be a separate fds,
         * because reopen_fd_as() closes an old fd
         */
        if err_fd == out_fd || err_fd == in_fd {
            err_fd = dup_safe(err_fd).unwrap_or_else(|_| {
                unsafe { libc::_exit(1) };
            });
        }
        if out_fd == in_fd {
            out_fd = dup_safe(out_fd).unwrap_or_else(|_| {
                unsafe { libc::_exit(1) };
            });
        }

        if move_fd_from(&mut out_fd, libc::STDIN_FILENO).is_err()
            || move_fd_from(&mut err_fd, libc::STDIN_FILENO).is_err()
        {
            unsafe { libc::_exit(1) };
        }

        if in_fd < 0 {
            unsafe { libc::close(libc::STDIN_FILENO) };
        } else if reopen_fd_as(libc::STDIN_FILENO, in_fd).is_err() {
            unsafe { libc::_exit(1) };
        }

        if move_fd_from(&mut err_fd, libc::STDOUT_FILENO).is_err() {
            unsafe { libc::_exit(1) };
        }

        if reopen_fd_as(libc::STDOUT_FILENO, out_fd).is_err()
            || reopen_fd_as(libc::STDERR_FILENO, err_fd).is_err()
        {
            unsafe { libc::_exit(1) };
        }

        let _ = close_fds(libc::STDERR_FILENO + 1);

        let c_cmd = CString::new(cmd).unwrap_or_else(|_| {
            unsafe { libc::_exit(1) };
        });

        let c_argv: Vec<CString> = argv
            .iter()
            .filter_map(|s| CString::new(*s).ok())
            .collect();

        let mut c_argv_ptrs: Vec<*const libc::c_char> =
            c_argv.iter().map(|s| s.as_ptr()).collect();
        c_argv_ptrs.push(std::ptr::null());

        unsafe {
            libc::execvp(c_cmd.as_ptr(), c_argv_ptrs.as_ptr());
            libc::_exit(1);
        }
    }

    let mut status: libc::c_int = 0;
    let ret = loop {
        let wait_ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if wait_ret == -1 {
            break -1;
        }

        if libc::WIFEXITED(status) {
            let exit_code = libc::WEXITSTATUS(status);
            if (flags & CRS_CAN_FAIL) == 0 && exit_code != 0 {
            }
            break if exit_code == 0 { 0 } else { -1 };
        } else if libc::WIFSIGNALED(status) {
            break -1;
        }
    };

    unsafe {
        libc::sigprocmask(libc::SIG_SETMASK, &oldmask, std::ptr::null_mut());
    }

    ret
}

pub fn cr_fchpermat(
    dirfd: RawFd,
    path: &str,
    new_uid: libc::uid_t,
    new_gid: libc::gid_t,
    new_mode: libc::mode_t,
    flags: libc::c_int,
) -> io::Result<()> {
    let c_path = CString::new(path)
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "path contains null byte"))?;

    let ret = unsafe { libc::fchownat(dirfd, c_path.as_ptr(), new_uid, new_gid, flags) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EPERM) {
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "Unable to change [{dirfd}]/{path} ownership to ({new_uid}, {new_gid}): {err}"
                ),
            ));
        }
    }

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstatat(dirfd, c_path.as_ptr(), &mut st, flags) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        return Err(io::Error::new(
            err.kind(),
            format!("Unable to stat [{dirfd}]/{path}: {err}"),
        ));
    }

    if new_uid != st.st_uid || new_gid != st.st_gid {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "Unable to change [{dirfd}]/{path} ownership ({}, {}) to ({new_uid}, {new_gid})",
                st.st_uid, st.st_gid
            ),
        ));
    }

    if new_mode == st.st_mode {
        return Ok(());
    }

    /*
     * We have no lchmod() function, and fchmod() will fail on
     * O_PATH | O_NOFOLLOW fd. Yes, we have fchmodat()
     * function and flag AT_SYMLINK_NOFOLLOW described in
     * man 2 fchmodat, but it is not currently implemented. %)
     */
    if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        return Ok(());
    }

    let ret = if path.is_empty() && (flags & libc::AT_EMPTY_PATH) != 0 {
        unsafe { libc::fchmod(dirfd, new_mode) }
    } else {
        let mode_flags = flags & !(libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH);
        unsafe { libc::fchmodat(dirfd, c_path.as_ptr(), new_mode, mode_flags) }
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        return Err(io::Error::new(
            err.kind(),
            format!("Unable to set perms {new_mode:o} on [{dirfd}]/{path}: {err}"),
        ));
    }

    Ok(())
}

pub fn cr_fchperm(
    fd: RawFd,
    new_uid: libc::uid_t,
    new_gid: libc::gid_t,
    new_mode: libc::mode_t,
) -> io::Result<()> {
    cr_fchpermat(fd, "", new_uid, new_gid, new_mode, libc::AT_EMPTY_PATH)
}

pub fn get_relative_path<'a>(path: &'a str, sub_path: &str) -> Option<&'a str> {
    let mut path_bytes = path.as_bytes();
    let mut sub_bytes = sub_path.as_bytes();
    let mut skip_slashes = true;

    loop {
        let path_at_separator = path_bytes.is_empty()
            || path_bytes[0] == b'/';
        let sub_at_separator = sub_bytes.is_empty()
            || sub_bytes[0] == b'/';

        if path_at_separator && sub_at_separator {
            skip_slashes = true;
        }

        if skip_slashes {
            while !path_bytes.is_empty() {
                if path_bytes[0] == b'/' {
                    path_bytes = &path_bytes[1..];
                } else if path_bytes[0] == b'.'
                    && (path_bytes.len() == 1
                        || path_bytes[1] == b'/'
                        || path_bytes[1] == 0)
                {
                    path_bytes = &path_bytes[1..];
                } else {
                    break;
                }
            }

            while !sub_bytes.is_empty() {
                if sub_bytes[0] == b'/' {
                    sub_bytes = &sub_bytes[1..];
                } else if sub_bytes[0] == b'.'
                    && (sub_bytes.len() == 1
                        || sub_bytes[1] == b'/'
                        || sub_bytes[1] == 0)
                {
                    sub_bytes = &sub_bytes[1..];
                } else {
                    break;
                }
            }
        }

        if sub_bytes.is_empty() {
            if skip_slashes {
                let offset = path.len() - path_bytes.len();
                return Some(&path[offset..]);
            }
            return None;
        }
        skip_slashes = false;

        if path_bytes.is_empty() {
            return None;
        }

        if path_bytes[0] != sub_bytes[0] {
            return None;
        }

        path_bytes = &path_bytes[1..];
        sub_bytes = &sub_bytes[1..];
    }
}

/// Checks if `path` is a sub-path of `sub_path`.
///
/// Maps to: criu/util.c:is_sub_path (lines 2093-2102)
///
/// Returns true if path contains sub_path as a prefix, false otherwise.
#[inline]
pub fn is_sub_path(path: &str, sub_path: &str) -> bool {
    get_relative_path(path, sub_path).is_some()
}

pub fn strlcpy(dest: &mut [u8], src: &[u8], size: usize) -> usize {
    let src_len = src.iter().position(|&b| b == 0).unwrap_or(src.len());

    if size > 0 {
        let copy_len = if src_len >= size { size - 1 } else { src_len };
        dest[..copy_len].copy_from_slice(&src[..copy_len]);
        dest[copy_len] = 0;
    }

    src_len
}

pub fn cr_fchown(fd: RawFd, new_uid: libc::uid_t, new_gid: libc::gid_t) -> io::Result<()> {
    let ret = unsafe { libc::fchown(fd, new_uid, new_gid) };
    if ret == 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EPERM) {
        return Err(err);
    }

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstat(fd, &mut st) };
    if ret < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("fstat() after fchown() for fd {fd}"),
        ));
    }

    if new_uid != st.st_uid || new_gid != st.st_gid {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }

    Ok(())
}

pub fn mkdirpat(fd: RawFd, path: &str, mode: libc::mode_t) -> io::Result<()> {
    const PATH_MAX: usize = 4096;

    if path.len() >= PATH_MAX {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("path {} is longer than PATH_MAX", path),
        ));
    }

    let mut made_path: Vec<u8> = path.as_bytes().to_vec();
    made_path.push(0); // null terminate for C

    let mut i = 0usize;

    // Skip leading slash if present
    if !made_path.is_empty() && made_path[0] == b'/' {
        i = 1;
    }

    while i < made_path.len() - 1 {
        // Find next slash
        let pos = made_path[i..].iter().position(|&c| c == b'/');

        if let Some(slash_offset) = pos {
            let slash_idx = i + slash_offset;
            // Temporarily null-terminate at slash
            made_path[slash_idx] = 0;

            // Try to create this component
            let c_path = std::ffi::CStr::from_bytes_with_nul(&made_path[..slash_idx + 1])
                .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid path"))?;

            let ret = unsafe { libc::mkdirat(fd, c_path.as_ptr(), mode) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EEXIST) {
                    return Err(err);
                }
            }

            // Restore slash
            made_path[slash_idx] = b'/';
            i = slash_idx + 1;
        } else {
            // No more slashes, create final component
            let c_path = std::ffi::CStr::from_bytes_with_nul(&made_path)
                .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid path"))?;

            let ret = unsafe { libc::mkdirat(fd, c_path.as_ptr(), mode) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EEXIST) {
                    return Err(err);
                }
            }
            break;
        }
    }

    Ok(())
}

/// Installs a file descriptor for /proc/self access.
/// If fd < 0, closes the existing service fd.
/// Returns the installed fd on success, -1 on error.
pub fn set_proc_self_fd(
    sfd_state: &mut ServiceFdState,
    open_proc_self_pid: &mut libc::pid_t,
    fd: RawFd,
) -> RawFd {
    if fd < 0 {
        return sfd_state.close_service_fd(SfdType::ProcSelfFdOff) as RawFd;
    }

    *open_proc_self_pid = unsafe { libc::getpid() };
    sfd_state.install_service_fd(SfdType::ProcSelfFdOff, fd)
}

/// Installs a file descriptor for /proc/[pid] access.
/// If fd < 0, closes the existing service fd.
/// Returns the installed fd on success, -1 on error.
pub fn set_proc_pid_fd(
    sfd_state: &mut ServiceFdState,
    open_proc_pid: &mut libc::pid_t,
    pid: libc::pid_t,
    fd: RawFd,
) -> RawFd {
    if fd < 0 {
        return sfd_state.close_service_fd(SfdType::ProcPidFdOff) as RawFd;
    }

    *open_proc_pid = pid;
    sfd_state.install_service_fd(SfdType::ProcPidFdOff, fd)
}

pub fn close_pid_proc(
    sfd_state: &mut ServiceFdState,
    open_proc_self_pid: &mut libc::pid_t,
    open_proc_pid: &mut libc::pid_t,
) -> i32 {
    set_proc_self_fd(sfd_state, open_proc_self_pid, -1);
    set_proc_pid_fd(sfd_state, open_proc_pid, PROC_NONE, -1);
    0
}

fn get_proc_fd(
    sfd_state: &ServiceFdState,
    open_proc_self_pid: libc::pid_t,
    open_proc_pid: libc::pid_t,
    pid: libc::pid_t,
) -> RawFd {
    if pid == PROC_SELF {
        let open_proc_self_fd = sfd_state.get_service_fd(SfdType::ProcSelfFdOff);
        // Check that cached fd belongs to this process
        if open_proc_self_fd >= 0 && open_proc_self_pid != unsafe { libc::getpid() } {
            return -1;
        }
        return open_proc_self_fd;
    } else if pid == open_proc_pid {
        return sfd_state.get_service_fd(SfdType::ProcPidFdOff);
    }
    -1
}

fn close_proc(sfd_state: &mut ServiceFdState) {
    sfd_state.close_service_fd(SfdType::ProcFdOff);
}

fn open_proc_sfd(sfd_state: &mut ServiceFdState, path: &str) -> i32 {
    let c_path = match CString::new(path) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    close_proc(sfd_state);

    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_DIRECTORY | libc::O_PATH) };
    if fd < 0 {
        log::error!("Can't open {}", path);
        return -1;
    }

    let ret = sfd_state.install_service_fd(SfdType::ProcFdOff, fd);
    if ret < 0 {
        return -1;
    }

    0
}

pub fn open_pid_proc(
    sfd_state: &mut ServiceFdState,
    open_proc_self_pid: &mut libc::pid_t,
    open_proc_pid: &mut libc::pid_t,
    pid: libc::pid_t,
) -> RawFd {
    let fd = get_proc_fd(sfd_state, *open_proc_self_pid, *open_proc_pid, pid);
    if fd >= 0 {
        return fd;
    }

    let mut dfd = sfd_state.get_service_fd(SfdType::ProcFdOff);
    if dfd < 0 {
        if open_proc_sfd(sfd_state, "/proc") < 0 {
            return -1;
        }
        dfd = sfd_state.get_service_fd(SfdType::ProcFdOff);
    }

    if pid == PROC_GEN {
        return dfd;
    }

    let path = if pid == PROC_SELF {
        CString::new("self").unwrap()
    } else {
        CString::new(format!("{}", pid)).unwrap()
    };

    let fd = unsafe { libc::openat(dfd, path.as_ptr(), libc::O_PATH) };
    if fd < 0 {
        log::error!("Can't open {}", path.to_str().unwrap_or(""));
        return -1;
    }

    if pid == PROC_SELF {
        set_proc_self_fd(sfd_state, open_proc_self_pid, fd)
    } else {
        set_proc_pid_fd(sfd_state, open_proc_pid, pid, fd)
    }
}

pub fn call_in_child_process(
    f: extern "C" fn(*mut c_void) -> i32,
    arg: *mut c_void,
    sfd_state: &mut ServiceFdState,
    open_proc_self_pid: &mut libc::pid_t,
    open_proc_pid: &mut libc::pid_t,
) -> i32 {
    let mut status: i32 = 0;
    let mut ret: i32 = -1;

    // Parent freezes till child exit, so child may use the same stack.
    // No SIGCHLD flag, so it's not need to block signal.
    let flags = libc::CLONE_VFORK
        | libc::CLONE_VM
        | libc::CLONE_FILES
        | libc::CLONE_IO
        | libc::CLONE_SIGHAND
        | libc::CLONE_SYSVSEM;

    let pid = clone_noasan_raw(f, flags, arg);
    if pid == -1 {
        log::error!("Can't clone");
        return -1;
    }

    unsafe {
        *libc::__errno_location() = 0;
    }

    let wait_ret = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };

    if wait_ret != pid || !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        let errno = unsafe { *libc::__errno_location() };
        log::error!(
            "Can't wait or bad status: errno={}, status={}",
            errno,
            status
        );
    } else {
        ret = 0;
    }

    // Child opened PROC_SELF for pid. If we create one more child
    // with the same pid later, it will try to reuse this /proc/self.
    close_pid_proc(sfd_state, open_proc_self_pid, open_proc_pid);
    ret
}

const LAST_PID_PATH: &str = "/proc/sys/kernel/ns_last_pid";

pub fn set_next_pid(pid: libc::pid_t) -> io::Result<()> {
    let c_path = CString::new(LAST_PID_PATH).unwrap();
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let buf = format!("{}", pid - 1);
    let ret = unsafe { libc::write(fd, buf.as_ptr() as *const c_void, buf.len()) };
    unsafe { libc::close(fd) };

    if ret != buf.len() as isize {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("Failed to write {} to {}", buf, LAST_PID_PATH),
        ));
    }
    Ok(())
}

pub fn make_yard(path: &str) -> io::Result<()> {
    let c_path =
        CString::new(path).map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid path"))?;
    let c_none = CString::new("none").unwrap();
    let c_tmpfs = CString::new("tmpfs").unwrap();

    let ret = unsafe {
        libc::mount(
            c_none.as_ptr(),
            c_path.as_ptr(),
            c_tmpfs.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("Unable to mount tmpfs in {}", path),
        ));
    }

    let ret = unsafe {
        libc::mount(
            c_none.as_ptr(),
            c_path.as_ptr(),
            std::ptr::null(),
            libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            "Unable to mark yard as private",
        ));
    }

    Ok(())
}

/// Resets SIGCHLD handler to default.
///
/// Maps to: criu/cr-restore.c:ignore_kids (lines 1925-1931)
///
/// This is called after restore is complete to restore normal
/// child process handling.
pub fn ignore_kids() {
    unsafe {
        let sa: libc::sigaction = std::mem::zeroed();
        // SIG_DFL is 0, which is what zeroed gives us for sa_handler
        if libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut()) < 0 {
            log::error!("Restoring CHLD sigaction failed");
        }
    }
}

/// Reaps all zombie child processes.
///
/// Maps to: criu/cr-restore.c:reap_zombies (lines 1986-1996)
///
/// Loops calling wait() until all zombie children are reaped.
pub fn reap_zombies() {
    loop {
        let pid = unsafe { libc::wait(std::ptr::null_mut()) };
        if pid == -1 {
            let errno = unsafe { *libc::__errno_location() };
            if errno != libc::ECHILD {
                log::error!("Error while waiting for pids: {}", errno);
            }
            return;
        }
    }
}

pub fn page_size() -> usize {
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize })
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Faults {
    #[default]
    None = 0,
    DumpEarly = 1,
    RestoreRootOnly = 2,
    DumpPages = 3,
    RestoreOpenLinkRemap = 4,
    ParasiteConnect = 5,
    PostRestore = 6,
    VdsoTrampolines = 127,
    CheckOpenHandle = 128,
    NoMemfd = 129,
    NoBreakpoints = 130,
    PartialPages = 131,
    HugeAnonShmemId = 132,
    CannotMapVdso = 133,
    CorruptExtregs = 134,
    DontUsePagmapScan = 135,
    DumpCrash = 136,
    CompelInterruptOnlyMode = 137,
    PluginCudaForceEnable = 138,
    Max = 139,
}

static FI_STRATEGY: OnceLock<Faults> = OnceLock::new();

pub fn set_fi_strategy(f: Faults) -> Result<(), Faults> {
    FI_STRATEGY.set(f)
}

pub fn fi_strategy() -> Faults {
    FI_STRATEGY.get().copied().unwrap_or(Faults::None)
}

pub fn fault_injected(f: Faults) -> bool {
    fi_strategy() == f
}

pub fn arch_ptrace_restore(_pid: i32, _item_idx: usize) -> i32 {
    0
}

use std::sync::atomic::{AtomicU32, Ordering};

static SERVICE_FD_RLIM_CUR: AtomicU32 = AtomicU32::new(0);

pub fn service_fd_rlim_cur() -> u32 {
    SERVICE_FD_RLIM_CUR.load(Ordering::Relaxed)
}

pub fn set_service_fd_rlim_cur(val: u32) {
    SERVICE_FD_RLIM_CUR.store(val, Ordering::Relaxed);
}

fn cap_to_mask(cap: i32) -> u32 {
    1u32 << (cap % 32)
}

fn cap_to_index(cap: i32) -> usize {
    (cap >> 5) as usize
}

pub fn has_capability(cap: i32, cap_eff: &[u32]) -> bool {
    let mask = cap_to_mask(cap);
    let index = cap_to_index(cap);

    if index >= cap_eff.len() {
        return false;
    }

    let effective = cap_eff[index];
    if (mask & effective) == 0 {
        log::debug!("Effective capability {} missing", cap);
        return false;
    }

    true
}

pub fn has_cap_sys_resource(cap_eff: &[u32]) -> bool {
    const CAP_SYS_RESOURCE: i32 = 24;
    has_capability(CAP_SYS_RESOURCE, cap_eff)
}

pub fn open_proc(pid: libc::pid_t, subpath: &str) -> RawFd {
    let path = format!("/proc/{}/{}", pid, subpath);
    let c_path = match CString::new(path) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) }
}

pub fn close_safe(fd: &mut RawFd) {
    if *fd >= 0 {
        unsafe { libc::close(*fd) };
        *fd = -1;
    }
}

pub fn rlimit_unlimit_nofile() {
    use crate::criu::kerndat::kdat;
    use crate::criu::options::opts;

    if opts().unprivileged != 0 && !has_cap_sys_resource(&opts().cap_eff) {
        return;
    }

    let new_limit = libc::rlimit {
        rlim_cur: kdat().sysctl_nr_open as u64,
        rlim_max: kdat().sysctl_nr_open as u64,
    };

    let ret = unsafe { libc::prlimit(libc::getpid(), libc::RLIMIT_NOFILE, &new_limit, std::ptr::null_mut()) };

    if ret != 0 {
        log::error!("rlimit: Can't setup RLIMIT_NOFILE for self");
        return;
    }

    log::debug!("rlimit: RLIMIT_NOFILE unlimited for self");
    set_service_fd_rlim_cur(kdat().sysctl_nr_open);
}

static SAVED_LOGINUID: std::sync::Mutex<u32> = std::sync::Mutex::new(crate::criu::proc_parse::INVALID_UID);

/*
 * Save old loginuid and set it to INVALID_UID:
 * this value means that loginuid is unset and it will be inherited.
 * After you set some value to /proc/<>/loginuid it can't be changed
 * inside container due to permissions.
 * But you still can set this value if it was unset.
 */
pub fn prepare_userns_hook() -> i32 {
    use crate::criu::kerndat::{kdat, LoginuidFunc};
    use crate::criu::proc_parse::{parse_pid_loginuid, prepare_loginuid, INVALID_UID};

    if kdat().luid != LoginuidFunc::Full {
        return 0;
    }

    let loginuid = match parse_pid_loginuid(unsafe { libc::getpid() }, false) {
        Ok(uid) => uid,
        Err(_) => return -1,
    };

    if let Ok(mut saved) = SAVED_LOGINUID.lock() {
        *saved = loginuid;
    }

    if prepare_loginuid(INVALID_UID) < 0 {
        log::error!("Setting loginuid for CT init task failed, CAP_AUDIT_CONTROL?");
        return -1;
    }

    0
}

pub fn restore_origin_ns_hook() {
    use crate::criu::kerndat::{kdat, LoginuidFunc};
    use crate::criu::proc_parse::prepare_loginuid;

    if kdat().luid != LoginuidFunc::Full {
        return;
    }

    let saved = match SAVED_LOGINUID.lock() {
        Ok(guard) => *guard,
        Err(_) => return,
    };

    /* not critical: it does not affect CT in any way */
    if prepare_loginuid(saved) < 0 {
        log::error!("Restore original /proc/self/loginuid failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strlcpy_normal() {
        let mut dest = [0u8; 10];
        let src = b"hello";
        let len = strlcpy(&mut dest, src, 10);
        assert_eq!(len, 5);
        assert_eq!(&dest[..6], b"hello\0");
    }

    #[test]
    fn test_strlcpy_truncate() {
        let mut dest = [0u8; 4];
        let src = b"hello world";
        let len = strlcpy(&mut dest, src, 4);
        assert_eq!(len, 11); // returns original length
        assert_eq!(&dest[..4], b"hel\0"); // truncated and null-terminated
    }

    #[test]
    fn test_strlcpy_exact_fit() {
        let mut dest = [0u8; 6];
        let src = b"hello";
        let len = strlcpy(&mut dest, src, 6);
        assert_eq!(len, 5);
        assert_eq!(&dest[..6], b"hello\0");
    }

    #[test]
    fn test_strlcpy_empty_src() {
        let mut dest = [0xffu8; 4];
        let src = b"";
        let len = strlcpy(&mut dest, src, 4);
        assert_eq!(len, 0);
        assert_eq!(dest[0], 0);
    }

    #[test]
    fn test_strlcpy_zero_size() {
        let mut dest = [0xffu8; 4];
        let src = b"hello";
        let len = strlcpy(&mut dest, src, 0);
        assert_eq!(len, 5);
        // dest unchanged when size is 0
        assert_eq!(dest[0], 0xff);
    }

    #[test]
    fn test_mkdirpat() {
        use std::ffi::CString;

        // Create a temporary directory
        let tmpdir = std::env::temp_dir();
        let tmpdir_c = CString::new(tmpdir.to_str().unwrap()).unwrap();
        let fd = unsafe { libc::open(tmpdir_c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        assert!(fd >= 0);

        // Create a unique test path
        let test_path = format!("crust_test_{}/sub/dir", std::process::id());

        // Create directories
        let result = mkdirpat(fd, &test_path, 0o755);
        assert!(result.is_ok());

        // Verify the directory exists
        let full_path = tmpdir.join(&test_path);
        assert!(full_path.exists());
        assert!(full_path.is_dir());

        // Clean up
        let _ = std::fs::remove_dir_all(tmpdir.join(format!("crust_test_{}", std::process::id())));
        unsafe { libc::close(fd) };
    }

    #[test]
    fn test_close_pid_proc() {
        let mut sfd_state = ServiceFdState::new();
        let mut open_proc_self_pid: libc::pid_t = 0;
        let mut open_proc_pid: libc::pid_t = 0;

        let result = close_pid_proc(&mut sfd_state, &mut open_proc_self_pid, &mut open_proc_pid);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_is_sub_path() {
        // path contains sub_path
        assert!(is_sub_path("/a/b/c", "/a"));
        assert!(is_sub_path("/a/b/c", "/a/b"));
        assert!(is_sub_path("/a/b/c", "/a/b/c"));

        // path does not contain sub_path
        assert!(!is_sub_path("/a/b", "/a/b/c"));
        assert!(!is_sub_path("/x/y", "/a"));
    }
}
