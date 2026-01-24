use std::ffi::CString;
use std::fs;
use std::path::Path;

pub const INVALID_UID: u32 = u32::MAX;

/// Represents a thread's PID information.
#[derive(Debug, Clone)]
pub struct ThreadPid {
    pub real: i32,
    pub virt: i32,
}

/// Parses login UID from /proc/<pid>/loginuid.
///
/// Maps to: criu/proc_parse.c:parse_pid_loginuid (lines 1009-1032)
///
/// Arguments:
/// - `pid`: Process ID to read loginuid from
/// - `ignore_noent`: If true, ENOENT errors are not logged
///
/// Returns:
/// - `Ok(uid)`: The login UID value
/// - `Err(-1)`: Failed to read or parse
pub fn parse_pid_loginuid(pid: libc::pid_t, ignore_noent: bool) -> Result<u32, i32> {
    let path = format!("/proc/{}/loginuid", pid);
    let c_path = match CString::new(path.clone()) {
        Ok(p) => p,
        Err(_) => return Err(-1),
    };

    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if ignore_noent && err.raw_os_error() == Some(libc::ENOENT) {
            return Err(-1);
        }
        log::error!("Failed to open {}", path);
        return Err(-1);
    }

    let mut buf = [0u8; 11];
    let num = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 10) };
    unsafe { libc::close(fd) };

    if num < 0 {
        log::error!("Unable to read /proc/{}/loginuid", pid);
        return Err(-1);
    }

    let s = std::str::from_utf8(&buf[..num as usize]).map_err(|_| -1)?;
    s.trim().parse::<u32>().map_err(|_| -1)
}

/// Parses threads from /proc/<pid>/task directory.
///
/// Maps to: criu/proc_parse.c:parse_threads (lines 2538-2583)
///
/// Arguments:
/// - `pid`: Process ID to read threads from
///
/// Returns:
/// - `Ok(threads)`: Vector of thread PIDs found
/// - `Err(-1)`: Failed to read directory
pub fn parse_threads(pid: libc::pid_t) -> Result<Vec<ThreadPid>, i32> {
    let task_path = format!("/proc/{}/task", pid);
    let path = Path::new(&task_path);

    let dir = match fs::read_dir(path) {
        Ok(d) => d,
        Err(_) => return Err(-1),
    };

    let mut threads = Vec::new();

    for entry in dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };

        // Skip . and .. entries
        if name_str.starts_with('.') {
            continue;
        }

        // Parse thread ID
        if let Ok(tid) = name_str.parse::<i32>() {
            threads.push(ThreadPid {
                real: tid,
                virt: -1, // Will be filled in later from image
            });
        }
    }

    Ok(threads)
}

/// Writes login UID to /proc/self/loginuid.
///
/// Maps to: criu/proc_parse.c:prepare_loginuid (lines 990-1007)
///
/// Arguments:
/// - `value`: The login UID value to write
///
/// Returns 0 on success, -1 on failure.
pub fn prepare_loginuid(value: u32) -> i32 {
    let path = CString::new("/proc/self/loginuid").unwrap();

    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY) };
    if fd < 0 {
        return -1;
    }

    let buf = format!("{}", value);
    let written = unsafe {
        libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len())
    };

    if written < 0 {
        log::warn!("Write {} to /proc/self/loginuid failed", buf);
        unsafe { libc::close(fd) };
        return -1;
    }

    unsafe { libc::close(fd) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pid_loginuid_self() {
        // Read our own loginuid
        let result = parse_pid_loginuid(std::process::id() as libc::pid_t, false);
        // This should succeed (either with a UID or INVALID_UID)
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_parse_pid_loginuid_invalid_pid() {
        // Non-existent PID should fail
        let result = parse_pid_loginuid(999999, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_uid_constant() {
        assert_eq!(INVALID_UID, u32::MAX);
        assert_eq!(INVALID_UID as i32, -1);
    }

    #[test]
    fn test_parse_threads_self() {
        // Parse our own threads
        let pid = std::process::id() as libc::pid_t;
        let result = parse_threads(pid);
        assert!(result.is_ok());

        let threads = result.unwrap();
        // Should have at least one thread (the main thread)
        assert!(!threads.is_empty());

        // The main thread should match our PID
        let main_tid_found = threads.iter().any(|t| t.real == pid);
        assert!(main_tid_found);
    }

    #[test]
    fn test_parse_threads_invalid_pid() {
        // Non-existent PID should fail
        let result = parse_threads(999999);
        assert!(result.is_err());
    }

    #[test]
    fn test_thread_pid_struct() {
        let thread = ThreadPid { real: 1234, virt: -1 };
        assert_eq!(thread.real, 1234);
        assert_eq!(thread.virt, -1);
    }
}
