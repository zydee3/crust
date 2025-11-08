//! PID control mechanisms for exact PID allocation
//!
//! Process restore requires recreating processes with their original PIDs.
//! Two mechanisms are supported:
//! 1. clone3() with set_tid (kernel 5.5+)
//! 2. /proc/sys/kernel/ns_last_pid fallback (older kernels)

use crate::error::{CrustError, Result};
use crust_syscall::{clone3, CloneArgs};
use std::fs::OpenOptions;
use std::io::Write;

const SIGCHLD: u64 = 17;

/// Fork a new process with the specified PID using clone3
///
/// Uses the clone3 syscall with set_tid to allocate an exact PID.
/// Requires kernel 5.5+ and CAP_SYS_ADMIN.
///
/// Returns Ok(0) in the child process, Ok(pid) in the parent.
pub fn clone3_with_pid(target_pid: i32) -> Result<i32> {
    let mut pid_array = [target_pid];

    let mut args = CloneArgs::new();
    args.flags = 0; // No special clone flags needed
    args.exit_signal = SIGCHLD;
    args.set_tid = pid_array.as_mut_ptr() as u64;
    args.set_tid_size = 1;

    let result = unsafe {
        clone3(
            &args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };

    result.map_err(|e| {
        CrustError::PidControl(format!(
            "clone3 with set_tid failed for PID {}: {}",
            target_pid, e
        ))
    })
}

/// Fallback: Set /proc/sys/kernel/ns_last_pid then fork
///
/// Older mechanism (kernel 3.3+) that sets the last allocated PID,
/// then immediately forks. The forked process gets last_pid + 1.
///
/// IMPORTANT: This has a race condition if other processes are forking.
/// Use clone3_with_pid() when available (kernel 5.5+).
///
/// Returns Ok(0) in the child process, Ok(pid) in the parent.
pub fn fork_with_ns_last_pid(target_pid: i32) -> Result<i32> {
    // Open /proc/sys/kernel/ns_last_pid
    let mut file = OpenOptions::new()
        .write(true)
        .open("/proc/sys/kernel/ns_last_pid")
        .map_err(|e| {
            CrustError::PidControl(format!(
                "Failed to open /proc/sys/kernel/ns_last_pid: {}. Are you root?",
                e
            ))
        })?;

    // Write target_pid - 1 (next fork will get target_pid)
    let last_pid = target_pid - 1;
    write!(file, "{}", last_pid).map_err(|e| {
        CrustError::PidControl(format!(
            "Failed to write to /proc/sys/kernel/ns_last_pid: {}",
            e
        ))
    })?;

    // Drop file to ensure write completes
    drop(file);

    // Immediately fork (should get target_pid)
    // Use clone with minimal flags
    let mut args = CloneArgs::new();
    args.flags = 0;
    args.exit_signal = SIGCHLD;

    let result = unsafe {
        clone3(
            &args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };

    result.map_err(|e| {
        CrustError::PidControl(format!(
            "clone3 (without set_tid) failed: {}",
            e
        ))
    })
}

/// High-level API: Fork a process with exact PID
///
/// Tries mechanisms in order:
/// 1. clone3 with set_tid (preferred, kernel 5.5+)
/// 2. /proc/sys/kernel/ns_last_pid fallback (kernel 3.3+)
///
/// Returns Ok(0) in the child process, Ok(actual_pid) in the parent.
pub fn fork_with_pid(target_pid: i32) -> Result<i32> {
    // Try clone3 with set_tid first
    match clone3_with_pid(target_pid) {
        Ok(result) => return Ok(result),
        Err(e) => {
            // Log the failure but continue to fallback
            eprintln!("clone3 with set_tid failed ({}), trying fallback...", e);
        }
    }

    // Fall back to ns_last_pid mechanism
    let result = fork_with_ns_last_pid(target_pid)?;

    // In parent process, verify we got the right PID
    if result != 0 && result != target_pid {
        return Err(CrustError::PidControl(format!(
            "PID mismatch: wanted {}, got {}",
            target_pid, result
        )));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires root privileges
    fn test_clone3_with_pid() {
        // This test requires root and will fork
        let target_pid = 99999; // Use high PID unlikely to conflict

        match clone3_with_pid(target_pid) {
            Ok(0) => {
                // Child process
                std::process::exit(0);
            }
            Ok(pid) => {
                // Parent process
                assert_eq!(pid, target_pid);

                // Wait for child
                unsafe {
                    let mut status = 0;
                    libc::waitpid(pid, &mut status, 0);
                }
            }
            Err(e) => {
                // May fail if kernel doesn't support clone3 set_tid
                eprintln!("clone3 test failed (expected on older kernels): {}", e);
            }
        }
    }

    #[test]
    #[ignore] // Requires root privileges
    fn test_fork_with_ns_last_pid() {
        let target_pid = 99998;

        match fork_with_ns_last_pid(target_pid) {
            Ok(0) => {
                // Child process
                std::process::exit(0);
            }
            Ok(pid) => {
                // Parent process
                assert_eq!(pid, target_pid);

                // Wait for child
                unsafe {
                    let mut status = 0;
                    libc::waitpid(pid, &mut status, 0);
                }
            }
            Err(e) => {
                panic!("fork_with_ns_last_pid failed: {}", e);
            }
        }
    }
}
