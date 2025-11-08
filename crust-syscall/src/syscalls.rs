//! Higher-level syscall wrappers
//!
//! Type-safe wrappers around raw syscalls with proper error handling.

use crate::constants::*;
use crate::errno::Errno;
use crate::raw;

/// Map memory (anonymous or file-backed)
#[inline(always)]
pub unsafe fn mmap(
    addr: usize,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> Result<usize, Errno> {
    let ret = raw::syscall6(
        SYS_MMAP,
        addr as u64,
        length as u64,
        prot as u64,
        flags as u64,
        fd as u64,
        offset as u64,
    );
    Errno::from_syscall_ret(ret)
}

/// Unmap memory
#[inline(always)]
pub unsafe fn munmap(addr: usize, length: usize) -> Result<(), Errno> {
    let ret = raw::syscall2(SYS_MUNMAP, addr as u64, length as u64);
    Errno::from_syscall_ret(ret).map(|_| ())
}

/// Remap memory
#[inline(always)]
pub unsafe fn mremap(
    old_addr: usize,
    old_size: usize,
    new_size: usize,
    flags: i32,
    new_addr: usize,
) -> Result<usize, Errno> {
    let ret = raw::syscall5(
        SYS_MREMAP,
        old_addr as u64,
        old_size as u64,
        new_size as u64,
        flags as u64,
        new_addr as u64,
    );
    Errno::from_syscall_ret(ret)
}

/// Read from file descriptor
#[inline(always)]
pub unsafe fn read(fd: i32, buf: *mut u8, count: usize) -> Result<usize, Errno> {
    let ret = raw::syscall3(SYS_READ, fd as u64, buf as u64, count as u64);
    Errno::from_syscall_ret(ret)
}

/// Write to file descriptor
#[inline(always)]
pub unsafe fn write(fd: i32, buf: *const u8, count: usize) -> Result<usize, Errno> {
    let ret = raw::syscall3(SYS_WRITE, fd as u64, buf as u64, count as u64);
    Errno::from_syscall_ret(ret)
}

/// Open file
#[inline(always)]
pub unsafe fn open(path: *const u8, flags: i32, mode: u32) -> Result<i32, Errno> {
    let ret = raw::syscall3(SYS_OPEN, path as u64, flags as u64, mode as u64);
    Errno::from_syscall_ret(ret).map(|fd| fd as i32)
}

/// Close file descriptor
#[inline(always)]
pub unsafe fn close(fd: i32) -> Result<(), Errno> {
    let ret = raw::syscall1(SYS_CLOSE, fd as u64);
    Errno::from_syscall_ret(ret).map(|_| ())
}

/// Process control operations
#[inline(always)]
pub unsafe fn prctl(
    option: i32,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> Result<i32, Errno> {
    let ret = raw::syscall5(
        SYS_PRCTL,
        option as u64,
        arg2,
        arg3,
        arg4,
        arg5,
    );
    Errno::from_syscall_ret(ret).map(|v| v as i32)
}

/// Architecture-specific process control
#[inline(always)]
pub unsafe fn arch_prctl(code: i32, addr: u64) -> Result<(), Errno> {
    let ret = raw::syscall2(SYS_ARCH_PRCTL, code as u64, addr);
    Errno::from_syscall_ret(ret).map(|_| ())
}

/// rt_sigreturn - restore CPU state from sigframe (NEVER RETURNS)
#[inline(always)]
pub unsafe fn rt_sigreturn() -> ! {
    raw::syscall0(SYS_RT_SIGRETURN);
    core::hint::unreachable_unchecked()
}

/// Arguments structure for clone3 syscall
#[repr(C)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,         // Pointer to store pidfd
    pub child_tid: u64,     // Pointer for CLONE_CHILD_SETTID
    pub parent_tid: u64,    // Pointer for CLONE_PARENT_SETTID
    pub exit_signal: u64,
    pub stack: u64,         // Pointer to stack bottom
    pub stack_size: u64,
    pub tls: u64,           // Thread-local storage pointer
    pub set_tid: u64,       // Pointer to array of PIDs
    pub set_tid_size: u64,  // Number of PIDs in set_tid array
    pub cgroup: u64,        // cgroup file descriptor
}

impl CloneArgs {
    /// Create a new CloneArgs with all fields zeroed
    pub const fn new() -> Self {
        CloneArgs {
            flags: 0,
            pidfd: 0,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: 0,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: 0,
        }
    }
}

/// Clone a process with extended options (clone3 syscall)
///
/// Returns the child PID in the parent process, or 0 in the child process.
#[inline(always)]
pub unsafe fn clone3(args: *const CloneArgs, size: usize) -> Result<i32, Errno> {
    let ret = raw::syscall2(SYS_CLONE3, args as u64, size as u64);
    Errno::from_syscall_ret(ret).map(|v| v as i32)
}
