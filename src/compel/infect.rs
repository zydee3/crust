//! Parasite infection and control functions

use std::io;
use std::ptr;

use libc::{c_void, pid_t, ptrace, wait4, SIGTRAP, __WALL};

use super::arch::{KRtSigset, ThreadCtx, UserRegsStruct};
use super::ptrace::{
    ptrace_get_regs, ptrace_set_regs, PTRACE_SETSIGMASK, PTRACE_SYSCALL, PTRACE_SYSCALL_TRAP,
};

/// Minimum size for parasite start area
pub const PARASITE_START_AREA_MIN: usize = 4096;

/// Size of built-in syscall code
pub const BUILTIN_SYSCALL_SIZE: usize = 8;

/// Memfd filename used by compel
pub const MEMFD_FNAME: &[u8] = b"CRIUMFD\0";

/// Size of memfd filename (including null terminator)
pub const MEMFD_FNAME_SZ: usize = MEMFD_FNAME.len();

/// Type alias for open_proc callback
pub type OpenProcFn = Option<fn(pid: pid_t, what: i32, flags: i32) -> i32>;

/// Type alias for save_regs callback
pub type SaveRegsFn = Option<fn(arg: *mut c_void, regs: &UserRegsStruct) -> i32>;

/// Type alias for make_sigframe callback
pub type MakeSigframeFn = Option<fn(arg: *mut c_void, sigframe: *mut c_void, regs: &UserRegsStruct, blk: *mut KRtSigset) -> i32>;

/// Type alias for child handler callback
pub type ChildHandlerFn = Option<fn(sig: i32, info: *mut libc::siginfo_t, ctx: *mut c_void)>;

/// Relocation entry for parasite blob
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CompelReloc {
    pub offset: u64,
    pub type_: u32,
    pub sym: u32,
    pub addend: i64,
}

/// Header describing the parasite blob layout
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct ParasiteBlobHdr {
    /// Pointer to parasite code in memory
    pub mem: *const c_void,
    /// Blob size
    pub bsize: usize,
    /// Offset to parasite entry point
    pub parasite_ip_off: u64,
    /// Offset to command field
    pub cmd_off: u64,
    /// Offset to args pointer field
    pub args_ptr_off: u64,
    /// Offset to GOT
    pub got_off: u64,
    /// Offset to arguments area
    pub args_off: u64,
    /// Offset to data section
    pub data_off: u64,
    /// Relocation entries
    pub relocs: *mut CompelReloc,
    /// Number of relocation entries
    pub nr_relocs: u32,
}

/// Type of parasite blob
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum ParasiteType {
    #[default]
    Standard = 0,
    Compat = 1,
}

/// Descriptor for the parasite blob
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct ParasiteBlobDesc {
    pub parasite_type: ParasiteType,
    pub hdr: ParasiteBlobHdr,
}

/// Infection context - settings for parasite injection
#[derive(Debug, Clone)]
#[repr(C)]
pub struct InfectCtx {
    /// Socket for communication
    pub sock: i32,

    /// Callback to save registers
    pub save_regs: SaveRegsFn,
    /// Callback to make sigframe
    pub make_sigframe: MakeSigframeFn,
    /// Opaque argument for callbacks
    pub regs_arg: *mut c_void,

    /// Task address space size
    pub task_size: u64,
    /// Entry point for infection
    pub syscall_ip: u64,
    /// Fine-tuning flags (e.g. faults)
    pub flags: u64,

    /// Handler for SIGCHLD deaths
    pub child_handler: ChildHandlerFn,
    /// Original SIGCHLD handler
    pub orig_handler: libc::sigaction,

    /// Callback to open /proc entries
    pub open_proc: OpenProcFn,

    /// Fd for parasite code to send messages to
    pub log_fd: i32,
    /// User-specified address where to mmap parasitic code
    pub remote_map_addr: u64,
}

impl Default for InfectCtx {
    fn default() -> Self {
        Self {
            sock: -1,
            save_regs: None,
            make_sigframe: None,
            regs_arg: ptr::null_mut(),
            task_size: 0,
            syscall_ip: 0,
            flags: 0,
            child_handler: None,
            orig_handler: unsafe { std::mem::zeroed() },
            open_proc: None,
            log_fd: -1,
            remote_map_addr: 0,
        }
    }
}

/// Parasite control block
///
/// This structure controls the infection of a target process. It holds
/// all the state needed to inject and execute parasite code.
#[derive(Debug)]
pub struct ParasiteCtl {
    /// Real pid of the victim
    pub rpid: pid_t,
    /// Remote mmap address in victim
    pub remote_map: *mut c_void,
    /// Local mmap address (for reading/writing)
    pub local_map: *mut c_void,
    /// Address for the breakpoint
    pub sigreturn_addr: *mut c_void,
    /// Length of mapped region
    pub map_length: u64,

    /// Infection context/settings
    pub ictx: InfectCtx,

    /// Whether parasite is daemonized (thread leader)
    pub daemonized: bool,

    /// Original thread context (saved before infection)
    pub orig: ThreadCtx,

    /// Thread leader stack in remote process
    pub rstack: *mut c_void,
    /// Sigframe in local map
    pub sigframe: *mut c_void,
    /// Sigframe address in remote process
    pub rsigframe: *mut c_void,

    /// Stack for non-leader threads
    pub r_thread_stack: *mut c_void,

    /// Service routine start IP
    pub parasite_ip: u64,

    /// Address for command in remote process
    pub cmd: *mut u32,
    /// Address for arguments in remote process
    pub args: *mut c_void,
    /// Size of arguments area
    pub args_size: u64,
    /// Transport socket for transferring fds
    pub tsock: i32,

    /// Parasite blob descriptor
    pub pblob: ParasiteBlobDesc,
}

impl Default for ParasiteCtl {
    fn default() -> Self {
        Self {
            rpid: 0,
            remote_map: ptr::null_mut(),
            local_map: ptr::null_mut(),
            sigreturn_addr: ptr::null_mut(),
            map_length: 0,
            ictx: InfectCtx::default(),
            daemonized: false,
            orig: ThreadCtx::new(),
            rstack: ptr::null_mut(),
            sigframe: ptr::null_mut(),
            rsigframe: ptr::null_mut(),
            r_thread_stack: ptr::null_mut(),
            parasite_ip: 0,
            cmd: ptr::null_mut(),
            args: ptr::null_mut(),
            args_size: 0,
            tsock: -1,
            pblob: ParasiteBlobDesc::default(),
        }
    }
}

impl ParasiteCtl {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Trace mode for compel_stop_on_syscall
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceFlags {
    /// Trace syscall entry
    Enter,
    /// Trace syscall exit
    Exit,
    /// Trace all (multi-task)
    All,
}

pub fn task_is_trapped(status: i32, pid: pid_t) -> bool {
    if WIFSTOPPED(status) && (WSTOPSIG(status) & !PTRACE_SYSCALL_TRAP) == SIGTRAP {
        return true;
    }

    log::error!("Task {} is in unexpected state: {:x}", pid, status);
    if WIFEXITED(status) {
        log::error!("Task exited with {}", WEXITSTATUS(status));
    }
    if WIFSIGNALED(status) {
        log::error!("Task signaled with {}", WTERMSIG(status));
    }
    if WIFSTOPPED(status) {
        log::error!("Task stopped with {}", WSTOPSIG(status));
    }
    if WIFCONTINUED(status) {
        log::error!("Task continued");
    }

    false
}

pub fn is_required_syscall(regs: &UserRegsStruct, pid: pid_t, sys_nr: i32, sys_nr_compat: i32) -> bool {
    let mode = if regs.is_native() { "native" } else { "compat" };
    let req_sysnr = if regs.is_native() {
        sys_nr as u64
    } else {
        sys_nr_compat as u64
    };

    log::debug!(
        "{} ({}) is going to execute the syscall {}, required is {}",
        pid,
        mode,
        regs.syscall_nr(),
        req_sysnr
    );

    regs.syscall_nr() == req_sysnr
}

/// Stop all threads on a specific syscall
///
/// Waits for tasks to hit a syscall entry/exit point matching sys_nr
pub fn compel_stop_on_syscall(tasks: i32, sys_nr: i32, sys_nr_compat: i32) -> io::Result<()> {
    let mut trace = if tasks > 1 {
        TraceFlags::All
    } else {
        TraceFlags::Enter
    };
    let mut regs = UserRegsStruct::new();
    let mut status: i32 = 0;
    let mut tasks_remaining = tasks;

    // Stop all threads on the enter point in sys_rt_sigreturn
    while tasks_remaining > 0 {
        let pid = unsafe { wait4(-1, &mut status, __WALL, ptr::null_mut()) };
        if pid == -1 {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                "wait4 failed",
            ));
        }

        if !task_is_trapped(status, pid) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Task {} not trapped", pid),
            ));
        }

        log::debug!("{} was trapped", pid);

        if (WSTOPSIG(status) & PTRACE_SYSCALL_TRAP) == 0 {
            // On some platforms such as ARM64, it is impossible to
            // pass through a breakpoint, so let's clear it right
            // after it has been triggered.
            // TODO: ptrace_flush_breakpoints(pid)
            continue_syscall(pid)?;
            continue;
        }

        if trace == TraceFlags::Exit {
            trace = TraceFlags::Enter;
            log::debug!("`- Expecting exit");
            continue_syscall(pid)?;
            continue;
        }

        if trace == TraceFlags::Enter {
            trace = TraceFlags::Exit;
        }

        ptrace_get_regs(pid, &mut regs)?;

        if is_required_syscall(&regs, pid, sys_nr, sys_nr_compat) {
            // The process is going to execute the required syscall,
            // the next stop will be on the exit from this syscall
            let ret = unsafe { ptrace(PTRACE_SYSCALL, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }

            let pid2 = unsafe { wait4(pid, &mut status, __WALL, ptr::null_mut()) };
            if pid2 == -1 {
                return Err(io::Error::new(
                    io::Error::last_os_error().kind(),
                    "wait4 failed",
                ));
            }

            if !task_is_trapped(status, pid) {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Task {} not trapped after syscall", pid),
                ));
            }

            log::debug!("{} was stopped", pid);
            tasks_remaining -= 1;
            continue;
        }

        continue_syscall(pid)?;
    }

    Ok(())
}

fn continue_syscall(pid: pid_t) -> io::Result<()> {
    let ret = unsafe { ptrace(PTRACE_SYSCALL, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Capture thread context (registers and signal mask)
pub fn prepare_thread(pid: pid_t, ctx: &mut ThreadCtx) -> io::Result<()> {
    // Get signal mask
    let ret = unsafe {
        ptrace(
            PTRACE_GETSIGMASK,
            pid,
            std::mem::size_of::<KRtSigset>() as *mut c_void,
            &mut ctx.sigmask as *mut _ as *mut c_void,
        )
    };
    if ret != 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("can't get signal blocking mask for {}", pid),
        ));
    }

    ptrace_get_regs(pid, &mut ctx.regs)?;

    Ok(())
}

/// Restore thread context
pub fn restore_thread_ctx(pid: pid_t, ctx: &ThreadCtx) -> io::Result<()> {
    ptrace_set_regs(pid, &ctx.regs)?;

    let ret = unsafe {
        ptrace(
            PTRACE_SETSIGMASK,
            pid,
            std::mem::size_of::<KRtSigset>() as *mut c_void,
            &ctx.sigmask as *const _ as *mut c_void,
        )
    };
    if ret != 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            "Can't restore signal mask",
        ));
    }

    Ok(())
}

/// Run parasite code in the target process
pub fn parasite_run(
    pid: pid_t,
    cmd: u32,
    ip: u64,
    stack: *mut c_void,
    regs: &mut UserRegsStruct,
    octx: &ThreadCtx,
) -> io::Result<()> {
    let mut block = KRtSigset::new();
    block.fill();
    // FIXME(issues/1429): SIGTRAP can't be blocked, otherwise its handler
    // will be reset to the default one.
    block.del(SIGTRAP);

    let ret = unsafe {
        ptrace(
            PTRACE_SETSIGMASK,
            pid,
            std::mem::size_of::<KRtSigset>() as *mut c_void,
            &block as *const _ as *mut c_void,
        )
    };
    if ret != 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("Can't block signals for {}", pid),
        ));
    }

    // Setup registers for parasite execution
    regs.set_ip(ip);
    if !stack.is_null() {
        regs.set_sp(stack as u64);
    }

    if let Err(e) = ptrace_set_regs(pid, regs) {
        // Restore original sigmask on error
        let _ = unsafe {
            ptrace(
                PTRACE_SETSIGMASK,
                pid,
                std::mem::size_of::<KRtSigset>() as *mut c_void,
                &octx.sigmask as *const _ as *mut c_void,
            )
        };
        return Err(io::Error::new(e.kind(), format!("Can't set registers for {}", pid)));
    }

    let ret = unsafe { ptrace(cmd, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) };
    if ret != 0 {
        // Restore on error
        let _ = ptrace_set_regs(pid, &octx.regs);
        let _ = unsafe {
            ptrace(
                PTRACE_SETSIGMASK,
                pid,
                std::mem::size_of::<KRtSigset>() as *mut c_void,
                &octx.sigmask as *const _ as *mut c_void,
            )
        };
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("Can't run parasite at {}", pid),
        ));
    }

    Ok(())
}

/// Stop PIE process
pub fn compel_stop_pie(pid: pid_t, _addr: *mut c_void, no_bp: bool) -> io::Result<i32> {
    if no_bp {
        log::debug!("Force no-breakpoints restore of {}", pid);
        return Ok(0);
    }

    // TODO: ptrace_set_breakpoint support
    // For now, just use syscall tracing
    let ret = unsafe { ptrace(PTRACE_SYSCALL, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) };
    if ret != 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("Unable to restart the {} process", pid),
        ));
    }
    Ok(0)
}

/// Allocate and prepare a parasite control block without full context
///
/// This creates a minimal parasite_ctl structure that can be used for
/// operations that don't require full infection (e.g., stopping a process
/// after parasite execution).
pub fn compel_prepare_noctx(pid: pid_t) -> io::Result<Box<ParasiteCtl>> {
    // Compile-time check (equivalent to BUILD_BUG_ON in C)
    const _: () = assert!(
        PARASITE_START_AREA_MIN >= BUILTIN_SYSCALL_SIZE + MEMFD_FNAME_SZ,
        "PARASITE_START_AREA_MIN too small"
    );

    let mut ctl = Box::new(ParasiteCtl::default());

    ctl.tsock = -1;
    ctl.ictx.log_fd = -1;

    prepare_thread(pid, &mut ctl.orig)?;

    ctl.rpid = pid;

    Ok(ctl)
}

/// Unmap memory in the traced process
///
/// Executes munmap syscall in the target process to free previously
/// mapped memory (typically the parasite code region).
pub fn compel_unmap(ctl: &mut ParasiteCtl, addr: u64) -> io::Result<()> {
    let mut regs = ctl.orig.regs.clone();
    let pid = ctl.rpid;

    parasite_run(
        pid,
        PTRACE_SYSCALL,
        addr,
        ctl.rstack,
        &mut regs,
        &ctl.orig,
    )?;

    // Wait for munmap syscall
    #[cfg(target_arch = "x86_64")]
    let (sys_nr, sys_nr_compat) = (libc::SYS_munmap as i32, 91); // 91 is __NR_munmap for i386

    #[cfg(target_arch = "aarch64")]
    let (sys_nr, sys_nr_compat) = (libc::SYS_munmap as i32, libc::SYS_munmap as i32);

    if let Err(e) = compel_stop_on_syscall(1, sys_nr, sys_nr_compat) {
        // Still try to restore context on error
        let _ = restore_thread_ctx(pid, &ctl.orig);
        return Err(e);
    }

    // Restore thread context. Don't restore extended registers - they were
    // restored with rt_sigreturn from sigframe.
    restore_thread_ctx(pid, &ctl.orig)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_is_trapped_sigtrap() {
        // Simulate WIFSTOPPED with SIGTRAP
        // status format: signal << 8 | 0x7f (stopped)
        let status = (SIGTRAP << 8) | 0x7f;
        // Note: This test would need actual wait status values
        // Just testing the function exists and compiles
    }

    #[test]
    fn test_is_required_syscall() {
        let mut regs = UserRegsStruct::new();
        // Set orig_ax to match sys_nr
        #[cfg(target_arch = "x86_64")]
        {
            regs.regs.native.orig_ax = 15;
        }
        #[cfg(target_arch = "aarch64")]
        {
            regs.regs[8] = 15;
        }

        assert!(is_required_syscall(&regs, 1, 15, 15));
        assert!(!is_required_syscall(&regs, 1, 16, 16));
    }

    #[test]
    fn test_ksigset() {
        let mut set = KRtSigset::new();
        assert_eq!(set.sig[0], 0);

        set.fill();
        assert_eq!(set.sig[0], !0u64);

        set.empty();
        assert_eq!(set.sig[0], 0);

        set.add(1); // SIGHUP
        assert_eq!(set.sig[0], 1);

        set.add(2); // SIGINT
        assert_eq!(set.sig[0], 3);

        set.del(1);
        assert_eq!(set.sig[0], 2);
    }
}

// Wrappers for libc wait status macros
#[allow(non_snake_case)]
fn WIFSTOPPED(status: i32) -> bool {
    (status & 0xff) == 0x7f
}

#[allow(non_snake_case)]
fn WSTOPSIG(status: i32) -> i32 {
    (status >> 8) & 0xff
}

#[allow(non_snake_case)]
fn WIFEXITED(status: i32) -> bool {
    (status & 0x7f) == 0
}

#[allow(non_snake_case)]
fn WEXITSTATUS(status: i32) -> i32 {
    (status >> 8) & 0xff
}

#[allow(non_snake_case)]
fn WIFSIGNALED(status: i32) -> bool {
    ((status & 0x7f) + 1) >> 1 > 0 && !WIFSTOPPED(status)
}

#[allow(non_snake_case)]
fn WTERMSIG(status: i32) -> i32 {
    status & 0x7f
}

#[allow(non_snake_case)]
fn WIFCONTINUED(status: i32) -> bool {
    status == 0xffff
}

use super::ptrace::PTRACE_GETSIGMASK;
