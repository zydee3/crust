use std::ffi::c_void;

/// Clone3 arguments structure for the clone3 syscall.
/// Maps to: criu/include/sched.h:_clone_args (lines 21-32)
#[repr(C)]
#[derive(Default)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
}

/// Creates a process using clone3() with a specific PID.
///
/// Maps to: criu/clone-noasan.c:clone3_with_pid_noasan (lines 49-84)
///
/// Arguments:
/// - `f`: Function to execute in child process
/// - `arg`: Argument to pass to function
/// - `flags`: Clone flags (must not include CLONE_VM or low 8 bits)
/// - `exit_signal`: Signal sent to parent on child exit
/// - `pid`: Target PID for the new process
///
/// Returns the child PID on success, -1 on error.
pub fn clone3_with_pid_noasan<F>(
    f: F,
    arg: *mut c_void,
    flags: i32,
    exit_signal: i32,
    pid: libc::pid_t,
) -> libc::pid_t
where
    F: FnOnce(*mut c_void) -> i32,
{
    // BUG_ON(flags & CLONE_VM)
    assert!(
        (flags & libc::CLONE_VM) == 0,
        "BUG: clone3_with_pid_noasan does not support CLONE_VM"
    );

    // Make sure no child signals are requested. clone3() uses exit_signal for that.
    // BUG_ON(flags & 0xff)
    assert!(
        (flags & 0xff) == 0,
        "BUG: clone3_with_pid_noasan does not support child signals in flags"
    );

    log::debug!("Creating process using clone3()");

    let mut c_args = CloneArgs::default();

    // clone3() explicitly blocks setting an exit_signal if CLONE_PARENT is specified.
    // With clone() it also did not work, but there was no error message.
    // The exit signal from the thread group leader is taken.
    if (flags & libc::CLONE_PARENT) == 0 {
        if exit_signal != libc::SIGCHLD {
            log::error!("Exit signal not SIGCHLD");
            unsafe {
                *libc::__errno_location() = libc::EINVAL;
            }
            return -1;
        }
        c_args.exit_signal = exit_signal as u64;
    }

    c_args.flags = flags as u64;

    // For clone3 with set_tid, we need to pass a pointer to the pid value
    // and set set_tid_size to 1 (one level of PID namespace)
    let mut target_pid = pid;
    c_args.set_tid = &mut target_pid as *mut _ as u64;
    c_args.set_tid_size = 1;

    // Call clone3 syscall
    // Note: __NR_clone3 is 435 on x86_64, 435 on aarch64
    #[cfg(target_arch = "x86_64")]
    const __NR_CLONE3: libc::c_long = 435;
    #[cfg(target_arch = "aarch64")]
    const __NR_CLONE3: libc::c_long = 435;

    let result = unsafe {
        libc::syscall(
            __NR_CLONE3,
            &c_args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    } as libc::pid_t;

    if result == 0 {
        // Child process - execute function and exit
        let ret = f(arg);
        unsafe { libc::exit(ret) };
    }

    result
}

pub fn clone_noasan<F>(f: F, flags: i32, arg: *mut c_void) -> libc::pid_t
where
    F: FnOnce(*mut c_void) -> i32,
{
    // The C code calculates a stack pointer from the current stack.
    // We allocate a stack buffer for the child instead.
    const STACK_SIZE: usize = 4096;
    let mut stack = vec![0u8; STACK_SIZE];
    let stack_top = stack.as_mut_ptr().wrapping_add(STACK_SIZE) as *mut c_void;

    // Ensure CLONE_VM requires CLONE_VFORK
    if (flags & libc::CLONE_VM) != 0 && (flags & libc::CLONE_VFORK) == 0 {
        panic!("BUG: CLONE_VM requires CLONE_VFORK");
    }

    // We need to use the raw clone syscall with a function pointer.
    // Since Rust closures can't be passed to clone directly, we use a trampoline.
    extern "C" fn trampoline<F: FnOnce(*mut c_void) -> i32>(arg: *mut c_void) -> i32 {
        // Safety: This is only called once from clone, and we reconstruct the closure
        let closure_and_arg: &mut (Option<F>, *mut c_void) =
            unsafe { &mut *(arg as *mut (Option<F>, *mut c_void)) };
        let f = closure_and_arg.0.take().unwrap();
        let user_arg = closure_and_arg.1;
        f(user_arg)
    }

    let mut closure_and_arg: (Option<F>, *mut c_void) = (Some(f), arg);
    let closure_ptr = &mut closure_and_arg as *mut _ as *mut c_void;

    // Safety: We're calling clone with proper stack alignment
    let pid = unsafe { libc::clone(trampoline::<F>, stack_top, flags, closure_ptr) };

    // If clone fails with CLONE_VFORK | CLONE_VM, the closure was never taken
    // If it succeeds, the child ran synchronously (CLONE_VFORK) so we're safe

    pid
}

pub fn clone_noasan_raw(
    f: extern "C" fn(*mut c_void) -> i32,
    flags: i32,
    arg: *mut c_void,
) -> libc::pid_t {
    const STACK_SIZE: usize = 4096;
    let mut stack = vec![0u8; STACK_SIZE];
    let stack_top = stack.as_mut_ptr().wrapping_add(STACK_SIZE) as *mut c_void;

    if (flags & libc::CLONE_VM) != 0 && (flags & libc::CLONE_VFORK) == 0 {
        panic!("BUG: CLONE_VM requires CLONE_VFORK");
    }

    unsafe { libc::clone(f, stack_top, flags, arg) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clone_args_struct_size() {
        // CloneArgs should be 80 bytes (10 x u64)
        assert_eq!(std::mem::size_of::<CloneArgs>(), 80);
    }

    #[test]
    fn test_clone_args_default() {
        let args = CloneArgs::default();
        assert_eq!(args.flags, 0);
        assert_eq!(args.pidfd, 0);
        assert_eq!(args.child_tid, 0);
        assert_eq!(args.parent_tid, 0);
        assert_eq!(args.exit_signal, 0);
        assert_eq!(args.stack, 0);
        assert_eq!(args.stack_size, 0);
        assert_eq!(args.tls, 0);
        assert_eq!(args.set_tid, 0);
        assert_eq!(args.set_tid_size, 0);
    }

    #[test]
    #[should_panic(expected = "BUG: clone3_with_pid_noasan does not support CLONE_VM")]
    fn test_clone3_with_pid_rejects_clone_vm() {
        clone3_with_pid_noasan(
            |_| 0,
            std::ptr::null_mut(),
            libc::CLONE_VM,
            libc::SIGCHLD,
            12345,
        );
    }

    #[test]
    #[should_panic(expected = "BUG: clone3_with_pid_noasan does not support child signals in flags")]
    fn test_clone3_with_pid_rejects_signals_in_flags() {
        // Lower 8 bits contain child signal
        clone3_with_pid_noasan(|_| 0, std::ptr::null_mut(), 0x01, libc::SIGCHLD, 12345);
    }

    #[test]
    fn test_clone3_with_pid_non_sigchld_without_clone_parent() {
        // Without CLONE_PARENT, exit_signal must be SIGCHLD
        let result = clone3_with_pid_noasan(
            |_| 0,
            std::ptr::null_mut(),
            0,
            libc::SIGUSR1, // Not SIGCHLD
            12345,
        );
        assert_eq!(result, -1);
    }
}
