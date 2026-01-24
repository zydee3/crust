//! Ptrace wrapper functions

use std::io;
use std::mem;
use std::ptr;

use libc::{c_void, iovec, pid_t, ptrace, NT_PRSTATUS, PTRACE_PEEKDATA, PTRACE_POKEDATA};

use super::arch::UserRegsStruct;

/// PTRACE_O_SUSPEND_SECCOMP option
pub const PTRACE_O_SUSPEND_SECCOMP: u32 = 1 << 21;

/// PTRACE_O_TRACESYSGOOD option - set bit 7 in signal number on syscall stops
pub const PTRACE_O_TRACESYSGOOD: u32 = 1;

/// PTRACE_SYSCALL_TRAP - bit set in WSTOPSIG when stopped on syscall
pub const PTRACE_SYSCALL_TRAP: i32 = 0x80;

/// PTRACE_GETREGSET request
pub const PTRACE_GETREGSET: u32 = 0x4204;

/// PTRACE_SETREGSET request
pub const PTRACE_SETREGSET: u32 = 0x4205;

/// PTRACE_SETOPTIONS request
pub const PTRACE_SETOPTIONS: u32 = 0x4200;

/// PTRACE_GETSIGMASK request
pub const PTRACE_GETSIGMASK: u32 = 0x420a;

/// PTRACE_SETSIGMASK request
pub const PTRACE_SETSIGMASK: u32 = 0x420b;

/// PTRACE_SYSCALL request
pub const PTRACE_SYSCALL: u32 = 24;

pub fn ptrace_suspend_seccomp(pid: pid_t) -> io::Result<()> {
    let ret = unsafe {
        ptrace(
            PTRACE_SETOPTIONS,
            pid,
            ptr::null_mut::<c_void>(),
            (PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD) as *mut c_void,
        )
    };
    if ret < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            "suspending seccomp failed",
        ));
    }
    Ok(())
}

pub fn ptrace_poke_area(pid: pid_t, src: *const c_void, addr: *mut c_void, bytes: usize) -> io::Result<()> {
    if bytes & (mem::size_of::<libc::c_long>() - 1) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Poke request with non-word size {}", bytes),
        ));
    }

    let src = src as *const libc::c_long;
    let addr = addr as *mut libc::c_long;
    let words = bytes / mem::size_of::<libc::c_long>();

    for w in 0..words {
        let val = unsafe { *src.add(w) };
        let ret = unsafe { ptrace(PTRACE_POKEDATA, pid, addr.add(w), val as *mut c_void) };
        if ret != 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(io::Error::from_raw_os_error(errno));
        }
    }
    Ok(())
}

pub fn ptrace_peek_area(pid: pid_t, dst: *mut c_void, addr: *const c_void, bytes: usize) -> io::Result<()> {
    if bytes & (mem::size_of::<libc::c_long>() - 1) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Peek request with non-word size {}", bytes),
        ));
    }

    let dst = dst as *mut libc::c_long;
    let addr = addr as *const libc::c_long;
    let words = bytes / mem::size_of::<libc::c_long>();

    for w in 0..words {
        // Clear errno before call
        unsafe { *libc::__errno_location() = 0 };
        let val = unsafe { ptrace(PTRACE_PEEKDATA, pid, addr.add(w), ptr::null_mut::<c_void>()) };
        let errno = unsafe { *libc::__errno_location() };
        if errno != 0 {
            return Err(io::Error::from_raw_os_error(errno));
        }
        unsafe {
            *dst.add(w) = val;
        }
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
pub fn ptrace_get_regs(pid: pid_t, regs: &mut UserRegsStruct) -> io::Result<()> {
    let mut iov = iovec {
        iov_base: unsafe { &mut regs.regs.native as *mut _ as *mut c_void },
        iov_len: mem::size_of::<super::arch::x86_64::UserRegsStruct64>(),
    };

    let ret = unsafe { ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS as *mut c_void, &mut iov as *mut _ as *mut c_void) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }

    if iov.iov_len == mem::size_of::<super::arch::x86_64::UserRegsStruct64>() {
        regs.is_native = 0x0A; // NATIVE_MAGIC
        return Ok(());
    }
    if iov.iov_len == mem::size_of::<super::arch::x86_64::UserRegsStruct32>() {
        regs.is_native = 0x0C; // COMPAT_MAGIC
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "PTRACE_GETREGSET read {} bytes for pid {}, but native/compat regs sizes are {}/{} bytes",
            iov.iov_len,
            pid,
            mem::size_of::<super::arch::x86_64::UserRegsStruct64>(),
            mem::size_of::<super::arch::x86_64::UserRegsStruct32>()
        ),
    ))
}

#[cfg(target_arch = "x86_64")]
pub fn ptrace_set_regs(pid: pid_t, regs: &UserRegsStruct) -> io::Result<()> {
    let (base, len) = if regs.is_native() {
        (
            unsafe { &regs.regs.native as *const _ as *const c_void },
            mem::size_of::<super::arch::x86_64::UserRegsStruct64>(),
        )
    } else {
        (
            unsafe { &regs.regs.compat as *const _ as *const c_void },
            mem::size_of::<super::arch::x86_64::UserRegsStruct32>(),
        )
    };

    let iov = iovec {
        iov_base: base as *mut c_void,
        iov_len: len,
    };

    let ret = unsafe { ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS as *mut c_void, &iov as *const _ as *mut c_void) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
pub fn ptrace_get_regs(pid: pid_t, regs: &mut UserRegsStruct) -> io::Result<()> {
    let mut iov = iovec {
        iov_base: regs as *mut _ as *mut c_void,
        iov_len: mem::size_of::<UserRegsStruct>(),
    };

    let ret = unsafe { ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS as *mut c_void, &mut iov as *mut _ as *mut c_void) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
pub fn ptrace_set_regs(pid: pid_t, regs: &UserRegsStruct) -> io::Result<()> {
    let iov = iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: mem::size_of::<UserRegsStruct>(),
    };

    let ret = unsafe { ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS as *mut c_void, &iov as *const _ as *mut c_void) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(PTRACE_SYSCALL_TRAP, 0x80);
        assert_eq!(PTRACE_GETREGSET, 0x4204);
        assert_eq!(PTRACE_SETREGSET, 0x4205);
    }
}
