//! aarch64 architecture-specific types

/// aarch64 user registers (matches struct user_pt_regs from kernel)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UserRegsStruct {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

impl UserRegsStruct {
    pub fn new() -> Self {
        Self::default()
    }

    /// aarch64 is always "native" (no compat mode in our scope)
    pub fn is_native(&self) -> bool {
        true
    }

    /// Get syscall number (x8 register)
    pub fn syscall_nr(&self) -> u64 {
        self.regs[8]
    }

    /// Get instruction pointer (pc)
    pub fn ip(&self) -> u64 {
        self.pc
    }

    /// Set instruction pointer (pc)
    pub fn set_ip(&mut self, val: u64) {
        self.pc = val;
    }

    /// Get stack pointer
    pub fn sp(&self) -> u64 {
        self.sp
    }

    /// Set stack pointer
    pub fn set_sp(&mut self, val: u64) {
        self.sp = val;
    }

    /// Get result register (x0)
    pub fn result(&self) -> u64 {
        self.regs[0]
    }
}

/// Get the correct syscall number (aarch64 has no compat mode)
pub fn nr_syscall(syscall_native: i64, _syscall_compat: i64, _is_compat: bool) -> i64 {
    syscall_native
}
