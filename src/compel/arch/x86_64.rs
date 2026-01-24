//! x86_64 architecture-specific types

/// 64-bit user registers
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UserRegsStruct64 {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub bp: u64,
    pub bx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub ax: u64,
    pub cx: u64,
    pub dx: u64,
    pub si: u64,
    pub di: u64,
    pub orig_ax: u64,
    pub ip: u64,
    pub cs: u64,
    pub flags: u64,
    pub sp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

/// 32-bit user registers (compat mode)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UserRegsStruct32 {
    pub bx: u32,
    pub cx: u32,
    pub dx: u32,
    pub si: u32,
    pub di: u32,
    pub bp: u32,
    pub ax: u32,
    pub ds: u32,
    pub es: u32,
    pub fs: u32,
    pub gs: u32,
    pub orig_ax: u32,
    pub ip: u32,
    pub cs: u32,
    pub flags: u32,
    pub sp: u32,
    pub ss: u32,
}

pub const NATIVE_MAGIC: i16 = 0x0A;
pub const COMPAT_MAGIC: i16 = 0x0C;

/// Union of native and compat registers
///
/// To be sure that we rely on inited reg->__is_native, this member
/// is (short int) instead of initial (bool). The right way to
/// check if regs are native or compat is to use user_regs_native() macro.
#[derive(Clone, Copy)]
#[repr(C)]
pub union UserRegsUnion {
    pub native: UserRegsStruct64,
    pub compat: UserRegsStruct32,
}

impl Default for UserRegsUnion {
    fn default() -> Self {
        Self {
            native: UserRegsStruct64::default(),
        }
    }
}

impl std::fmt::Debug for UserRegsUnion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Default to showing native
        unsafe { write!(f, "{:?}", self.native) }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct UserRegsStruct {
    pub regs: UserRegsUnion,
    /// use user_regs_native macro to check it
    pub is_native: i16,
}

impl Default for UserRegsStruct {
    fn default() -> Self {
        Self {
            regs: UserRegsUnion::default(),
            is_native: NATIVE_MAGIC,
        }
    }
}

impl std::fmt::Debug for UserRegsStruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_native() {
            unsafe { write!(f, "UserRegsStruct {{ native: {:?} }}", self.regs.native) }
        } else {
            unsafe { write!(f, "UserRegsStruct {{ compat: {:?} }}", self.regs.compat) }
        }
    }
}

impl UserRegsStruct {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_native(&self) -> bool {
        self.is_native == NATIVE_MAGIC
    }

    pub fn set_native(&mut self) {
        self.is_native = NATIVE_MAGIC;
    }

    pub fn set_compat(&mut self) {
        self.is_native = COMPAT_MAGIC;
    }

    /// Get syscall number (orig_ax)
    pub fn syscall_nr(&self) -> u64 {
        if self.is_native() {
            unsafe { self.regs.native.orig_ax }
        } else {
            unsafe { self.regs.compat.orig_ax as u64 }
        }
    }

    /// Get instruction pointer
    pub fn ip(&self) -> u64 {
        if self.is_native() {
            unsafe { self.regs.native.ip }
        } else {
            unsafe { self.regs.compat.ip as u64 }
        }
    }

    /// Set instruction pointer
    pub fn set_ip(&mut self, val: u64) {
        if self.is_native() {
            self.regs.native.ip = val;
        } else {
            self.regs.compat.ip = val as u32;
        }
    }

    /// Get stack pointer
    pub fn sp(&self) -> u64 {
        if self.is_native() {
            unsafe { self.regs.native.sp }
        } else {
            unsafe { self.regs.compat.sp as u64 }
        }
    }

    /// Set stack pointer
    pub fn set_sp(&mut self, val: u64) {
        if self.is_native() {
            self.regs.native.sp = val;
        } else {
            self.regs.compat.sp = val as u32;
        }
    }

    /// Get result register (ax)
    pub fn result(&self) -> u64 {
        if self.is_native() {
            unsafe { self.regs.native.ax }
        } else {
            unsafe { self.regs.compat.ax as u64 }
        }
    }
}

/// Get the correct syscall number based on native/compat mode
pub fn nr_syscall(syscall_native: i64, syscall_compat: i64, is_compat: bool) -> i64 {
    if is_compat {
        syscall_compat
    } else {
        syscall_native
    }
}
