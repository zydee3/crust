//! Architecture-specific types and macros for compel

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

/// Signal set constants
pub const KNSIG: usize = 64;
pub const NSIG_BPW: usize = 64;
pub const KNSIG_WORDS: usize = KNSIG / NSIG_BPW;

/// Kernel signal set
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct KRtSigset {
    pub sig: [u64; KNSIG_WORDS],
}

impl KRtSigset {
    pub const fn new() -> Self {
        Self {
            sig: [0; KNSIG_WORDS],
        }
    }

    pub fn fill(&mut self) {
        for i in 0..KNSIG_WORDS {
            self.sig[i] = !0u64;
        }
    }

    pub fn empty(&mut self) {
        for i in 0..KNSIG_WORDS {
            self.sig[i] = 0;
        }
    }

    pub fn add(&mut self, sig: i32) {
        let s = (sig - 1) as usize;
        self.sig[s / NSIG_BPW] |= 1u64 << (s % NSIG_BPW);
    }

    pub fn del(&mut self, sig: i32) {
        let s = (sig - 1) as usize;
        self.sig[s / NSIG_BPW] &= !(1u64 << (s % NSIG_BPW));
    }
}

/// Thread context saved during parasite operations
#[derive(Debug, Clone)]
pub struct ThreadCtx {
    pub sigmask: KRtSigset,
    pub regs: UserRegsStruct,
}

impl ThreadCtx {
    pub fn new() -> Self {
        Self {
            sigmask: KRtSigset::new(),
            regs: UserRegsStruct::new(),
        }
    }
}

impl Default for ThreadCtx {
    fn default() -> Self {
        Self::new()
    }
}
