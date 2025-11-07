//! Syscall numbers and constants for x86_64 Linux

// Syscall numbers
pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_MMAP: u64 = 9;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_RT_SIGRETURN: u64 = 15;
pub const SYS_MREMAP: u64 = 25;
pub const SYS_CLONE: u64 = 56;
pub const SYS_PRCTL: u64 = 157;
pub const SYS_ARCH_PRCTL: u64 = 158;

// mmap() prot flags
pub const PROT_NONE: i32 = 0x0;
pub const PROT_READ: i32 = 0x1;
pub const PROT_WRITE: i32 = 0x2;
pub const PROT_EXEC: i32 = 0x4;

// mmap() flags
pub const MAP_SHARED: i32 = 0x01;
pub const MAP_PRIVATE: i32 = 0x02;
pub const MAP_FIXED: i32 = 0x10;
pub const MAP_ANONYMOUS: i32 = 0x20;

// mremap() flags
pub const MREMAP_MAYMOVE: i32 = 1;
pub const MREMAP_FIXED: i32 = 2;

// prctl() operations
pub const PR_SET_MM: i32 = 35;
pub const PR_SET_MM_MAP: i32 = 14;

// arch_prctl() operations
pub const ARCH_SET_FS: i32 = 0x1002;
pub const ARCH_SET_GS: i32 = 0x1001;

// Open flags
pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
