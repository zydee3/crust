//! Error handling for syscalls

use core::fmt;

/// Syscall error wrapper
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl Errno {
    /// Check if return value is an error (negative values in range [-4095, -1])
    #[inline(always)]
    pub fn from_syscall_ret(ret: i64) -> Result<usize, Self> {
        if ret < 0 && ret >= -4095 {
            Err(Errno(-ret as i32))
        } else {
            Ok(ret as usize)
        }
    }

    /// Common errno values
    pub const EINTR: i32 = 4;
    pub const EAGAIN: i32 = 11;
    pub const ENOMEM: i32 = 12;
    pub const EFAULT: i32 = 14;
    pub const EINVAL: i32 = 22;
}

#[cfg(feature = "std")]
impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Errno {}
