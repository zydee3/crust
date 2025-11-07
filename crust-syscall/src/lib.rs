//! Raw syscall wrappers for crust
//!
//! This crate provides no_std syscall wrappers using inline assembly.
//! It's shared between the main binary (with std) and the restorer blob (no_std).

#![cfg_attr(not(feature = "std"), no_std)]

pub mod raw;
pub mod syscalls;
pub mod constants;
pub mod errno;

pub use syscalls::*;
pub use constants::*;
pub use errno::Errno;
