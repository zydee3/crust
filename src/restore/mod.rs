//! Process restoration logic
//!
//! This module contains the core logic for restoring processes from
//! CRIU checkpoint images.

pub mod args;
pub mod inject;
pub mod pid;

pub use args::{TaskRestoreArgs, VmaEntry};
pub use inject::{
    inject_restorer_blob,
    find_restorer_gap,
    find_address_gaps,
    find_bootstrap_gap,
    AddressGap,
};
pub use pid::{fork_with_pid, clone3_with_pid, fork_with_ns_last_pid};
