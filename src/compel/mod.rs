//! Compel - parasite code injection library
//!
//! Port of CRIU's compel library for injecting and executing code
//! in a traced process.

pub mod arch;
pub mod infect;
pub mod ptrace;

pub use arch::{KRtSigset, ThreadCtx, UserRegsStruct};
pub use infect::{
    compel_stop_on_syscall, compel_stop_pie, is_required_syscall, parasite_run, prepare_thread,
    restore_thread_ctx, task_is_trapped,
};
pub use ptrace::{
    ptrace_get_regs, ptrace_peek_area, ptrace_poke_area, ptrace_set_regs, ptrace_suspend_seccomp,
    PTRACE_SYSCALL_TRAP,
};
