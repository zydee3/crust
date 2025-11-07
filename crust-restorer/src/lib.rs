//! CRIU Restorer Blob
//!
//! This is a no_std, no_main PIE blob that executes inside the target process
//! to perform operations impossible from outside (rt_sigreturn, CLONE_THREAD, etc.).
//!
//! Design: Inline-only approach (Option 1 from restorer_blob_design.md)
//! Goal: Zero relocations by inlining all functions

#![no_std]
#![no_main]

use core::arch::asm;
use crust_syscall::*;

/// Task restore arguments passed from parent process
#[repr(C)]
pub struct TaskRestoreArgs {
    /// Base address of bootstrap region
    pub bootstrap_base: usize,
    /// Length of bootstrap region to unmap
    pub bootstrap_len: usize,
    /// Number of VMAs to restore
    pub vma_count: usize,
    /// Pointer to VMA array (in bootstrap region)
    pub vmas: *const VmaEntry,
    /// Pointer to sigframe for rt_sigreturn
    pub sigframe: *const u8,
}

/// VMA entry describing memory region to restore
#[repr(C)]
pub struct VmaEntry {
    pub start: usize,
    pub end: usize,
    pub prot: i32,
    pub flags: i32,
    pub premap_addr: usize,  // Where it was premapped
}

/// Entry point called by parent process
///
/// This is the function the parent sets RIP to after injection.
/// It must never return.
#[no_mangle]
#[inline(never)]  // Entry point cannot be inlined
pub extern "C" fn _start(args: *const TaskRestoreArgs) -> ! {
    unsafe {
        let args = &*args;

        // Step 1: Unmap old VMAs (CRIU's memory)
        unmap_old_vmas(args);

        // Step 2: Restore VMAs to final addresses
        restore_vmas(args);

        // Step 3: Restore CPU state and jump to original RIP
        restore_cpu_state(args);
    }
}

/// Unmap CRIU's memory (everything except bootstrap and premapped VMAs)
#[inline(always)]
unsafe fn unmap_old_vmas(_args: &TaskRestoreArgs) {
    // For MVP: Simply unmap the bootstrap region at the end
    // Full implementation would unmap all CRIU mappings

    // We'll do this at the very end, just before rt_sigreturn
    // For now, just a placeholder
}

/// Restore VMAs to their final addresses using mremap
#[inline(always)]
unsafe fn restore_vmas(args: &TaskRestoreArgs) {
    let vmas = core::slice::from_raw_parts(args.vmas, args.vma_count);

    // Process left-moving VMAs first (final_addr < premap_addr)
    for vma in vmas {
        if vma.start < vma.premap_addr {
            let len = vma.end - vma.start;
            let _ = mremap(
                vma.premap_addr,
                len,
                len,
                MREMAP_FIXED | MREMAP_MAYMOVE,
                vma.start,
            );
        }
    }

    // Then right-moving VMAs (final_addr > premap_addr)
    for vma in vmas.iter().rev() {
        if vma.start > vma.premap_addr {
            let len = vma.end - vma.start;
            let _ = mremap(
                vma.premap_addr,
                len,
                len,
                MREMAP_FIXED | MREMAP_MAYMOVE,
                vma.start,
            );
        }
    }
}

/// Restore CPU state via rt_sigreturn
#[inline(always)]
unsafe fn restore_cpu_state(args: &TaskRestoreArgs) -> ! {
    // Point stack at sigframe
    // rt_sigreturn expects RSP to point at the sigframe

    asm!(
        "mov rsp, {sigframe}",
        "mov rax, {nr_rt_sigreturn}",
        "syscall",
        sigframe = in(reg) args.sigframe,
        nr_rt_sigreturn = const SYS_RT_SIGRETURN,
        options(noreturn)
    );
}

/// Panic handler (required for no_std)
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        // Write "PANIC" to stderr (fd 2) and exit
        let msg = b"RESTORER PANIC\n";
        let _ = write(2, msg.as_ptr(), msg.len());

        // Infinite loop (can't exit from restorer)
        loop {
            core::hint::spin_loop();
        }
    }
}
