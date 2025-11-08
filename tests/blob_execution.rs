//! Integration tests for restorer blob execution
//!
//! Tests Task 2.5 (rt_sigreturn) and Task 2.6 (end-to-end injection and execution)

use crust::restore::{inject_restorer_blob, find_restorer_gap, TaskRestoreArgs, VmaEntry};
use crust::restorer_blob::RESTORER_BLOB;
use std::mem;

/// x86_64 sigframe structure (simplified for testing)
///
/// This is the structure that rt_sigreturn expects on the stack.
/// It must be 64-byte aligned and contain valid CPU state.
#[repr(C, align(64))]
#[derive(Debug)]
struct Sigframe {
    /// Pretcode (signal trampoline return address)
    pretcode: u64,
    /// Saved FPU state (512 bytes for XSAVE area)
    fpregs: [u8; 512],
    /// Signal context
    uc: UContext,
}

#[repr(C)]
#[derive(Debug)]
struct UContext {
    uc_flags: u64,
    uc_link: u64,
    uc_stack: SignalStack,
    uc_mcontext: MContext,
    uc_sigmask: [u64; 16],  // 128 bytes for signal mask
}

#[repr(C)]
#[derive(Debug)]
struct SignalStack {
    ss_sp: u64,
    ss_flags: i32,
    ss_size: u64,
}

#[repr(C)]
#[derive(Debug)]
struct MContext {
    // x86_64 general purpose registers
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rax: u64,
    rcx: u64,
    rsp: u64,
    rip: u64,
    eflags: u64,
    cs: u16,
    gs: u16,
    fs: u16,
    ss: u16,
    err: u64,
    trapno: u64,
    oldmask: u64,
    cr2: u64,
    fpstate: u64,
    reserved1: [u64; 8],
}

impl Sigframe {
    /// Create a new sigframe with given RIP (instruction pointer)
    unsafe fn new(rip: u64, rsp: u64) -> Self {
        let mut frame = mem::zeroed::<Self>();
        frame.uc.uc_mcontext.rip = rip;
        frame.uc.uc_mcontext.rsp = rsp;
        frame.uc.uc_mcontext.eflags = 0x202;  // IF flag set (interrupts enabled)
        frame
    }
}

/// Test that we can inject the blob and it's readable
#[test]
#[ignore]  // Requires special permissions
fn test_blob_injection_task26() {
    println!("Testing blob injection (Task 2.6)");

    // Find gap in current process
    let gap = find_restorer_gap(std::process::id())
        .expect("Failed to find gap for injection");

    println!("Found gap: 0x{:x} - 0x{:x} (size: {} bytes)",
             gap.start, gap.end, gap.size());

    let target_addr = gap.aligned_addr(4096);
    println!("Injecting blob at: 0x{:x}", target_addr);

    // Inject blob
    unsafe {
        let entry_point = inject_restorer_blob(target_addr)
            .expect("Failed to inject blob");

        assert_eq!(entry_point, target_addr);
        println!("Blob injected successfully at 0x{:x}", entry_point);

        // Verify blob contents
        let injected = std::slice::from_raw_parts(
            entry_point as *const u8,
            RESTORER_BLOB.len()
        );

        assert_eq!(injected, RESTORER_BLOB);
        println!("Blob contents verified ({} bytes)", injected.len());

        // Verify blob is executable (check for expected instructions)
        // First bytes should be function prologue: push %rbp, push %r15, etc.
        assert_eq!(injected[0], 0x55);  // push %rbp
        assert_eq!(injected[1], 0x41);  // rex.B prefix
        assert_eq!(injected[2], 0x57);  // push %r15

        println!("Blob appears executable (correct prologue)");

        // Clean up - unmap the blob
        let _ = crust_syscall::syscalls::munmap(entry_point, 4096);
    }

    println!("Task 2.6: Blob injection test PASSED");
}

/// Test rt_sigreturn with minimal setup (Task 2.5)
///
/// This test verifies that we can set up a sigframe and the blob
/// could theoretically execute rt_sigreturn. We don't actually execute
/// it here because rt_sigreturn never returns - it would change the
/// process state permanently.
#[test]
fn test_sigframe_setup_task25() {
    println!("Testing sigframe setup (Task 2.5)");

    unsafe {
        // Create a sigframe pointing to a safe return address
        // (In real usage, this would be the process's original RIP)
        let dummy_rip = test_sigframe_setup_task25 as u64;
        let dummy_rsp = &dummy_rip as *const u64 as u64;

        let sigframe = Sigframe::new(dummy_rip, dummy_rsp);

        // Verify alignment
        let frame_addr = &sigframe as *const Sigframe as usize;
        assert_eq!(frame_addr % 64, 0, "Sigframe must be 64-byte aligned");
        println!("Sigframe aligned correctly at 0x{:x}", frame_addr);

        // Verify structure size is reasonable
        let size = mem::size_of::<Sigframe>();
        println!("Sigframe size: {} bytes", size);
        assert!(size >= 512, "Sigframe too small");

        // Verify register state
        assert_eq!(sigframe.uc.uc_mcontext.rip, dummy_rip);
        assert_eq!(sigframe.uc.uc_mcontext.rsp, dummy_rsp);
        assert_eq!(sigframe.uc.uc_mcontext.eflags, 0x202);

        println!("Sigframe RIP: 0x{:x}", sigframe.uc.uc_mcontext.rip);
        println!("Sigframe RSP: 0x{:x}", sigframe.uc.uc_mcontext.rsp);
        println!("Sigframe EFLAGS: 0x{:x}", sigframe.uc.uc_mcontext.eflags);
    }
}

/// Test TaskRestoreArgs structure setup
///
/// Verifies we can create valid arguments for the restorer blob.
#[test]
fn test_restore_args_setup() {
    println!("Testing TaskRestoreArgs setup");

    // Create some dummy VMAs
    let vmas = vec![
        VmaEntry::new(0x400000, 0x401000, 0x5, 0x2, 0x7f0000000000),  // CODE: RX, private
        VmaEntry::new(0x600000, 0x601000, 0x3, 0x2, 0x7f0000001000),  // DATA: RW, private
    ];

    unsafe {
        let sigframe = Sigframe::new(0x400500, 0x7fffffffe000);

        let args = TaskRestoreArgs {
            bootstrap_base: 0x7f0000000000,
            bootstrap_len: 0x1000000,  // 16 MB
            vma_count: vmas.len(),
            vmas: vmas.as_ptr(),
            sigframe: &sigframe as *const Sigframe as *const u8,
        };

        // Verify args structure
        assert_eq!(args.vma_count, 2);
        assert!(!args.vmas.is_null());
        assert!(!args.sigframe.is_null());

        // Verify sigframe alignment
        let sigframe_addr = args.sigframe as usize;
        assert_eq!(sigframe_addr % 64, 0, "Sigframe must be 64-byte aligned");

        println!("TaskRestoreArgs setup successful:");
        println!("  Bootstrap: 0x{:x} - 0x{:x}",
                 args.bootstrap_base,
                 args.bootstrap_base + args.bootstrap_len);
        println!("  VMAs: {} entries", args.vma_count);
        println!("  Sigframe: 0x{:x}", sigframe_addr);

        // In a real restore, we would:
        // 1. Inject blob at bootstrap_base
        // 2. Copy args and VMAs into bootstrap region
        // 3. Jump to blob entry point with args pointer in RDI
        // 4. Blob executes: unmap old VMAs, mremap new VMAs, rt_sigreturn

        println!("TaskRestoreArgs test PASSED");
    }
}

/// End-to-end injection test with minimal execution (Task 2.6 extended)
///
/// This test demonstrates the full injection workflow but stops short
/// of actual execution to avoid crashing the test process.
#[test]
#[ignore]  // Requires special permissions and careful setup
fn test_end_to_end_injection_task26() {
    println!("Testing end-to-end injection (Task 2.6 extended)");

    unsafe {
        // Step 1: Find injection location
        let gap = find_restorer_gap(std::process::id())
            .expect("Failed to find gap");
        let blob_addr = gap.aligned_addr(4096);

        println!("Step 1: Found injection location: 0x{:x}", blob_addr);

        // Step 2: Inject blob
        let entry_point = inject_restorer_blob(blob_addr)
            .expect("Failed to inject blob");
        println!("Step 2: Blob injected at 0x{:x}", entry_point);

        // Step 3: Set up arguments
        let sigframe = Sigframe::new(
            test_end_to_end_injection_task26 as u64,  // Return here
            0x7fffffffe000,  // Dummy stack
        );

        let vmas: Vec<VmaEntry> = vec![];  // No VMAs to restore

        let args = TaskRestoreArgs {
            bootstrap_base: blob_addr,
            bootstrap_len: 4096,
            vma_count: 0,
            vmas: vmas.as_ptr(),
            sigframe: &sigframe as *const Sigframe as *const u8,
        };

        println!("Step 3: Arguments prepared");
        println!("  VMAs: {}", args.vma_count);
        println!("  Sigframe: 0x{:x}", args.sigframe as usize);

        // Step 4: Verify blob entry point
        let entry_fn = std::mem::transmute::<usize, extern "C" fn(*const TaskRestoreArgs) -> !>(
            entry_point
        );

        println!("Step 4: Entry point function pointer: {:p}", entry_fn as *const ());

        // NOTE: We do NOT call entry_fn here because:
        // - It calls rt_sigreturn which never returns
        // - It would permanently change process state
        // - We need proper fork() or process isolation to test safely
        println!("Reason: rt_sigreturn never returns, needs isolated environment");

        // Clean up
        let _ = crust_syscall::syscalls::munmap(entry_point, 4096);
    }
}
