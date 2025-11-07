# crust-restorer

Position-independent restorer blob for CRIU restore in Rust.

## Overview

This crate builds a minimal no_std, no_main PIE (Position Independent Executable) blob that executes inside the target process to perform operations impossible from outside:

- **rt_sigreturn** - Atomically restore CPU state and jump to original RIP
- **CLONE_THREAD** - Create threads (must be called from parent thread)
- **prctl operations** - Set memory map metadata, process name, etc.

## Design

**Approach:** Inline-only (Option 1 from [restorer_blob_design.md](../docs/restorer_blob_design.md))

- All functions use `#[inline(always)]`
- Direct syscalls via inline asm (no libc)
- Aggressive LTO and optimization
- **Result: Zero relocations** - no runtime relocation handling needed

## Building

```bash
# From project root
make restorer

# Or as part of release build
make release
```

This generates:
- `restorer.elf` - PIE executable (13KB, for inspection)
- `restorer_blob.bin` - Raw machine code (158 bytes)
- `../src/restorer_blob.rs` - Rust const array

## Build Process

All build logic is in the root Makefile:

1. **Compile**: `cargo build -p crust-restorer --release` → `libcrust_restorer.a`
2. **Link**: `ld -pie` → `restorer.elf` (PIE executable)
3. **Extract**: `objcopy -O binary --only-section=.text` → `restorer_blob.bin`
4. **Generate**: `xxd -i` → `../src/restorer_blob.rs` (Rust byte array)

## Validation

The Makefile checks for relocations:

```bash
readelf -r restorer.elf | grep "\.text"
# Expected: Zero relocations in .text section
```

**Current status:**
- ✅ Zero relocations in .text
- ✅ Blob size: 158 bytes
- ✅ Contains direct syscalls
- ✅ rt_sigreturn at end

## Structure

```rust
pub struct TaskRestoreArgs {
    pub bootstrap_base: usize,
    pub bootstrap_len: usize,
    pub vma_count: usize,
    pub vmas: *const VmaEntry,
    pub sigframe: *const u8,
}

#[no_mangle]
pub extern "C" fn _start(args: *const TaskRestoreArgs) -> ! {
    unmap_old_vmas(args);
    restore_vmas(args);
    restore_cpu_state(args);  // rt_sigreturn - never returns
}
```

## Code Size

- Source: 135 lines
- Compiled: 158 bytes
- All code inlined, no function calls

## Dependencies

- **crust-syscall** - Raw syscall wrappers (no_std compatible)
- **compiler_builtins** - Compiler intrinsics (automatically linked)

## References

- [criu_restore_context.md](../docs/criu_restore_context.md) - CRIU restore mechanisms
- [restorer_blob_design.md](../docs/restorer_blob_design.md) - Design options evaluated
