//! On restore we need different types of memory allocation.
//! Here's an engine that tries to generalize them all. The
//! main difference is in how the buffer with objects is being
//! grown up.
//!
//! Buffers, that are to be used by restorer will be remapped
//! into restorer address space with rst_mem_remap() call. Thus
//! we have to either keep track of all the buffers and objects,
//! or keep objects one-by-one in a plain linear buffer. The
//! engine uses the 2nd approach.

use std::ptr;
use std::sync::Mutex;

use libc::{
    c_void, mmap, mremap, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, MAP_SHARED, MREMAP_FIXED,
    MREMAP_MAYMOVE, PROT_READ, PROT_WRITE,
};

#[cfg(test)]
use libc::munmap;

use crate::criu::util::page_size;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum RstMemType {
    /// Shared non-remapable allocations. These can happen only
    /// in "global" context, i.e. when objects are allocated to
    /// be used by any process to be restored. The objects are
    /// not going to be used in restorer blob, thus allocation
    /// engine grows buffers in a simple manner.
    Shared = 0,
    /// Shared objects, that are about to be used in restorer
    /// blob. For these the *_remap_* stuff below is used to get
    /// the actual pointer on any object. Growing a buffer is
    /// done with mremap, so that we don't have to keep track
    /// of all the buffer chunks and can remap them in restorer
    /// in one call.
    Shremap = 1,
    /// Privately used objects. Buffer grow and remap is the
    /// same as for SHREMAP, but memory regions are MAP_PRIVATE.
    Private = 2,
}

struct RstMemTypeState {
    remapable: bool,
    enabled: bool,
    free_bytes: usize,
    free_mem: *mut u8,
    last: usize,
    buf: *mut u8,
    size: usize,
}

// SAFETY: The pointers are only accessed through synchronized methods
unsafe impl Send for RstMemTypeState {}

impl RstMemTypeState {
    const fn new(remapable: bool, enabled: bool) -> Self {
        Self {
            remapable,
            enabled,
            free_bytes: 0,
            free_mem: ptr::null_mut(),
            last: 0,
            buf: ptr::null_mut(),
            size: 0,
        }
    }
}

struct RstMemState {
    types: [RstMemTypeState; 3],
}

impl RstMemState {
    const fn new() -> Self {
        Self {
            types: [
                RstMemTypeState::new(false, true), // RM_SHARED
                RstMemTypeState::new(true, true),  // RM_SHREMAP
                RstMemTypeState::new(true, false), // RM_PRIVATE
            ],
        }
    }
}

static RST_MEM: Mutex<RstMemState> = Mutex::new(RstMemState::new());

fn rst_mem_grow_size(need_size: usize) -> usize {
    let page = page_size();
    let rst_mem_batch = 2 * page;

    let need_size = (need_size + page - 1) & !(page - 1); // round_up to page
    if need_size < rst_mem_batch {
        rst_mem_batch
    } else {
        need_size
    }
}

fn grow_shared(t: &mut RstMemTypeState, size: usize) -> Result<(), i32> {
    let size = rst_mem_grow_size(size);

    // This buffer will not get remapped into
    // restorer, thus we can just forget the
    // previous chunk location and allocate a
    // new one
    let aux = unsafe {
        mmap(
            ptr::null_mut(),
            size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if aux == MAP_FAILED {
        return Err(-1);
    }

    t.free_mem = aux as *mut u8;
    t.free_bytes = size;
    t.last = 0;

    Ok(())
}

fn grow_remap(t: &mut RstMemTypeState, flag: i32, size: usize) -> Result<(), i32> {
    let size = rst_mem_grow_size(size);

    let aux = if t.buf.is_null() {
        // Can't call mremap with NULL address :(
        unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                flag | MAP_ANONYMOUS,
                -1,
                0,
            )
        }
    } else {
        if flag & MAP_SHARED != 0 {
            // Anon shared memory cannot grow with
            // mremap, anon-shmem file size doesn't
            // change and memory access generates
            // SIGBUS. We should truncate the guy,
            // but for now we don't need it.
            return Err(-1);
        }
        // We'll have to remap all objects into restorer
        // address space and get their new addresses. Since
        // we allocate many objects as one linear array, it's
        // simpler just to grow the buffer and let callers
        // find out new array addresses, rather than allocate
        // a completely new one and force callers use objects'
        // cpos-s.
        unsafe { mremap(t.buf as *mut c_void, t.size, t.size + size, MREMAP_MAYMOVE) }
    };

    if aux == MAP_FAILED {
        return Err(-1);
    }

    let aux = aux as *mut u8;

    if !t.buf.is_null() {
        let offset = unsafe { t.free_mem.offset_from(t.buf) };
        t.free_mem = unsafe { aux.offset(offset) };
    } else {
        t.free_mem = aux;
    }

    t.free_bytes += size;
    t.size += size;
    t.buf = aux;

    Ok(())
}

/// Allocate and free objects. We don't need to free arbitrary
/// object, thus allocation is simple (linear) and only the
/// last object can be freed (pop-ed from buffer).
pub fn rst_mem_alloc(size: usize, mem_type: RstMemType) -> *mut u8 {
    let mut state = RST_MEM.lock().unwrap();
    let t = &mut state.types[mem_type as usize];

    assert!(t.enabled, "rst_mem type {:?} not enabled", mem_type);

    if t.free_bytes < size {
        let result = match mem_type {
            RstMemType::Shared => grow_shared(t, size),
            RstMemType::Shremap => grow_remap(t, MAP_SHARED, size),
            RstMemType::Private => grow_remap(t, MAP_PRIVATE, size),
        };
        if result.is_err() {
            return ptr::null_mut();
        }
    }

    let ret = t.free_mem;
    t.free_mem = unsafe { t.free_mem.add(size) };
    t.free_bytes -= size;
    t.last = size;

    ret
}

/// Word-align the current freelist pointer for the next allocation. If we don't
/// align pointers, some futex and atomic operations can fail.
pub fn rst_mem_align(mem_type: RstMemType) {
    let mut state = RST_MEM.lock().unwrap();
    let t = &mut state.types[mem_type as usize];

    let ptr = t.free_mem as usize;
    let align = std::mem::size_of::<*mut c_void>();
    let aligned = (ptr + align - 1) & !(align - 1);
    let padding = aligned - ptr;

    if padding <= t.free_bytes {
        t.free_bytes -= padding;
        t.free_mem = aligned as *mut u8;
    }
}

/// Reports a cookie of a current shared buffer position, that
/// can later be used in rst_mem_remap_ptr() to find out the object
/// pointer in the restorer blob.
pub fn rst_mem_align_cpos(mem_type: RstMemType) -> usize {
    let mut state = RST_MEM.lock().unwrap();
    let t = &mut state.types[mem_type as usize];

    assert!(t.remapable, "rst_mem_align_cpos: type not remapable");
    assert!(t.enabled, "rst_mem_align_cpos: type not enabled");

    let ptr = t.free_mem as usize;
    let align = std::mem::size_of::<*mut c_void>();
    let aligned = (ptr + align - 1) & !(align - 1);
    let padding = aligned - ptr;

    if padding <= t.free_bytes {
        t.free_bytes -= padding;
        t.free_mem = aligned as *mut u8;
    }

    unsafe { t.free_mem.offset_from(t.buf) as usize }
}

pub fn rst_mem_remap_ptr(pos: usize, mem_type: RstMemType) -> *mut u8 {
    let state = RST_MEM.lock().unwrap();
    let t = &state.types[mem_type as usize];

    assert!(t.remapable, "rst_mem_remap_ptr: type not remapable");

    unsafe { t.buf.add(pos) }
}

pub fn rst_mem_free_last(mem_type: RstMemType) {
    let mut state = RST_MEM.lock().unwrap();
    let t = &mut state.types[mem_type as usize];

    assert!(t.enabled, "rst_mem_free_last: type not enabled");

    t.free_mem = unsafe { t.free_mem.sub(t.last) };
    t.free_bytes += t.last;
    t.last = 0; // next free_last would be no-op
}

/// Disables SHARED and SHREMAP allocations, turns on PRIVATE
pub fn rst_mem_switch_to_private() {
    let mut state = RST_MEM.lock().unwrap();
    state.types[RstMemType::Shared as usize].enabled = false;
    state.types[RstMemType::Shremap as usize].enabled = false;
    state.types[RstMemType::Private as usize].enabled = true;
}

/// Routines to remap SHREMAP and PRIVATE into restorer address space
pub fn rst_mem_lock() -> usize {
    let mut state = RST_MEM.lock().unwrap();
    // Don't allow further allocations from rst_mem since we're
    // going to get the bootstrap area and remap all the stuff
    // into it. The SHREMAP and SHARED should be already locked
    // in the rst_mem_switch_to_private().
    state.types[RstMemType::Private as usize].enabled = false;

    state.types[RstMemType::Private as usize].size + state.types[RstMemType::Shremap as usize].size
}

fn rst_mem_remap_one(t: &mut RstMemTypeState, to: *mut c_void) -> Result<(), i32> {
    assert!(!t.enabled, "rst_mem_remap_one: type still enabled");
    assert!(t.remapable, "rst_mem_remap_one: type not remapable");

    if t.buf.is_null() {
        // No allocations happened from this buffer.
        // It's safe just to do nothing.
        return Ok(());
    }

    let aux = unsafe {
        mremap(
            t.buf as *mut c_void,
            t.size,
            t.size,
            MREMAP_MAYMOVE | MREMAP_FIXED,
            to,
        )
    };

    if aux == MAP_FAILED {
        return Err(-1);
    }

    t.buf = aux as *mut u8;
    Ok(())
}

pub fn rst_mem_remap(to: *mut c_void) -> Result<(), i32> {
    let mut state = RST_MEM.lock().unwrap();

    rst_mem_remap_one(&mut state.types[RstMemType::Private as usize], to)?;

    let private_size = state.types[RstMemType::Private as usize].size;
    let shremap_to = unsafe { (to as *mut u8).add(private_size) as *mut c_void };

    rst_mem_remap_one(&mut state.types[RstMemType::Shremap as usize], shremap_to)?;

    Ok(())
}

pub fn shmalloc(bytes: usize) -> *mut u8 {
    rst_mem_align(RstMemType::Shared);
    rst_mem_alloc(bytes, RstMemType::Shared)
}

/// Only last chunk can be released
pub fn shfree_last(_ptr: *mut u8) {
    rst_mem_free_last(RstMemType::Shared);
}

#[cfg(test)]
pub fn rst_mem_reset() {
    let mut state = RST_MEM.lock().unwrap();

    for t in &mut state.types {
        if !t.buf.is_null() {
            unsafe {
                munmap(t.buf as *mut c_void, t.size);
            }
        }
        t.free_bytes = 0;
        t.free_mem = ptr::null_mut();
        t.last = 0;
        t.buf = ptr::null_mut();
        t.size = 0;
    }

    state.types[RstMemType::Shared as usize].enabled = true;
    state.types[RstMemType::Shremap as usize].enabled = true;
    state.types[RstMemType::Private as usize].enabled = false;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shmalloc_basic() {
        rst_mem_reset();

        let ptr1 = shmalloc(64);
        assert!(!ptr1.is_null());

        let ptr2 = shmalloc(128);
        assert!(!ptr2.is_null());
        assert!(ptr2 > ptr1);

        rst_mem_reset();
    }

    #[test]
    fn test_rst_mem_alloc_shremap() {
        rst_mem_reset();

        let ptr1 = rst_mem_alloc(64, RstMemType::Shremap);
        assert!(!ptr1.is_null());

        let pos = rst_mem_align_cpos(RstMemType::Shremap);
        let ptr2 = rst_mem_alloc(128, RstMemType::Shremap);
        assert!(!ptr2.is_null());

        let remap_ptr = rst_mem_remap_ptr(pos, RstMemType::Shremap);
        assert_eq!(remap_ptr, ptr2);

        rst_mem_reset();
    }

    #[test]
    fn test_rst_mem_free_last() {
        rst_mem_reset();

        let ptr1 = shmalloc(64);
        assert!(!ptr1.is_null());

        let ptr2 = shmalloc(128);
        assert!(!ptr2.is_null());

        shfree_last(ptr2);

        let ptr3 = shmalloc(64);
        assert!(!ptr3.is_null());

        rst_mem_reset();
    }

    #[test]
    fn test_rst_mem_switch_to_private() {
        rst_mem_reset();

        let ptr = shmalloc(64);
        assert!(!ptr.is_null());

        rst_mem_switch_to_private();

        let ptr = rst_mem_alloc(64, RstMemType::Private);
        assert!(!ptr.is_null());

        rst_mem_reset();
    }

    #[test]
    fn test_rst_mem_large_allocation() {
        rst_mem_reset();

        let large_size = page_size() * 3;
        let ptr = shmalloc(large_size);
        assert!(!ptr.is_null());

        rst_mem_reset();
    }

    #[test]
    fn test_rst_mem_alignment() {
        rst_mem_reset();

        let _ = shmalloc(7);

        let ptr = shmalloc(8);
        assert!(!ptr.is_null());
        assert_eq!(ptr as usize % std::mem::size_of::<*mut c_void>(), 0);

        rst_mem_reset();
    }
}
