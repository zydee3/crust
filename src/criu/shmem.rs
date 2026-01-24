use std::io;
use std::ptr;

use crate::criu::list::{HlistHead, HlistNode};
use crate::criu::lock::Futex;
use crate::criu::pagemap::{PageRead, PAGE_SIZE, PR_SHMEM};
use crate::criu::pstree::{pid_rst_prio, vma_status, VmaArea};
use crate::criu::rst_malloc::shmalloc;
use crate::criu::servicefd::ServiceFdState;
use crate::offset_of;

const SHMEM_HASH_SIZE: usize = 32;
const SYSVIPC_SHMEM_PID: i32 = -1;

/// Shared memory info - allocated in shared memory via shmalloc.
/// Maps to: struct shmem_info (criu/shmem.c:52-101)
#[repr(C)]
pub struct ShmemInfo {
    pub h: HlistNode,
    pub shmid: u64,
    pub pid: i32,
    pub size: u64,
    pub fd: i32,
    pub lock: Futex,
    pub count: i32,
    pub self_count: i32,
}

impl ShmemInfo {
    /// Allocate and initialize a ShmemInfo in shared memory.
    pub unsafe fn alloc(shmid: u64, pid: i32, size: u64) -> *mut ShmemInfo {
        let ptr = shmalloc(std::mem::size_of::<ShmemInfo>()) as *mut ShmemInfo;
        if ptr.is_null() {
            return ptr::null_mut();
        }

        (*ptr).h = HlistNode::new();
        (*ptr).shmid = shmid;
        (*ptr).pid = pid;
        (*ptr).size = size;
        (*ptr).fd = -1;
        (*ptr).lock = Futex::new();
        (*ptr).count = 1;
        (*ptr).self_count = 1;

        ptr
    }
}

/// Hash table for shared memory lookups.
/// Maps to: shmems_hash (criu/shmem.c:46)
static mut SHMEMS_HASH: [HlistHead; SHMEM_HASH_SIZE] = {
    const EMPTY: HlistHead = HlistHead::new();
    [EMPTY; SHMEM_HASH_SIZE]
};

#[inline]
fn shmem_chain(shmid: u64) -> usize {
    (shmid as usize) % SHMEM_HASH_SIZE
}

/// Find shmem_info by shmid.
/// Maps to: shmem_find (criu/shmem.c:138-149)
pub unsafe fn shmem_find(shmid: u64) -> *mut ShmemInfo {
    let chain = shmem_chain(shmid);
    let mut node = SHMEMS_HASH[chain].first;

    while !node.is_null() {
        let si = crate::criu::list::list_entry(
            node as *mut crate::criu::list::ListHead,
            offset_of!(ShmemInfo, h),
        ) as *mut ShmemInfo;

        if (*si).shmid == shmid {
            return si;
        }
        node = (*node).next;
    }

    ptr::null_mut()
}

/// Add shmem_info to hash table.
/// Maps to: shmem_hash_add (criu/shmem.c:127-136)
unsafe fn shmem_hash_add(si: *mut ShmemInfo) {
    let chain = shmem_chain((*si).shmid);
    SHMEMS_HASH[chain].add_head(&mut (*si).h);
}

fn vma_entry_is(e: &crate::proto::VmaEntry, status: u32) -> bool {
    (e.status & status) == status
}

/// Collect shared memory for a VMA.
/// Maps to: collect_shmem (criu/shmem.c:427-497)
pub unsafe fn collect_shmem(pid: i32, vma: &mut VmaArea) -> i32 {
    let vi = &vma.e;
    let size = vi.pgoff + vi.end - vi.start;

    if vma_entry_is(vi, vma_status::VMA_AREA_SYSVIPC) {
        // vma.vm_open = open_shmem_sysv
        return 0;
    }

    // vma.vm_open = open_shmem

    let si = shmem_find(vi.shmid);

    if !si.is_null() {
        if (*si).pid == SYSVIPC_SHMEM_PID {
            log::error!("Shmem {:x} already collected as SYSVIPC", vi.shmid);
            return -1;
        }

        if (*si).size < size {
            (*si).size = size;
        }
        (*si).count += 1;

        /*
         * Only the shared mapping with a lowest
         * pid will be created in real, other processes
         * will wait until the kernel propagate this mapping
         * into /proc
         */
        if !pid_rst_prio(pid as u32, (*si).pid as u32) {
            if (*si).pid == pid {
                (*si).self_count += 1;
            }
            return 0;
        }

        (*si).pid = pid;
        (*si).self_count = 1;
        return 0;
    }

    let si = ShmemInfo::alloc(vi.shmid, pid, size);
    if si.is_null() {
        log::error!("Failed to allocate shmem_info");
        return -1;
    }

    log::info!(
        "Add new shmem 0x{:x} ({:#016x}-{:#016x})",
        vi.shmid,
        vi.start,
        vi.end
    );

    shmem_hash_add(si);
    0
}

fn round_up(x: u64, y: u64) -> u64 {
    ((x.wrapping_sub(1)) | (y - 1)).wrapping_add(1)
}

pub fn do_restore_shmem_content(
    addr: *mut u8,
    size: u64,
    shmid: u64,
    sfd_state: &ServiceFdState,
) -> io::Result<i32> {
    let mut pr = PageRead::new();

    let ret = crate::criu::pagemap::open_page_read(
        shmid,
        &mut pr,
        PR_SHMEM,
        sfd_state,
        false,
        false,
        false,
    )?;

    if !ret {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Failed to open page read for shmid {}", shmid),
        ));
    }

    let result = restore_shmem_pages(&mut pr, addr, size);

    pr.close();

    result
}

fn restore_shmem_pages(pr: &mut PageRead, addr: *mut u8, size: u64) -> io::Result<i32> {
    loop {
        let ret = pr.advance();
        if ret <= 0 {
            return Ok(ret);
        }

        let (vaddr, nr_pages) = {
            let pe = pr.pe.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "pe is None after advance")
            })?;
            (pe.vaddr, pe.nr_pages.unwrap_or(0))
        };

        if vaddr + nr_pages * PAGE_SIZE as u64 > size {
            break;
        }

        let dest = unsafe { addr.add(vaddr as usize) };
        pr.read_pages(vaddr, nr_pages, dest, 0)?;
    }

    Ok(0)
}

pub fn restore_memfd_shmem_content(
    fd: i32,
    shmid: u64,
    size: u64,
    sfd_state: &ServiceFdState,
) -> io::Result<i32> {
    if size == 0 {
        return Ok(0);
    }

    // Resize the memfd
    let ret = unsafe { libc::ftruncate(fd, size as libc::off_t) };
    if ret < 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Can't resize shmem 0x{:x} size={}: {}",
                shmid,
                size,
                io::Error::last_os_error()
            ),
        ));
    }

    // Map the memfd
    let addr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size as libc::size_t,
            libc::PROT_WRITE | libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };

    if addr == libc::MAP_FAILED {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Can't mmap shmem 0x{:x} size={}: {}",
                shmid,
                size,
                io::Error::last_os_error()
            ),
        ));
    }

    // Restore content - PAGE_SIZE aligned
    let aligned_size = round_up(size, PAGE_SIZE as u64);
    let result = do_restore_shmem_content(addr as *mut u8, aligned_size, shmid, sfd_state);

    // Cleanup
    unsafe {
        libc::munmap(addr, size as libc::size_t);
    }

    result
}
