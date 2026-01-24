use libc::iovec;
use std::io;
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::criu::image::{close_image, img_raw_size, open_image_at, open_pages_image_at, open_parent, CrImg};
use crate::criu::image_desc::CrFdType;
use crate::criu::protobuf::pb_read_one_eof;
use crate::criu::servicefd::{ServiceFdState, SfdType};
use crate::proto::PagemapEntry;

pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const MAX_BUNCH_SIZE: usize = 256;

pub const PE_PARENT: u32 = 1 << 0;
pub const PE_PRESENT: u32 = 1 << 2;

pub const PR_SHMEM: i32 = 0x1;
pub const PR_TASK: i32 = 0x2;
pub const PR_MOD: i32 = 0x4;
pub const PR_REMOTE: i32 = 0x8;
pub const PR_TYPE_MASK: i32 = PR_SHMEM | PR_TASK;

const PAGEMAP_ENTRY_SIZE_ESTIMATE: usize = 16;

static PAGE_READ_IDS: AtomicU32 = AtomicU32::new(1);

#[inline]
pub fn can_extend_bunch(bunch: &iovec, off: usize, len: usize) -> bool {
    let bunch_end = bunch.iov_base as usize + bunch.iov_len;
    let max_len = MAX_BUNCH_SIZE * PAGE_SIZE;

    // The next region is the continuation of the existing
    bunch_end == off &&
    // The resulting region is non empty and is small enough
    (bunch.iov_len == 0 || bunch.iov_len + len < max_len)
}

pub struct PageRead {
    pub pieok: bool,
    pub disable_dedup: bool,

    pub pmi: Option<CrImg>,
    pub pi: Option<CrImg>,
    pub pages_img_id: u32,

    pub pe: Option<PagemapEntry>,
    pub parent: Option<Box<PageRead>>,
    pub cvaddr: u64,
    pub pi_off: libc::off_t,

    pub bunch: iovec,
    pub id: u32,
    pub img_id: u64,

    pub pmes: Vec<PagemapEntry>,
    pub nr_pmes: i32,
    pub curr_pme: i32,
}

impl PageRead {
    pub fn new() -> Self {
        PageRead {
            pieok: false,
            disable_dedup: false,
            pmi: None,
            pi: None,
            pages_img_id: 0,
            pe: None,
            parent: None,
            cvaddr: 0,
            pi_off: 0,
            bunch: iovec { iov_base: ptr::null_mut(), iov_len: 0 },
            id: 0,
            img_id: 0,
            pmes: Vec::new(),
            nr_pmes: 0,
            curr_pme: 0,
        }
    }
}

impl Default for PageRead {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
pub fn pagemap_in_parent(pe: &PagemapEntry) -> bool {
    (pe.flags.unwrap_or(0) & PE_PARENT) != 0
}

#[inline]
pub fn pagemap_present(pe: &PagemapEntry) -> bool {
    (pe.flags.unwrap_or(0) & PE_PRESENT) != 0
}

#[inline]
pub fn pagemap_len(pe: &PagemapEntry) -> u64 {
    pe.nr_pages.unwrap_or(0) * PAGE_SIZE as u64
}

impl PageRead {
    pub fn advance(&mut self) -> i32 {
        self.curr_pme += 1;
        if self.curr_pme >= self.nr_pmes {
            return 0;
        }

        self.pe = Some(self.pmes[self.curr_pme as usize].clone());
        if let Some(ref pe) = self.pe {
            self.cvaddr = pe.vaddr;
        }

        1
    }

    fn skip_pagemap_pages(&mut self, len: u64) {
        if len == 0 {
            return;
        }

        if let Some(ref pe) = self.pe {
            if pagemap_present(pe) {
                self.pi_off += len as libc::off_t;
            }
        }
        self.cvaddr += len;
    }

    pub fn seek_pagemap(&mut self, vaddr: u64) -> i32 {
        if self.pe.is_none() {
            if self.advance() == 0 {
                return 0;
            }
        }

        loop {
            let (start, end) = {
                let pe = match &self.pe {
                    Some(pe) => pe,
                    None => return 0,
                };
                let start = pe.vaddr;
                let end = start + pagemap_len(pe);
                (start, end)
            };

            if vaddr < self.cvaddr {
                break;
            }

            if vaddr >= start && vaddr < end {
                self.skip_pagemap_pages(vaddr - self.cvaddr);
                return 1;
            }

            if end <= vaddr {
                self.skip_pagemap_pages(end - self.cvaddr);
            }

            if self.advance() == 0 {
                break;
            }
        }

        0
    }

    fn read_local_page(&mut self, _vaddr: u64, len: u64, buf: *mut u8) -> io::Result<()> {
        let pi = self.pi.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "pi is None")
        })?;

        let fd = pi.raw_fd();
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid pages image fd",
            ));
        }

        let mut curr: usize = 0;
        let len = len as usize;

        while curr < len {
            let ret = unsafe {
                libc::pread(
                    fd,
                    buf.add(curr) as *mut libc::c_void,
                    len - curr,
                    self.pi_off + curr as libc::off_t,
                )
            };
            if ret < 1 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Can't read mapping page: {}", ret),
                ));
            }
            curr += ret as usize;
        }

        Ok(())
    }

    fn read_parent_page(&mut self, mut vaddr: u64, mut nr: u64, mut buf: *mut u8) -> io::Result<()> {
        let parent = self.parent.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "No parent for snapshot pagemap")
        })?;

        while nr > 0 {
            let ret = parent.seek_pagemap(vaddr);
            if ret <= 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Missing {:x} in parent pagemap", vaddr),
                ));
            }

            let pe = parent.pe.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Parent pe is None")
            })?;
            let pe_nr_pages = pe.nr_pages.unwrap_or(0);
            let pe_vaddr = pe.vaddr;

            let mut p_nr = pe_nr_pages - (vaddr - pe_vaddr) / PAGE_SIZE as u64;
            if p_nr > nr {
                p_nr = nr;
            }

            parent.read_pages(vaddr, p_nr, buf, 0)?;

            nr -= p_nr;
            vaddr += p_nr * PAGE_SIZE as u64;
            buf = unsafe { buf.add((p_nr * PAGE_SIZE as u64) as usize) };
        }

        Ok(())
    }

    pub fn read_pages(&mut self, vaddr: u64, nr: u64, buf: *mut u8, _flags: u32) -> io::Result<()> {
        let len = nr * PAGE_SIZE as u64;

        let in_parent = {
            let pe = self.pe.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "pe is None")
            })?;
            pagemap_in_parent(pe)
        };

        if in_parent {
            self.read_parent_page(vaddr, nr, buf)?;
        } else {
            self.read_local_page(vaddr, len, buf)?;
            self.pi_off += len as libc::off_t;
        }

        self.cvaddr += len;

        Ok(())
    }

    pub fn close(&mut self) {
        close_page_read(self);
    }
}

pub fn free_pagemaps(pr: &mut PageRead) {
    pr.pmes.clear();
    pr.nr_pmes = 0;
}

pub fn init_compat_pagemap_entry(pe: &mut PagemapEntry) {
    // pagemap image generated with older version will either contain a hole
    // because the pages are in the parent snapshot or a pagemap that should
    // be marked with PE_PRESENT
    if pe.in_parent == Some(true) {
        let flags = pe.flags.unwrap_or(0);
        pe.flags = Some(flags | PE_PARENT);
    } else if pe.flags.is_none() {
        pe.flags = Some(PE_PRESENT);
    }

    if pe.nr_pages.is_none() {
        pe.nr_pages = Some(pe.compat_nr_pages as u64);
    }
}

pub fn punch_hole(pr: &mut PageRead, off: usize, len: usize, cleanup: bool) -> i32 {
    let bunch = &mut pr.bunch;

    if !cleanup && can_extend_bunch(bunch, off, len) {
        bunch.iov_len += len;
    } else {
        if bunch.iov_len > 0 {
            let pi = match &pr.pi {
                Some(pi) => pi,
                None => return -1,
            };
            let ret = unsafe {
                libc::fallocate(
                    pi.raw_fd(),
                    libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    bunch.iov_base as libc::off_t,
                    bunch.iov_len as libc::off_t,
                )
            };
            if ret != 0 {
                return -1;
            }
        }
        bunch.iov_base = off as *mut libc::c_void;
        bunch.iov_len = len;
    }
    0
}

pub fn close_page_read(pr: &mut PageRead) {
    if pr.bunch.iov_len > 0 {
        let ret = punch_hole(pr, 0, 0, true);
        if ret == -1 {
            return;
        }
        pr.bunch.iov_len = 0;
    }

    if let Some(ref mut parent) = pr.parent.take() {
        close_page_read(parent);
    }

    if let Some(ref mut pmi) = pr.pmi {
        close_image(pmi);
    }
    pr.pmi = None;

    if let Some(ref mut pi) = pr.pi {
        close_image(pi);
    }
    pr.pi = None;

    if !pr.pmes.is_empty() {
        free_pagemaps(pr);
    }
}

pub fn init_pagemaps(pr: &mut PageRead, streaming: bool) -> io::Result<()> {
    let fsize = if streaming {
        // TODO - There is no easy way to estimate the size of the pagemap that
        // is still to be read from the pipe. Possible solution is to ask the
        // image streamer for the size of the image. 1024 is a wild guess (more
        // space is allocated if needed).
        1024
    } else {
        let pmi = pr.pmi.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "pmi is None")
        })?;
        img_raw_size(pmi)? as usize
    };

    let nr_pmes = fsize / PAGEMAP_ENTRY_SIZE_ESTIMATE + 1;
    pr.pmes = Vec::with_capacity(nr_pmes);
    pr.nr_pmes = 0;
    pr.curr_pme = -1;

    let pmi = pr.pmi.as_mut().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "pmi is None")
    })?;

    loop {
        let entry: Option<PagemapEntry> = pb_read_one_eof(pmi)?;
        match entry {
            None => break,
            Some(mut pe) => {
                init_compat_pagemap_entry(&mut pe);
                pr.pmes.push(pe);
                pr.nr_pmes += 1;
            }
        }
    }

    if let Some(ref mut pmi) = pr.pmi {
        close_image(pmi);
    }
    pr.pmi = None;

    Ok(())
}

pub fn try_open_parent(
    dfd: RawFd,
    id: u64,
    pr: &mut PageRead,
    pr_flags: i32,
    streaming: bool,
    open_page_read_fn: fn(RawFd, u64, &mut PageRead, i32, bool) -> io::Result<bool>,
) -> io::Result<()> {
    // Image streaming lacks support for incremental images
    if streaming {
        pr.parent = None;
        return Ok(());
    }

    let pfd = match open_parent(dfd)? {
        Some(fd) => fd,
        None => {
            pr.parent = None;
            return Ok(());
        }
    };

    let mut parent = Box::new(PageRead::new());

    match open_page_read_fn(pfd, id, &mut parent, pr_flags, streaming) {
        Ok(found) => {
            unsafe { libc::close(pfd) };
            if found {
                pr.parent = Some(parent);
            } else {
                pr.parent = None;
            }
            Ok(())
        }
        Err(e) => {
            unsafe { libc::close(pfd) };
            Err(e)
        }
    }
}

pub fn open_page_read_at(
    dfd: RawFd,
    img_id: u64,
    pr: &mut PageRead,
    pr_flags: i32,
    auto_dedup: bool,
    streaming: bool,
    lazy_pages: bool,
) -> io::Result<bool> {
    let remote = (pr_flags & PR_REMOTE) != 0;

    // Only the top-most page-read can be remote, all the others are always local.
    let mut pr_flags = pr_flags & !PR_REMOTE;

    if auto_dedup {
        pr_flags |= PR_MOD;
    }

    let flags = if (pr_flags & PR_MOD) != 0 {
        (libc::O_RDWR) as u32
    } else {
        libc::O_RDONLY as u32
    };

    let fd_type = match pr_flags & PR_TYPE_MASK {
        PR_TASK => CrFdType::Pagemap,
        PR_SHMEM => CrFdType::ShmemPagemap,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid page read type",
            ));
        }
    };

    pr.pe = None;
    pr.parent = None;
    pr.cvaddr = 0;
    pr.pi_off = 0;
    pr.bunch.iov_len = 0;
    pr.bunch.iov_base = ptr::null_mut();
    pr.pmes.clear();
    pr.pieok = false;
    pr.disable_dedup = false;

    let path = match fd_type {
        CrFdType::Pagemap => format!("pagemap-{}.img", img_id),
        CrFdType::ShmemPagemap => format!("pagemap-shmem-{}.img", img_id),
        _ => unreachable!(),
    };

    let pmi = open_image_at(dfd, fd_type, libc::O_RDONLY as u32, &path)?;

    if pmi.is_empty() {
        return Ok(false);
    }

    pr.pmi = Some(pmi);

    if let Err(e) = try_open_parent(dfd, img_id, pr, pr_flags, streaming, open_page_read_at_recursive) {
        if let Some(ref mut pmi) = pr.pmi {
            close_image(pmi);
        }
        pr.pmi = None;
        return Err(e);
    }

    let pmi = pr.pmi.as_mut().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "pmi is None after try_open_parent")
    })?;

    let (pi, pages_img_id) = match open_pages_image_at(dfd, flags, pmi, dfd, 0) {
        Ok(result) => result,
        Err(e) => {
            close_page_read(pr);
            return Err(e);
        }
    };

    pr.pi = Some(pi);
    pr.pages_img_id = pages_img_id;

    if let Err(e) = init_pagemaps(pr, streaming) {
        close_page_read(pr);
        return Err(e);
    }

    pr.id = PAGE_READ_IDS.fetch_add(1, Ordering::SeqCst);
    pr.img_id = img_id;

    if !remote && !streaming && pr.parent.is_none() && !lazy_pages {
        pr.pieok = true;
    }

    Ok(true)
}

fn open_page_read_at_recursive(
    dfd: RawFd,
    img_id: u64,
    pr: &mut PageRead,
    pr_flags: i32,
    streaming: bool,
) -> io::Result<bool> {
    open_page_read_at(dfd, img_id, pr, pr_flags, false, streaming, false)
}

pub fn open_page_read(
    img_id: u64,
    pr: &mut PageRead,
    pr_flags: i32,
    sfd_state: &ServiceFdState,
    auto_dedup: bool,
    streaming: bool,
    lazy_pages: bool,
) -> io::Result<bool> {
    let dfd = sfd_state.get_service_fd(SfdType::ImgFdOff);
    if dfd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Image service fd not available",
        ));
    }
    open_page_read_at(dfd, img_id, pr, pr_flags, auto_dedup, streaming, lazy_pages)
}
