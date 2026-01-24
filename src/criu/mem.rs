use std::os::unix::io::RawFd;

use crate::criu::files::{files_collected, try_collect_special_file};
use crate::criu::image::{close_image, open_image};
use crate::criu::image_desc::CrFdType;
use crate::criu::kerndat::kdat;
use crate::criu::memfd::collect_memfd;
use crate::criu::pstree::{rsti_mut, vpid, vma_status, PidStore, VmaArea};
use crate::criu::protobuf::pb_read_one_eof;
use crate::criu::shmem::collect_shmem;
use crate::proto::{MmEntry, VmaEntry};

fn page_size() -> u64 {
    4096
}

fn vma_entry_is_private(e: &VmaEntry, task_size: u64) -> bool {
    use vma_status::*;

    let is_regular_private = (e.status & VMA_AREA_REGULAR) == VMA_AREA_REGULAR
        && ((e.status & VMA_ANON_PRIVATE) == VMA_ANON_PRIVATE
            || (e.status & VMA_FILE_PRIVATE) == VMA_FILE_PRIVATE)
        && e.end <= task_size;

    let is_shstk = (e.status & VMA_AREA_SHSTK) == VMA_AREA_SHSTK;
    let is_aioring = (e.status & VMA_AREA_AIORING) == VMA_AREA_AIORING;

    is_regular_private || is_shstk || is_aioring
}

fn vma_area_is_private(vma: &VmaArea, task_size: u64) -> bool {
    vma_entry_is_private(&vma.e, task_size)
}

fn vma_has_guard_gap_hidden(vma: &VmaArea) -> bool {
    kdat().stack_guard_gap_hidden && (vma.e.flags & libc::MAP_GROWSDOWN as u32) != 0
}

fn vma_area_is(vma: &VmaArea, status: u32) -> bool {
    (vma.e.status & status) == status
}

/// Maps to: collect_filemap (criu/files.c)
pub fn collect_filemap(vma: &mut VmaArea, _pid: i32) -> i32 {
    // Make a wild guess for the fdflags if not present
    if vma.e.fdflags.is_none() {
        let has_write = (vma.e.prot & libc::PROT_WRITE as u32) != 0;
        let is_file_shared = vma_area_is(vma, vma_status::VMA_FILE_SHARED);
        if has_write && is_file_shared {
            vma.e.fdflags = Some(libc::O_RDWR as u32);
        } else {
            vma.e.fdflags = Some(libc::O_RDONLY as u32);
        }
    }

    let is_memfd = vma_area_is(vma, vma_status::VMA_AREA_MEMFD);

    if is_memfd {
        if unsafe { collect_memfd(vma.e.shmid) }.is_null() {
            return -1;
        }
    } else {
        let desc = unsafe { try_collect_special_file(vma.e.shmid as u32, true) };
        if desc.is_null() {
            log::debug!("No file desc for filemap shmid {:#x}", vma.e.shmid);
        }
    }

    // vma.vmfd = fd;
    // vma.vm_open = open_filemap;
    0
}

pub fn prepare_mm_pid(store: &mut PidStore, item_idx: usize, dfd: RawFd) -> i32 {

    let pid = match store.get_item(item_idx) {
        Some(item) => vpid(item),
        None => return -1,
    };

    let mut mm_img = match open_image(dfd, CrFdType::Mm, &pid.to_string()) {
        Ok(img) => img,
        Err(_) => return -1,
    };

    let mm: MmEntry = match pb_read_one_eof(&mut mm_img) {
        Ok(Some(mm)) => mm,
        Ok(None) => {
            close_image(&mut mm_img);
            return 0;
        }
        Err(_) => {
            close_image(&mut mm_img);
            return -1;
        }
    };
    close_image(&mut mm_img);

    if files_collected() {
        let _ = unsafe { try_collect_special_file(mm.exe_file_id, true) };
    }

    log::debug!("Found {} VMAs in image", mm.vmas.len());

    let n_vmas = mm.vmas.len();
    let use_old_image = n_vmas == 0;

    // Old image. Read VMAs from vma-.img
    let mut vmas_img = if use_old_image {
        match open_image(dfd, CrFdType::Vmas, &pid.to_string()) {
            Ok(img) => Some(img),
            Err(_) => return -1,
        }
    } else {
        None
    };

    let task_size = kdat().task_size;
    let mut vn = 0;
    let mut vmas_collected: Vec<VmaArea> = Vec::new();
    let mut rst_priv_size: u64 = 0;

    loop {
        let should_break = if use_old_image {
            vmas_img.is_none()
        } else {
            vn >= n_vmas
        };

        if should_break {
            break;
        }

        let vma_entry: VmaEntry = if use_old_image {
            match pb_read_one_eof(vmas_img.as_mut().unwrap()) {
                Ok(Some(e)) => e,
                Ok(None) => {
                    if let Some(ref mut img) = vmas_img {
                        close_image(img);
                    }
                    vmas_img = None;
                    break;
                }
                Err(_) => {
                    if let Some(ref mut img) = vmas_img {
                        close_image(img);
                    }
                    return -1;
                }
            }
        } else {
            let e = mm.vmas[vn].clone();
            vn += 1;
            e
        };

        let mut vma = VmaArea::new(vma_entry);

        if vma_area_is_private(&vma, task_size) {
            rst_priv_size += vma.len();
            if vma_has_guard_gap_hidden(&vma) {
                rst_priv_size += page_size();
            }
        }

        log::info!("vma 0x{:x} 0x{:x}", vma.e.start, vma.e.end);

        if vma_area_is(&vma, vma_status::VMA_ANON_SHARED) {
            if unsafe { collect_shmem(pid, &mut vma) } < 0 {
                if let Some(ref mut img) = vmas_img {
                    close_image(img);
                }
                return -1;
            }
        } else if vma_area_is(&vma, vma_status::VMA_FILE_PRIVATE)
            || vma_area_is(&vma, vma_status::VMA_FILE_SHARED)
            || vma_area_is(&vma, vma_status::VMA_AREA_MEMFD)
        {
            if collect_filemap(&mut vma, pid) < 0 {
                if let Some(ref mut img) = vmas_img {
                    close_image(img);
                }
                return -1;
            }
        } else if vma_area_is(&vma, vma_status::VMA_AREA_SOCKET) {
            // collect_socket_map - stub for now
            log::debug!("Socket VMA at 0x{:x}", vma.e.start);
        }

        vmas_collected.push(vma);
    }

    if let Some(ref mut img) = vmas_img {
        close_image(img);
    }

    if let Some(item) = store.get_item_mut(item_idx) {
        if let Some(rsti) = rsti_mut(item) {
            rsti.mm = Some(Box::new(mm));
            rsti.vmas.nr = vmas_collected.len() as u32;
            rsti.vmas.rst_priv_size = rst_priv_size;
            rsti.vmas.entries = vmas_collected;
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vma_entry_is_private() {
        let mut e = VmaEntry {
            start: 0x1000,
            end: 0x2000,
            pgoff: 0,
            shmid: 0,
            prot: 0,
            flags: 0,
            status: vma_status::VMA_AREA_REGULAR | vma_status::VMA_ANON_PRIVATE,
            fd: -1,
            madv: None,
            fdflags: None,
        };

        assert!(vma_entry_is_private(&e, 0xFFFFFFFF));
        assert!(!vma_entry_is_private(&e, 0x1000)); // end > task_size

        e.status = vma_status::VMA_AREA_SHSTK;
        assert!(vma_entry_is_private(&e, 0xFFFFFFFF));

        e.status = vma_status::VMA_AREA_REGULAR | vma_status::VMA_ANON_SHARED;
        assert!(!vma_entry_is_private(&e, 0xFFFFFFFF));
    }
}
