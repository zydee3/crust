use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::Mutex;

use crate::criu::fdstore::{fdstore_add, fdstore_get, FdstoreDesc, Mutex as FdstoreMutex};
use crate::criu::image::{close_image, open_image};
use crate::criu::image_desc::CrFdType;
use crate::criu::protobuf::pb_read_one_eof;
use crate::criu::rst_malloc::shmalloc;
use crate::criu::servicefd::ServiceFdState;
use crate::criu::shmem::restore_memfd_shmem_content;
use crate::criu::util::{cr_fchown, cr_fchperm};
use crate::proto::MemfdInodeEntry;

pub const F_SEAL_SEAL: u32 = 0x0001;
pub const MFD_ALLOW_SEALING: u32 = 0x0002;
pub const MFD_HUGETLB: u32 = 0x0004;

const F_LINUX_SPECIFIC_BASE: i32 = 1024;
const F_ADD_SEALS: i32 = F_LINUX_SPECIFIC_BASE + 9;

struct SendSyncPtr<T>(*mut T);
unsafe impl<T> Send for SendSyncPtr<T> {}
unsafe impl<T> Sync for SendSyncPtr<T> {}

static MEMFD_INODES: Mutex<Vec<SendSyncPtr<MemfdRestoreInode>>> = Mutex::new(Vec::new());

pub struct MemfdRestoreInode {
    pub lock: FdstoreMutex,
    pub fdstore_id: i32,
    pub pending_seals: u32,
    pub mie: MemfdInodeEntry,
    pub was_opened_rw: bool,
}

impl MemfdRestoreInode {
    pub fn new(mie: MemfdInodeEntry) -> Self {
        Self {
            lock: FdstoreMutex::new(),
            fdstore_id: -1,
            pending_seals: 0,
            mie,
            was_opened_rw: false,
        }
    }
}

/// Maps to: collect_memfd (criu/memfd.c)
pub unsafe fn collect_memfd(id: u64) -> *mut crate::criu::files::FileDesc {
    use crate::criu::files::{fd_types, find_file_desc_raw};
    let desc = find_file_desc_raw(fd_types::MEMFD, id as u32);
    if desc.is_null() {
        log::error!("No entry for memfd {:#x}", id);
    }
    desc
}

fn collect_one_memfd_inode(mie: MemfdInodeEntry) -> i32 {
    let ptr = shmalloc(std::mem::size_of::<MemfdRestoreInode>()) as *mut MemfdRestoreInode;
    if ptr.is_null() {
        return -1;
    }

    unsafe {
        std::ptr::write(
            ptr,
            MemfdRestoreInode {
                lock: FdstoreMutex::new(),
                fdstore_id: -1,
                pending_seals: 0,
                mie,
                was_opened_rw: false,
            },
        );
        (*ptr).lock.init();
    }

    let mut inodes = MEMFD_INODES.lock().unwrap();
    inodes.push(SendSyncPtr(ptr));

    0
}

pub fn prepare_memfd_inodes(dfd: RawFd) -> i32 {
    let mut img = match open_image(dfd, CrFdType::MemfdInode, "") {
        Ok(img) => img,
        Err(_) => return -1,
    };

    log::info!("Collecting memfd inodes");

    loop {
        match pb_read_one_eof::<MemfdInodeEntry>(&mut img) {
            Ok(Some(mie)) => {
                if collect_one_memfd_inode(mie) < 0 {
                    close_image(&mut img);
                    return -1;
                }
            }
            Ok(None) => break,
            Err(e) => {
                log::error!("Failed to read memfd inode: {}", e);
                close_image(&mut img);
                return -1;
            }
        }
    }

    close_image(&mut img);
    log::debug!(" `- ... done");
    0
}

pub fn for_each_memfd_inode<F>(mut f: F) -> io::Result<()>
where
    F: FnMut(&mut MemfdRestoreInode) -> io::Result<()>,
{
    let inodes = MEMFD_INODES.lock().unwrap();
    for wrapped_ptr in inodes.iter() {
        let inode = unsafe { &mut *wrapped_ptr.0 };
        f(inode)?;
    }
    Ok(())
}

fn memfd_create(name: &str, flags: u32) -> io::Result<i32> {
    let c_name = CString::new(name).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "Invalid memfd name")
    })?;

    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c_name.as_ptr(),
            flags as libc::c_uint,
        )
    };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(fd as i32)
}

pub fn memfd_open_inode_nocache(
    inode: &mut MemfdRestoreInode,
    sfd_state: &ServiceFdState,
    fdstore_desc: &mut FdstoreDesc,
) -> io::Result<i32> {
    let mie = &inode.mie;
    let flags: u32;

    if mie.seals == F_SEAL_SEAL {
        inode.pending_seals = 0;
        flags = 0;
    } else {
        inode.pending_seals = mie.seals;
        flags = MFD_ALLOW_SEALING;
    }

    let final_flags = if let Some(hugetlb_flag) = mie.hugetlb_flag {
        flags | hugetlb_flag
    } else {
        flags
    };

    let fd = memfd_create(&mie.name, final_flags).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Can't create memfd:{}: {}", mie.name, e),
        )
    })?;

    let result = (|| -> io::Result<i32> {
        restore_memfd_shmem_content(fd, mie.shmid as u64, mie.size, sfd_state)?;

        if let Some(mode) = mie.mode {
            cr_fchperm(fd, mie.uid, mie.gid, mode).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "Can't set permissions {{ uid {} gid {} mode {:#o} }} of memfd:{}: {}",
                        mie.uid, mie.gid, mode, mie.name, e
                    ),
                )
            })?;
        } else {
            cr_fchown(fd, mie.uid, mie.gid).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "Can't set ownership {{ uid {} gid {} }} of memfd:{}: {}",
                        mie.uid, mie.gid, mie.name, e
                    ),
                )
            })?;
        }

        let fdstore_id = fdstore_add(sfd_state, fdstore_desc, fd).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to add fd to fdstore: {}", e),
            )
        })?;

        inode.fdstore_id = fdstore_id;
        Ok(fd)
    })();

    match result {
        Ok(ret_fd) => Ok(ret_fd),
        Err(e) => {
            unsafe { libc::close(fd) };
            Err(e)
        }
    }
}

pub fn memfd_open_inode(
    inode: &mut MemfdRestoreInode,
    sfd_state: &ServiceFdState,
    fdstore_desc: &mut FdstoreDesc,
) -> io::Result<i32> {
    if inode.fdstore_id != -1 {
        return fdstore_get(sfd_state, fdstore_desc, inode.fdstore_id).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to get fd from fdstore: {}", e),
            )
        });
    }

    inode.lock.lock();

    let fd = if inode.fdstore_id != -1 {
        fdstore_get(sfd_state, fdstore_desc, inode.fdstore_id).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to get fd from fdstore: {}", e),
            )
        })?
    } else {
        memfd_open_inode_nocache(inode, sfd_state, fdstore_desc)?
    };

    inode.lock.unlock();

    Ok(fd)
}

pub fn apply_memfd_seals(
    inodes: &mut [MemfdRestoreInode],
    sfd_state: &ServiceFdState,
    fdstore_desc: &mut FdstoreDesc,
) -> io::Result<()> {
    for inode in inodes.iter_mut() {
        if inode.pending_seals == 0 {
            continue;
        }

        let fd = memfd_open_inode(inode, sfd_state, fdstore_desc)?;

        let ret = unsafe { libc::fcntl(fd, F_ADD_SEALS, inode.pending_seals as libc::c_int) };

        unsafe { libc::close(fd) };

        if ret < 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Cannot apply seals on memfd: {}", io::Error::last_os_error()),
            ));
        }
    }

    Ok(())
}
