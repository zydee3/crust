use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::criu::fdstore::{fdstore_add, FdstoreDesc};
use crate::criu::image::{close_image, open_image};
use crate::criu::image_desc::CrFdType;
use crate::criu::list::{HlistNode, ListHead};
use crate::criu::options::opts;
use crate::criu::pidfd::init_dead_pidfd_hash;
use crate::criu::protobuf::pb_read_one_eof;
use crate::criu::rst_malloc::shmalloc;
use crate::criu::servicefd::ServiceFdState;
use crate::criu::sk_unix::init_sk_info_hash;
use crate::proto::FileEntry;

const FDESC_HASH_SIZE: usize = 64;

pub mod fd_types {
    pub const UND: i32 = 0;
    pub const REG: i32 = 1;
    pub const PIPE: i32 = 2;
    pub const FIFO: i32 = 3;
    pub const INETSK: i32 = 4;
    pub const UNIXSK: i32 = 5;
    pub const EVENTFD: i32 = 6;
    pub const EVENTPOLL: i32 = 7;
    pub const INOTIFY: i32 = 8;
    pub const SIGNALFD: i32 = 9;
    pub const PACKETSK: i32 = 10;
    pub const TTY: i32 = 11;
    pub const FANOTIFY: i32 = 12;
    pub const NETLINKSK: i32 = 13;
    pub const NS: i32 = 14;
    pub const TUNF: i32 = 15;
    pub const EXT: i32 = 16;
    pub const TIMERFD: i32 = 17;
    pub const MEMFD: i32 = 18;
    pub const BPFMAP: i32 = 19;
    pub const PIDFD: i32 = 20;
    pub const CTL_TTY: i32 = 65534;
    pub const AUTOFS_PIPE: i32 = 65535;
}

static INHERIT_FD_IDS: OnceLock<Mutex<HashMap<String, i32>>> = OnceLock::new();

fn get_inherit_fd_ids() -> &'static Mutex<HashMap<String, i32>> {
    INHERIT_FD_IDS.get_or_init(|| Mutex::new(HashMap::new()))
}

static FILES_COLLECTED: AtomicBool = AtomicBool::new(false);

/// File descriptor operations - contains type and callbacks.
/// Maps to: struct file_desc_ops (criu/include/files.h)
#[repr(C)]
pub struct FileDescOps {
    pub fd_type: i32,
}

impl FileDescOps {
    pub fn new(fd_type: i32) -> Self {
        Self { fd_type }
    }
}

/// File descriptor info - allocated in shared memory.
/// Maps to: struct file_desc (criu/include/files.h:56-63)
#[repr(C)]
pub struct FileDesc {
    pub id: u32,
    pub ops: *const FileDescOps,
    pub fd_info_head: ListHead,
    pub hash: HlistNode,
}

impl FileDesc {
    /// Create an uninitialized file descriptor.
    /// MUST be allocated via shmalloc and initialized before use.
    pub unsafe fn init(ptr: *mut FileDesc, id: u32, ops: *const FileDescOps) {
        (*ptr).id = id;
        (*ptr).ops = ops;
        (*ptr).fd_info_head.init();
        // hash node initialized when added to hash table
        (*ptr).hash = HlistNode::new();
    }
}

use crate::criu::list::HlistHead;
use crate::offset_of;

/// Hash table for file descriptors.
/// Maps to: file_desc_hash (criu/files.c)
struct FileDescHash {
    buckets: [HlistHead; FDESC_HASH_SIZE],
}

impl FileDescHash {
    const fn new() -> Self {
        const EMPTY: HlistHead = HlistHead::new();
        Self {
            buckets: [EMPTY; FDESC_HASH_SIZE],
        }
    }

    fn bucket(&self, id: u32) -> usize {
        (id as usize) % FDESC_HASH_SIZE
    }

    unsafe fn add(&mut self, desc: *mut FileDesc) {
        let bucket = self.bucket((*desc).id);
        self.buckets[bucket].add_head(&mut (*desc).hash);
    }

    unsafe fn find(&self, id: u32) -> *mut FileDesc {
        let bucket = self.bucket(id);
        let mut node = self.buckets[bucket].first;
        while !node.is_null() {
            let desc = crate::criu::list::list_entry(
                node as *mut ListHead,
                offset_of!(FileDesc, hash),
            ) as *mut FileDesc;
            if (*desc).id == id {
                return desc;
            }
            node = (*node).next;
        }
        ptr::null_mut()
    }

    unsafe fn find_by_type(&self, fd_type: i32, id: u32) -> *mut FileDesc {
        let bucket = self.bucket(id);
        let mut node = self.buckets[bucket].first;
        while !node.is_null() {
            let desc = crate::criu::list::list_entry(
                node as *mut ListHead,
                offset_of!(FileDesc, hash),
            ) as *mut FileDesc;
            if (*desc).id == id {
                let ops = (*desc).ops;
                if fd_type == fd_types::UND || (!ops.is_null() && (*ops).fd_type == fd_type) {
                    return desc;
                }
            }
            node = (*node).next;
        }
        ptr::null_mut()
    }
}

static mut FILE_DESC_HASH: FileDescHash = FileDescHash::new();

pub fn init_fdesc_hash() {
    // Hash table is const-initialized, nothing to do
}

/// Add a file descriptor to the hash table.
/// Maps to: file_desc_add (criu/files.c)
pub unsafe fn file_desc_add(desc: *mut FileDesc) {
    FILE_DESC_HASH.add(desc);
}

/// Find a file descriptor by ID.
pub unsafe fn file_desc_find(id: u32) -> *mut FileDesc {
    FILE_DESC_HASH.find(id)
}

/*
 * Warning -- old CRIU might generate matching IDs
 * for different file types! So any code that uses
 * FD_TYPES__UND for fdesc search MUST make sure it's
 * dealing with the merged files images where all
 * descs are forced to have different IDs.
 */
/// Maps to: find_file_desc_raw (criu/files.c:685-698)
pub unsafe fn find_file_desc_raw(fd_type: i32, id: u32) -> *mut FileDesc {
    FILE_DESC_HASH.find_by_type(fd_type, id)
}

/// Maps to: find_file_desc (criu/files.c:700-703)
pub unsafe fn find_file_desc(fe_type: i32, fe_id: u32) -> *mut FileDesc {
    find_file_desc_raw(fe_type, fe_id)
}

/*
 * Files dumped for vmas/exe links can have remaps
 * configured. Need to bump-up users for them, otherwise
 * the open_path() would unlink the remap file after
 * the very first open.
 */
/// Maps to: try_collect_special_file (criu/files-reg.c:266-274)
pub unsafe fn try_collect_special_file(id: u32, optional: bool) -> *mut FileDesc {
    let desc = find_file_desc_raw(fd_types::REG, id);
    if desc.is_null() && !optional {
        log::error!("No entry for reg-file-ID {:#x}", id);
    }
    desc
}

/// Maps to: collect_special_file macro (criu/include/files-reg.h)
pub unsafe fn collect_special_file(id: u32) -> *mut FileDesc {
    try_collect_special_file(id, false)
}

/// FLE stage during restore.
/// Maps to: stage field bits in fdinfo_list_entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FleStage {
    Initialized = 0,
    Open = 1,
    Received = 2,
}

/// File descriptor info list entry - allocated in shared memory.
/// Maps to: struct fdinfo_list_entry (criu/include/files.h:83-93)
#[repr(C)]
pub struct FdinfoListEntry {
    pub desc_list: ListHead,
    pub desc: *mut FileDesc,
    pub ps_list: ListHead,
    pub task: *mut crate::criu::pstree::PstreeItem,
    pub fe: *mut FdinfoEntry,
    pub pid: i32,
    pub received: bool,
    pub stage: FleStage,
    pub fake: bool,
}

impl FdinfoListEntry {
    /// Allocate and initialize an FLE in shared memory.
    /// Maps to: alloc_fle (criu/files.c:793-810)
    pub unsafe fn alloc(pid: i32, fe: FdinfoEntry) -> *mut FdinfoListEntry {
        let fle_size = std::mem::size_of::<FdinfoListEntry>();
        let fe_size = std::mem::size_of::<FdinfoEntry>();

        let fle_ptr = shmalloc(fle_size) as *mut FdinfoListEntry;
        if fle_ptr.is_null() {
            return ptr::null_mut();
        }

        let fe_ptr = shmalloc(fe_size) as *mut FdinfoEntry;
        if fe_ptr.is_null() {
            return ptr::null_mut();
        }
        ptr::write(fe_ptr, fe);

        (*fle_ptr).desc_list.init();
        (*fle_ptr).ps_list.init();
        (*fle_ptr).desc = ptr::null_mut();
        (*fle_ptr).task = ptr::null_mut();
        (*fle_ptr).fe = fe_ptr;
        (*fle_ptr).pid = pid;
        (*fle_ptr).received = false;
        (*fle_ptr).stage = FleStage::Initialized;
        (*fle_ptr).fake = false;

        fle_ptr
    }
}

/// Add FLE to file descriptor's list.
/// Maps to: collect_desc_fle (criu/files.c:812-850)
unsafe fn collect_desc_fle(fle: *mut FdinfoListEntry, desc: *mut FileDesc, _force_master: bool) {
    (*fle).desc = desc;
    (*desc).fd_info_head.add_tail(&mut (*fle).desc_list);
    log::debug!(
        "collect_desc_fle: fd={} id={:#x}",
        (*(*fle).fe).fd,
        (*(*fle).fe).id
    );
}

/// Add FLE to task's fd list.
/// Maps to: collect_task_fd (criu/files.c:852-859)
unsafe fn collect_task_fd(fle: *mut FdinfoListEntry, task: *mut crate::criu::pstree::PstreeItem) {
    (*fle).task = task;
    log::debug!("collect_task_fd: fd={}", (*(*fle).fe).fd);
}

/// Allocate and collect an FLE.
/// Maps to: collect_fd (criu/files.c:861-898)
pub unsafe fn collect_fd_to(
    pid: i32,
    e: FdinfoEntry,
    desc: *mut FileDesc,
    task: *mut crate::criu::pstree::PstreeItem,
    fake: bool,
    force_master: bool,
) -> *mut FdinfoListEntry {
    let fle = FdinfoListEntry::alloc(pid, e);
    if fle.is_null() {
        return ptr::null_mut();
    }

    (*fle).fake = fake;

    if !desc.is_null() {
        collect_desc_fle(fle, desc, force_master);
    }
    if !task.is_null() {
        collect_task_fd(fle, task);
    }

    fle
}

/// Collect file descriptor info.
/// Maps to: collect_fd (criu/files.c:861-898)
pub unsafe fn collect_fd(
    pid: i32,
    e: &FdinfoEntry,
    task: *mut crate::criu::pstree::PstreeItem,
    fake: bool,
) -> i32 {
    log::info!("Collect fdinfo pid={} fd={} id={:#x}", pid, e.fd, e.id);

    let desc = find_file_desc(e.r#type, e.id);
    if desc.is_null() {
        log::error!("No file for fd {} id {:#x}", e.fd, e.id);
        return -1;
    }

    let fle = collect_fd_to(pid, e.clone(), desc, task, fake, false);
    if fle.is_null() {
        return -1;
    }

    0
}

pub fn inherit_fd_lookup_id(id: &str) -> i32 {
    for inh in &opts().inherit_fds {
        if inh.inh_id == id {
            log::info!("Found id {} (fd {}) in inherit fd list", id, inh.inh_fd);
            return inh.inh_fd;
        }
    }
    -1
}

pub fn inherit_fd_lookup_fdstore_id(id: &str) -> i32 {
    let map = get_inherit_fd_ids().lock().unwrap();
    map.get(id).copied().unwrap_or(-1)
}

pub fn inherit_fd_move_to_fdstore(
    sfd_state: &ServiceFdState,
    fdstore_desc: &mut FdstoreDesc,
) -> i32 {
    let mut id_map = get_inherit_fd_ids().lock().unwrap();

    for inh in &opts().inherit_fds {
        let fd_id = match fdstore_add(sfd_state, fdstore_desc, inh.inh_fd) {
            Ok(id) => id,
            Err(_) => {
                log::error!("Failed to add inherited fd {} to fdstore", inh.inh_fd);
                return -1;
            }
        };

        id_map.insert(inh.inh_id.clone(), fd_id);

        unsafe {
            libc::close(inh.inh_fd);
        }
    }

    0
}

use crate::criu::pstree::{rsti_mut, vpid, Fdt, PidStore};

pub fn shared_fdt_prepare(store: &mut crate::criu::pstree::PidStore, item_idx: usize) -> i32 {
    let parent_idx = {
        let item = match store.get_item(item_idx) {
            Some(i) => i,
            None => return -1,
        };
        match item.parent_idx {
            Some(idx) => idx,
            None => return -1,
        }
    };

    let (parent_fdt, parent_vpid) = {
        let parent = match store.get_item(parent_idx) {
            Some(p) => p,
            None => return -1,
        };
        let fdt_info = match &parent.mode_info {
            Some(crate::criu::pstree::ModeInfo::Restore(rsti)) => {
                rsti.fdt.as_ref().map(|f| (f.nr, f.pid))
            }
            _ => None,
        };
        (fdt_info, vpid(parent))
    };

    let (fdt_nr, item_service_fd_id) = if let Some((nr, _fdt_pid)) = parent_fdt {
        let new_nr = nr + 1;

        if let Some(parent) = store.get_item_mut(parent_idx) {
            if let Some(rsti) = rsti_mut(parent) {
                if let Some(ref mut fdt) = rsti.fdt {
                    fdt.nr = new_nr;
                }
            }
        }

        (new_nr, nr)
    } else {
        let mut fdt = Box::new(Fdt::default());
        fdt.fdt_lock.init();
        fdt.nr = 1;
        fdt.pid = parent_vpid;

        if let Some(parent) = store.get_item_mut(parent_idx) {
            if let Some(rsti) = rsti_mut(parent) {
                rsti.fdt = Some(fdt);
            }
        }

        (2, 1)
    };

    {
        let mut fdt = Box::new(Fdt::default());
        fdt.fdt_lock.init();
        fdt.nr = fdt_nr;
        fdt.pid = parent_vpid;

        let item = match store.get_item_mut(item_idx) {
            Some(i) => i,
            None => return -1,
        };
        if let Some(rsti) = rsti_mut(item) {
            rsti.fdt = Some(fdt);
            rsti.service_fd_id = item_service_fd_id;
        }
    }

    0
}

pub fn files_collected() -> bool {
    FILES_COLLECTED.load(Ordering::Relaxed)
}

fn collect_one_file(fe: &FileEntry) -> i32 {
    // TODO: Dispatch based on fe.r#type to appropriate collector
    // For now, just log and continue
    log::debug!("Collecting file entry id={} type={:?}", fe.id, fe.r#type);
    0
}

pub fn prepare_files(dfd: RawFd) -> i32 {
    init_fdesc_hash();
    init_sk_info_hash();
    init_dead_pidfd_hash();

    let mut img = match open_image(dfd, CrFdType::Files, "") {
        Ok(img) => img,
        Err(_) => return -1,
    };

    log::info!("Collecting files");

    loop {
        match pb_read_one_eof::<FileEntry>(&mut img) {
            Ok(Some(fe)) => {
                FILES_COLLECTED.store(true, Ordering::Relaxed);
                if collect_one_file(&fe) < 0 {
                    close_image(&mut img);
                    return -1;
                }
            }
            Ok(None) => break,
            Err(e) => {
                log::error!("Failed to read file entry: {}", e);
                close_image(&mut img);
                return -1;
            }
        }
    }

    close_image(&mut img);
    log::debug!(" `- ... done");
    0
}

pub fn close_old_fds(sfd_state: &mut ServiceFdState) -> i32 {
    use crate::criu::util::{close_pid_proc, open_pid_proc, PROC_NONE, PROC_SELF};
    use std::ffi::CString;

    let mut open_proc_self_pid: libc::pid_t = 0;
    let mut open_proc_pid: libc::pid_t = PROC_NONE;

    // Close previous /proc/self/ service fd, as we don't want to reuse it
    // from a different task.
    sfd_state.close_service_fd(crate::criu::servicefd::SfdType::ProcSelfFdOff);

    // Open /proc/self/fd directory
    let proc_self_fd = open_pid_proc(sfd_state, &mut open_proc_self_pid, &mut open_proc_pid, PROC_SELF);
    if proc_self_fd < 0 {
        return -1;
    }

    let fd_path = CString::new("fd").unwrap();
    let dir_fd = unsafe { libc::openat(proc_self_fd, fd_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if dir_fd < 0 {
        close_pid_proc(sfd_state, &mut open_proc_self_pid, &mut open_proc_pid);
        return -1;
    }

    // Read directory entries and close non-service fds
    let dir = unsafe { libc::fdopendir(dir_fd) };
    if dir.is_null() {
        unsafe { libc::close(dir_fd) };
        close_pid_proc(sfd_state, &mut open_proc_self_pid, &mut open_proc_pid);
        return -1;
    }

    loop {
        let de = unsafe { libc::readdir(dir) };
        if de.is_null() {
            break;
        }

        let name = unsafe { std::ffi::CStr::from_ptr((*de).d_name.as_ptr()) };
        let name_str = match name.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Skip . and ..
        if name_str == "." || name_str == ".." {
            continue;
        }

        let fd: i32 = match name_str.parse() {
            Ok(f) => f,
            Err(_) => {
                log::error!("Can't parse {}", name_str);
                unsafe { libc::closedir(dir) };
                close_pid_proc(sfd_state, &mut open_proc_self_pid, &mut open_proc_pid);
                return -1;
            }
        };

        // Skip service fds and the directory fd itself
        let dir_fd_val = unsafe { libc::dirfd(dir) };
        if !sfd_state.is_any_service_fd(fd) && dir_fd_val != fd {
            unsafe { libc::close(fd) };
        }
    }

    unsafe { libc::closedir(dir) };
    close_pid_proc(sfd_state, &mut open_proc_self_pid, &mut open_proc_pid);

    0
}

use crate::proto::{FdinfoEntry, FsEntry};

pub fn prepare_fd_pid(store: &mut PidStore, item_idx: usize, dfd: std::os::unix::io::RawFd) -> i32 {
    use crate::criu::kerndat::kdat;

    let (pid, files_id, is_zombie, has_fdt_mismatch) = {
        let item = match store.get_item(item_idx) {
            Some(i) => i,
            None => return -1,
        };

        let is_zombie = item.ids.is_none();
        if is_zombie {
            return 0;
        }

        let files_id = item.ids.as_ref().map(|ids| ids.files_id).unwrap_or(0);
        let pid = vpid(item);

        let has_fdt_mismatch = match &item.mode_info {
            Some(crate::criu::pstree::ModeInfo::Restore(rsti)) => {
                if let Some(ref fdt) = rsti.fdt {
                    fdt.pid != pid
                } else {
                    false
                }
            }
            _ => false,
        };

        (pid, files_id, is_zombie, has_fdt_mismatch)
    };

    if has_fdt_mismatch {
        return 0;
    }

    let mut img = match open_image(dfd, CrFdType::Fdinfo, &files_id.to_string()) {
        Ok(img) => img,
        Err(_) => return -1,
    };

    let sysctl_nr_open = kdat().sysctl_nr_open;
    let mut fds_collected: Vec<FdinfoEntry> = Vec::new();
    let mut ret = 0;

    loop {
        let e: FdinfoEntry = match pb_read_one_eof(&mut img) {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) => {
                ret = -1;
                break;
            }
        };

        if e.fd >= sysctl_nr_open {
            log::error!("Too big FD number to restore {}", e.fd);
            ret = -1;
            break;
        }

        log::info!("Collect fdinfo pid={} fd={} id={:#x}", pid, e.fd, e.id);

        if files_collected() {
            // TODO: pass actual pstree_item pointer once PstreeItem is shmalloc'd
            if unsafe { collect_fd(pid, &e, ptr::null_mut(), false) } < 0 {
                ret = -1;
                break;
            }
        }
        fds_collected.push(e);
    }

    close_image(&mut img);

    if ret == 0 {
        if let Some(item) = store.get_item_mut(item_idx) {
            if let Some(rsti) = rsti_mut(item) {
                rsti.fds = fds_collected;
            }
        }
    }

    ret
}

pub fn prepare_fs_pid(store: &mut PidStore, item_idx: usize, dfd: std::os::unix::io::RawFd) -> i32 {
    let pid = match store.get_item(item_idx) {
        Some(item) => vpid(item),
        None => return -1,
    };

    let mut img = match open_image(dfd, CrFdType::Fs, &pid.to_string()) {
        Ok(img) => img,
        Err(_) => return -1,
    };

    let fe: FsEntry = match pb_read_one_eof(&mut img) {
        Ok(Some(e)) => e,
        Ok(None) => {
            close_image(&mut img);
            return 0;
        }
        Err(_) => {
            close_image(&mut img);
            return -1;
        }
    };
    close_image(&mut img);

    let cwd_id = fe.cwd_id;
    let root_id = fe.root_id;
    let has_umask = fe.umask.is_some();
    let umask = fe.umask.unwrap_or(0);

    if files_collected() {
        unsafe {
            let _ = try_collect_special_file(cwd_id, true);
            let _ = try_collect_special_file(root_id, true);
        }
    }

    if let Some(item) = store.get_item_mut(item_idx) {
        if let Some(rsti) = rsti_mut(item) {
            rsti.cwd = Some(cwd_id);
            rsti.root = Some(root_id);
            rsti.has_umask = has_umask;
            rsti.umask = umask;
        }
    }

    0
}
