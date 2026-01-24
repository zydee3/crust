use std::ptr::NonNull;
use std::sync::atomic::AtomicU32;
use std::sync::OnceLock;

use super::rbtree::{rb_first, rb_link_and_balance, rb_next, RbNode, RbRoot};

pub const RESERVED_PIDS: i32 = 300;
pub const INIT_PID: i32 = 1;

// CLONE_NEWTIME not in older libc
pub const CLONE_NEWTIME: u64 = 0x00000080;

pub const CLONE_ALLNS: u64 = libc::CLONE_NEWPID as u64
    | libc::CLONE_NEWNET as u64
    | libc::CLONE_NEWIPC as u64
    | libc::CLONE_NEWUTS as u64
    | libc::CLONE_NEWNS as u64
    | libc::CLONE_NEWUSER as u64
    | libc::CLONE_NEWCGROUP as u64
    | CLONE_NEWTIME;

pub const CLONE_SUBNS: u64 = libc::CLONE_NEWNS as u64 | libc::CLONE_NEWNET as u64;

use crate::proto::{CoreEntry, FdinfoEntry, MmEntry, TaskKobjIdsEntry};

static ROOT_ITEM_IDX: OnceLock<usize> = OnceLock::new();
static ROOT_ITEM_PID_REAL: OnceLock<libc::pid_t> = OnceLock::new();

pub fn set_root_item(idx: usize, pid_real: libc::pid_t) -> Result<(), ()> {
    ROOT_ITEM_IDX.set(idx).map_err(|_| ())?;
    ROOT_ITEM_PID_REAL.set(pid_real).map_err(|_| ())?;
    Ok(())
}

pub fn root_item_idx() -> usize {
    *ROOT_ITEM_IDX.get().expect("root_item not initialized")
}

pub fn root_item_idx_try() -> Option<usize> {
    ROOT_ITEM_IDX.get().copied()
}

pub fn root_item_pid_real() -> libc::pid_t {
    *ROOT_ITEM_PID_REAL.get().expect("root_item not initialized")
}

pub fn root_item_pid_real_try() -> Option<libc::pid_t> {
    ROOT_ITEM_PID_REAL.get().copied()
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TaskState {
    Alive = 0x1,
    Dead = 0x2,
    Stopped = 0x3,
    Helper = 0x4,
    Thread = 0x5,
    #[default]
    Undef = 0xff,
}

impl From<i32> for TaskState {
    fn from(v: i32) -> Self {
        match v {
            0x1 => TaskState::Alive,
            0x2 => TaskState::Dead,
            0x3 => TaskState::Stopped,
            0x4 => TaskState::Helper,
            0x5 => TaskState::Thread,
            _ => TaskState::Undef,
        }
    }
}

#[derive(Debug, Default)]
pub struct Futex {
    pub raw: AtomicU32,
}

impl Futex {
    pub fn new(val: u32) -> Self {
        Self {
            raw: AtomicU32::new(val),
        }
    }

    pub fn init(&self) {
        self.raw.store(0, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn get(&self) -> u32 {
        self.raw.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn set(&self, v: u32) {
        self.raw.store(v, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn set_and_wake(&self, v: u32) {
        self.set(v);
        self.wake();
    }

    pub fn wake(&self) {
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                &self.raw as *const AtomicU32,
                libc::FUTEX_WAKE,
                i32::MAX,
                std::ptr::null::<libc::timespec>(),
                std::ptr::null::<u32>(),
                0u32,
            );
        }
    }

    fn sys_futex_wait(&self, expected: u32, timeout: Option<&libc::timespec>) -> i32 {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_futex,
                &self.raw as *const AtomicU32,
                libc::FUTEX_WAIT,
                expected as i32,
                timeout.map_or(std::ptr::null(), |t| t as *const _),
                std::ptr::null::<u32>(),
                0u32,
            )
        };
        if ret == -1 {
            -unsafe { *libc::__errno_location() }
        } else {
            ret as i32
        }
    }

    pub fn wait_until(&self, v: u32) {
        let timeout = libc::timespec {
            tv_sec: 120,
            tv_nsec: 0,
        };
        const FUTEX_ABORT_FLAG: u32 = 0x80000000;
        loop {
            let tmp = self.get();
            if (tmp & FUTEX_ABORT_FLAG) != 0 || tmp == v {
                break;
            }
            let ret = self.sys_futex_wait(tmp, Some(&timeout));
            if ret == -libc::ETIMEDOUT || ret == -libc::EINTR || ret == -libc::EWOULDBLOCK {
                continue;
            }
            if ret < 0 {
                panic!("futex_wait_until failed: {}", ret);
            }
        }
    }
}

pub struct PidNsEntry {
    pub virt: i32,
    pub node: RbNode,
}

impl Default for PidNsEntry {
    fn default() -> Self {
        Self {
            virt: -1,
            node: RbNode::new(),
        }
    }
}

impl std::fmt::Debug for PidNsEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PidNsEntry")
            .field("virt", &self.virt)
            .finish()
    }
}

#[derive(Debug)]
pub struct Pid {
    pub item_idx: Option<usize>,
    /*
     * The @real pid is used to fetch tasks during dumping stage,
     * This is a global pid seen from the context where the dumping
     * is running.
     */
    pub real: i32,
    pub state: TaskState,
    pub stop_signo: i32,
    /*
     * The @virt pid is one which used in the image itself and keeps
     * the pid value to be restored. This pid fetched from the
     * dumpee context, because the dumpee might have own pid namespace.
     */
    pub ns: [PidNsEntry; 1],
}

impl Default for Pid {
    fn default() -> Self {
        Self {
            item_idx: None,
            real: -1,
            state: TaskState::Undef,
            stop_signo: -1,
            ns: [PidNsEntry::default()],
        }
    }
}

pub mod vma_status {
    pub const VMA_AREA_NONE: u32 = 0 << 0;
    pub const VMA_AREA_REGULAR: u32 = 1 << 0;
    pub const VMA_AREA_STACK: u32 = 1 << 1;
    pub const VMA_AREA_VSYSCALL: u32 = 1 << 2;
    pub const VMA_AREA_VDSO: u32 = 1 << 3;
    pub const VMA_AREA_HEAP: u32 = 1 << 5;
    pub const VMA_FILE_PRIVATE: u32 = 1 << 6;
    pub const VMA_FILE_SHARED: u32 = 1 << 7;
    pub const VMA_ANON_SHARED: u32 = 1 << 8;
    pub const VMA_ANON_PRIVATE: u32 = 1 << 9;
    pub const VMA_AREA_SYSVIPC: u32 = 1 << 10;
    pub const VMA_AREA_SOCKET: u32 = 1 << 11;
    pub const VMA_AREA_VVAR: u32 = 1 << 12;
    pub const VMA_AREA_AIORING: u32 = 1 << 13;
    pub const VMA_AREA_MEMFD: u32 = 1 << 14;
    pub const VMA_AREA_SHSTK: u32 = 1 << 15;
    pub const VMA_AREA_GUARD: u32 = 1 << 16;
    pub const VMA_EXT_PLUGIN: u32 = 1 << 27;
    pub const VMA_CLOSE: u32 = 1 << 28;
    pub const VMA_NO_PROT_WRITE: u32 = 1 << 29;
    pub const VMA_PREMMAPED: u32 = 1 << 30;
    pub const VMA_UNSUPP: u32 = 1 << 31;
}

use crate::proto::VmaEntry;

#[derive(Debug)]
pub struct VmaArea {
    pub e: VmaEntry,
    pub vmfd: Option<u32>,
    pub pvma: Option<usize>,
    pub page_bitmap: Option<Vec<u64>>,
    pub premmaped_addr: u64,
}

impl VmaArea {
    pub fn new(e: VmaEntry) -> Self {
        Self {
            e,
            vmfd: None,
            pvma: None,
            page_bitmap: None,
            premmaped_addr: 0,
        }
    }

    pub fn is(&self, status: u32) -> bool {
        (self.e.status & status) == status
    }

    pub fn len(&self) -> u64 {
        self.e.end - self.e.start
    }
}

#[derive(Debug, Default)]
pub struct VmAreaList {
    pub entries: Vec<VmaArea>,
    pub nr: u32,
    pub nr_aios: u32,
    pub rst_priv_size: u64,
    pub nr_priv_pages_longest: u64,
    pub nr_shared_pages_longest: u64,
}

impl VmAreaList {
    pub fn init(&mut self) {
        self.entries.clear();
        self.nr = 0;
        self.nr_aios = 0;
        self.rst_priv_size = 0;
        self.nr_priv_pages_longest = 0;
        self.nr_shared_pages_longest = 0;
    }
}

#[derive(Debug, Default)]
pub struct Fdt {
    pub nr: i32,
    pub pid: i32,
    /*
     * The fd table is ready for restoing, if fdt_lock is equal to nr
     * The fdt table was restored, if fdt_lock is equal to nr + 1
     */
    pub fdt_lock: Futex,
}

#[derive(Debug, Default)]
pub struct RstRseq {
    pub rseq_abi_pointer: u64,
    pub rseq_cs_pointer: u64,
}

#[derive(Debug, Default)]
pub struct RstArchInfo {}

#[derive(Debug, Default)]
pub struct RstInfo {
    pub fds: Vec<FdinfoEntry>,
    pub premmapped_addr: u64,
    pub premmapped_len: u64,
    pub clone_flags: u64,
    pub munmap_restorer: u64,
    pub service_fd_id: i32,
    pub fdt: Option<Box<Fdt>>,
    pub vmas: VmAreaList,
    pub mm: Option<Box<MmEntry>>,
    pub vma_io: Vec<()>,
    pub pages_img_id: u32,
    pub cg_set: u32,
    pub pgrp_leader_idx: Option<usize>,
    pub pgrp_set: Futex,
    pub cwd: Option<u32>,
    pub root: Option<u32>,
    pub has_umask: bool,
    pub umask: u32,
    /*
     * We set this flag when process has seccomp filters
     * so that we know to suspend them before we unmap the
     * restorer blob.
     */
    pub has_seccomp: bool,
    /*
     * To be compatible with old images where filters
     * are bound to group leader and we need to use tsync flag.
     */
    pub has_old_seccomp_filter: bool,
    pub rseqe: Option<Box<RstRseq>>,
    pub shstk_enable: Futex,
    pub shstk_unlock: Futex,
    pub breakpoint: u64,
    pub arch_info: RstArchInfo,
}

#[derive(Debug, Default)]
pub struct DmpInfo {
    pub netns: Option<()>,
    pub mem_pp: Option<()>,
    pub parasite_ctl: Option<()>,
    pub thread_ctls: Vec<()>,
    pub thread_sp: Vec<u64>,
    pub thread_rseq_cs: Vec<()>,
    /*
     * Although we don't support dumping different struct creds in general,
     * we do for threads. Let's keep track of their profiles here; a NULL
     * entry means there was no LSM profile for this thread.
     */
    pub thread_lsms: Vec<()>,
}

#[derive(Debug)]
pub enum ModeInfo {
    Restore(Box<RstInfo>),
    Dump(Box<DmpInfo>),
}

#[derive(Debug)]
pub struct PstreeItem {
    pub parent_idx: Option<usize>,
    pub children: Vec<usize>,
    pub sibling: Vec<usize>,
    pub pid: Pid,
    pub pgid: i32,
    pub sid: i32,
    pub born_sid: i32,
    pub nr_threads: i32,
    pub threads: Vec<Pid>,
    pub core: Vec<Option<Box<CoreEntry>>>,
    pub ids: Option<Box<TaskKobjIdsEntry>>,
    pub task_st: Futex,
    pub mode_info: Option<ModeInfo>,
}

impl Default for PstreeItem {
    fn default() -> Self {
        Self {
            parent_idx: None,
            children: Vec::new(),
            sibling: Vec::new(),
            pid: Pid::default(),
            pgid: 0,
            sid: 0,
            born_sid: -1,
            nr_threads: 0,
            threads: Vec::new(),
            core: Vec::new(),
            ids: None,
            task_st: Futex::default(),
            mode_info: None,
        }
    }
}

pub fn rsti(item: &PstreeItem) -> Option<&RstInfo> {
    match &item.mode_info {
        Some(ModeInfo::Restore(info)) => Some(info),
        _ => None,
    }
}

pub fn rsti_mut(item: &mut PstreeItem) -> Option<&mut RstInfo> {
    match &mut item.mode_info {
        Some(ModeInfo::Restore(info)) => Some(info),
        _ => None,
    }
}

pub fn dmpi(item: &PstreeItem) -> Option<&DmpInfo> {
    match &item.mode_info {
        Some(ModeInfo::Dump(info)) => Some(info),
        _ => None,
    }
}

pub fn alloc_pstree_item(rst: bool) -> PstreeItem {
    let mut item = PstreeItem::default();

    if rst {
        let mut rst_info = Box::new(RstInfo::default());
        rst_info.vmas.init();
        item.mode_info = Some(ModeInfo::Restore(rst_info));
    } else {
        let dmp_info = Box::new(DmpInfo::default());
        item.mode_info = Some(ModeInfo::Dump(dmp_info));
    }

    item.pid.ns[0].virt = -1;
    item.pid.ns[0].node.init();
    item.pid.real = -1;
    item.pid.state = TaskState::Undef;
    item.pid.stop_signo = -1;
    item.born_sid = -1;

    item.task_st.init();

    item
}

pub struct PidStore {
    pid_root: RbRoot,
    items: Vec<Box<PstreeItem>>,
}

impl Default for PidStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PidStore {
    pub fn new() -> Self {
        PidStore {
            pid_root: RbRoot::new(),
            items: Vec::new(),
        }
    }

    pub fn lookup_create_pid(&mut self, pid: i32, existing_item: Option<usize>) -> Option<usize> {
        unsafe {
            let mut node = self.pid_root.rb_node;
            let mut new_link: *mut Option<NonNull<RbNode>> = &mut self.pid_root.rb_node;
            let mut parent: Option<NonNull<RbNode>> = None;

            while let Some(current) = node {
                let pid_ns_entry = Self::entry_from_node(current);
                let this_virt = (*pid_ns_entry).virt;

                parent = node;
                if pid < this_virt {
                    new_link = &mut (*current.as_ptr()).rb_left;
                    node = (*current.as_ptr()).rb_left;
                } else if pid > this_virt {
                    new_link = &mut (*current.as_ptr()).rb_right;
                    node = (*current.as_ptr()).rb_right;
                } else {
                    return self.find_item_idx_by_pid_ns_entry(pid_ns_entry);
                }
            }

            let item_idx = if let Some(idx) = existing_item {
                idx
            } else {
                let item = alloc_pstree_item(true);
                let idx = self.items.len();
                self.items.push(Box::new(item));
                idx
            };

            let item = &mut self.items[item_idx];
            item.pid.ns[0].virt = pid;
            item.pid.item_idx = Some(item_idx);
            item.pid.ns[0].node.init();

            let node_ptr = NonNull::new(&mut item.pid.ns[0].node)?;
            rb_link_and_balance(&mut self.pid_root, node_ptr, parent, &mut *new_link);

            Some(item_idx)
        }
    }

    fn entry_from_node(node: NonNull<RbNode>) -> *mut PidNsEntry {
        let node_offset = std::mem::offset_of!(PidNsEntry, node);
        let node_ptr = node.as_ptr() as *mut u8;
        unsafe { node_ptr.sub(node_offset) as *mut PidNsEntry }
    }

    fn find_item_idx_by_pid_ns_entry(&self, entry: *const PidNsEntry) -> Option<usize> {
        let pid_offset = std::mem::offset_of!(Pid, ns);
        let entry_ptr = entry as *const u8;
        let pid_ptr = unsafe { entry_ptr.sub(pid_offset) } as *const Pid;

        unsafe { (*pid_ptr).item_idx }
    }

    pub fn pstree_pid_by_virt(&self, pid: i32) -> Option<usize> {
        unsafe {
            let mut node = self.pid_root.rb_node;

            while let Some(current) = node {
                let pid_ns_entry = Self::entry_from_node(current);
                let this_virt = (*pid_ns_entry).virt;

                if pid < this_virt {
                    node = (*current.as_ptr()).rb_left;
                } else if pid > this_virt {
                    node = (*current.as_ptr()).rb_right;
                } else {
                    return self.find_item_idx_by_pid_ns_entry(pid_ns_entry);
                }
            }
            None
        }
    }

    pub fn pstree_item_by_virt(&self, pid: i32) -> Option<usize> {
        let idx = self.pstree_pid_by_virt(pid)?;
        let item = self.get_item(idx)?;
        assert!(
            item.pid.state != TaskState::Thread,
            "BUG: pstree_item_by_virt called on thread"
        );
        Some(idx)
    }

    pub fn lookup_create_item(&mut self, pid: i32) -> Option<usize> {
        let idx = self.lookup_create_pid(pid, None)?;
        let item = self.get_item(idx)?;
        if item.pid.state == TaskState::Thread {
            panic!("BUG: lookup_create_item called on thread");
        }
        Some(idx)
    }

    pub fn get_item(&self, idx: usize) -> Option<&PstreeItem> {
        self.items.get(idx).map(|b| b.as_ref())
    }

    pub fn get_item_mut(&mut self, idx: usize) -> Option<&mut PstreeItem> {
        self.items.get_mut(idx).map(|b| b.as_mut())
    }

    pub fn items_count(&self) -> usize {
        self.items.len()
    }

    pub fn get_free_pid(&self) -> i32 {
        unsafe {
            let first_node = match rb_first(&self.pid_root) {
                Some(n) => n,
                None => return -1,
            };

            let mut prev = Self::entry_from_node(first_node);

            loop {
                // Get next candidate PID (current + 1, but skip reserved range)
                let mut pid = (*prev).virt + 1;
                if pid < RESERVED_PIDS {
                    pid = RESERVED_PIDS + 1;
                }

                // Get next node in tree
                let prev_node = NonNull::new(&mut (*prev).node as *mut RbNode).unwrap();
                let next_node = rb_next(prev_node);

                // If no more nodes, this PID is available
                if next_node.is_none() {
                    return pid;
                }

                let next = Self::entry_from_node(next_node.unwrap());

                // If there's a gap (next PID in tree > candidate), we found a free slot
                if (*next).virt > pid {
                    return pid;
                }

                // Continue to next entry
                prev = next;
            }
        }
    }
}

#[inline]
pub fn vpid(item: &PstreeItem) -> i32 {
    item.pid.ns[0].virt
}

#[inline]
pub fn is_alive_state(state: TaskState) -> bool {
    matches!(state, TaskState::Alive | TaskState::Stopped)
}

#[inline]
pub fn task_alive(item: &PstreeItem) -> bool {
    is_alive_state(item.pid.state)
}

#[inline]
pub fn task_dead(item: &PstreeItem) -> bool {
    item.pid.state == TaskState::Dead
}

#[inline]
pub fn pid_rst_prio(pid_a: u32, pid_b: u32) -> bool {
    pid_a < pid_b
}

#[inline]
pub fn pid_rst_prio_eq(pid_a: u32, pid_b: u32) -> bool {
    pid_a <= pid_b
}

pub fn get_clone_mask(item_ids: &TaskKobjIdsEntry, parent_ids: &TaskKobjIdsEntry) -> u64 {
    let mut mask: u64 = 0;

    if item_ids.files_id == parent_ids.files_id {
        mask |= libc::CLONE_FILES as u64;
    }
    if item_ids.pid_ns_id != parent_ids.pid_ns_id {
        mask |= libc::CLONE_NEWPID as u64;
    }
    if item_ids.net_ns_id != parent_ids.net_ns_id {
        mask |= libc::CLONE_NEWNET as u64;
    }
    if item_ids.ipc_ns_id != parent_ids.ipc_ns_id {
        mask |= libc::CLONE_NEWIPC as u64;
    }
    if item_ids.uts_ns_id != parent_ids.uts_ns_id {
        mask |= libc::CLONE_NEWUTS as u64;
    }
    if item_ids.time_ns_id != parent_ids.time_ns_id {
        mask |= 0x00000080; // CLONE_NEWTIME (not in older libc)
    }
    if item_ids.mnt_ns_id != parent_ids.mnt_ns_id {
        mask |= libc::CLONE_NEWNS as u64;
    }
    if item_ids.user_ns_id != parent_ids.user_ns_id {
        mask |= libc::CLONE_NEWUSER as u64;
    }

    mask
}

pub fn init_pstree_helper(item: &mut PstreeItem) -> i32 {
    assert!(
        item.parent_idx.is_some(),
        "BUG: init_pstree_helper called on item without parent"
    );

    item.pid.state = TaskState::Helper;

    if let Some(rsti) = rsti_mut(item) {
        rsti.clone_flags = 0;
        rsti.fds.clear();
    }

    if let Some(te) = task_entries_try() {
        unsafe {
            let te_ptr = te as *const _ as *mut crate::criu::task_entries::TaskEntries;
            (*te_ptr).nr_helpers += 1;
        }
    }

    0
}

use std::os::unix::io::RawFd;

use crate::criu::image::{close_image, open_image, CrImg};
use crate::criu::image_desc::CrFdType;
use crate::criu::namespaces::{ns_desc, rst_add_ns_id};
use crate::criu::protobuf::pb_read_one_eof;
use crate::criu::task_entries::task_entries_try;
use crate::proto::PstreeEntry;

pub fn read_pstree_ids(
    item: &mut PstreeItem,
    item_idx: usize,
    dfd: RawFd,
) -> i32 {
    let pid = vpid(item);
    let path = format!("ids-{}.img", pid);

    let mut img = match open_image(dfd, CrFdType::Ids, &path) {
        Ok(img) => img,
        Err(_) => return -1,
    };

    if img.is_empty() {
        return 0;
    }

    let ids: Option<TaskKobjIdsEntry> = match pb_read_one_eof(&mut img) {
        Ok(opt) => opt,
        Err(_) => {
            close_image(&mut img);
            return -1;
        }
    };

    close_image(&mut img);

    let ids = match ids {
        Some(ids) => ids,
        None => return 0,
    };

    if let Some(mnt_ns_id) = ids.mnt_ns_id {
        if rst_add_ns_id(mnt_ns_id, item_idx, pid, &ns_desc::MNT) != 0 {
            return -1;
        }
    }
    if let Some(net_ns_id) = ids.net_ns_id {
        if rst_add_ns_id(net_ns_id, item_idx, pid, &ns_desc::NET) != 0 {
            return -1;
        }
    }
    if let Some(pid_ns_id) = ids.pid_ns_id {
        if rst_add_ns_id(pid_ns_id, item_idx, pid, &ns_desc::PID) != 0 {
            return -1;
        }
    }

    item.ids = Some(Box::new(ids));
    0
}

pub fn read_pstree_image(
    store: &mut PidStore,
    dfd: RawFd,
    pid_max: &mut i32,
) -> i32 {
    log::info!("Reading image tree");

    let mut img = match open_image(dfd, CrFdType::Pstree, "pstree.img") {
        Ok(img) => img,
        Err(_) => return -1,
    };

    let ret;
    loop {
        let r = read_one_pstree_item(store, &mut img, pid_max, dfd);
        if r <= 0 {
            ret = r;
            break;
        }
    }

    close_image(&mut img);
    ret
}

pub fn read_one_pstree_item(
    store: &mut PidStore,
    img: &mut CrImg,
    pid_max: &mut i32,
    dfd: RawFd,
) -> i32 {
    let e: Option<PstreeEntry> = match pb_read_one_eof(img) {
        Ok(opt) => opt,
        Err(_) => return -1,
    };

    let e = match e {
        Some(entry) => entry,
        None => return 0,
    };

    let pi_idx = match store.lookup_create_item(e.pid as i32) {
        Some(idx) => idx,
        None => return -1,
    };

    {
        let pi = store.get_item(pi_idx).unwrap();
        assert!(
            pi.pid.state == TaskState::Undef,
            "BUG: pstree item state should be UNDEF"
        );
    }

    /*
     * All pids should be added in the tree to be able to find
     * free pid-s for helpers. pstree_item for these pid-s will
     * be initialized when we meet PstreeEntry with this pid or
     * we will create helpers for them.
     */
    if store.lookup_create_item(e.pgid as i32).is_none() {
        return -1;
    }
    if store.lookup_create_item(e.sid as i32).is_none() {
        return -1;
    }

    // Update pid_max
    if (e.pid as i32) > *pid_max {
        *pid_max = e.pid as i32;
    }
    if (e.pgid as i32) > *pid_max {
        *pid_max = e.pgid as i32;
    }
    if (e.sid as i32) > *pid_max {
        *pid_max = e.sid as i32;
    }

    // Set up parent-child relationship
    let parent_idx = if e.ppid == 0 {
        if root_item_idx_try().is_some() {
            log::error!(
                "Parent missed on non-root task with pid {}, image corruption!",
                e.pid
            );
            return -1;
        }
        // This is the root item
        let pi_pid_real = store.get_item(pi_idx).unwrap().pid.real;
        if set_root_item(pi_idx, pi_pid_real).is_err() {
            return -1;
        }
        None
    } else {
        let parent_result = store.pstree_pid_by_virt(e.ppid as i32);
        match parent_result {
            Some(idx) => {
                let parent = store.get_item(idx).unwrap();
                if parent.pid.state == TaskState::Undef || parent.pid.state == TaskState::Thread {
                    log::error!("Can't find a parent for {}", e.pid);
                    return -1;
                }
                Some(idx)
            }
            None => {
                log::error!("Can't find a parent for {}", e.pid);
                return -1;
            }
        }
    };

    // Set up threads
    let nr_threads = e.threads.len();
    let mut threads = Vec::with_capacity(nr_threads);
    for (i, tid) in e.threads.iter().enumerate() {
        let mut thread_pid = Pid::default();
        thread_pid.real = -1;
        thread_pid.ns[0].virt = *tid as i32;
        thread_pid.state = TaskState::Thread;
        thread_pid.item_idx = None;

        if i > 0 {
            // Thread leader is already in tree
            let existing = store.pstree_pid_by_virt(*tid as i32);
            if existing.is_some() {
                log::error!("Unexpected task {} in a tree {}", tid, i);
                return -1;
            }
        }

        threads.push(thread_pid);
    }

    // Update the item
    {
        let pi = store.get_item_mut(pi_idx).unwrap();
        pi.pid.ns[0].virt = e.pid as i32;
        pi.pgid = e.pgid as i32;
        pi.sid = e.sid as i32;
        pi.pid.state = TaskState::Alive;
        pi.parent_idx = parent_idx;
        pi.nr_threads = nr_threads as i32;
        pi.threads = threads;
    }

    // Add to parent's children list
    if let Some(parent_idx) = parent_idx {
        let parent = store.get_item_mut(parent_idx).unwrap();
        parent.children.push(pi_idx);
    }

    // Update task_entries
    // Note: In the C code, task_entries is in shared memory and modified atomically.
    // For now, we use unsafe to update the counts. This will need proper
    // synchronization when multi-process restore is implemented.
    if let Some(te) = task_entries_try() {
        unsafe {
            let te_ptr = te as *const _ as *mut crate::criu::task_entries::TaskEntries;
            (*te_ptr).nr_threads += nr_threads as i32;
            (*te_ptr).nr_tasks += 1;
        }
    }

    // Read pstree ids - note: we don't fail if we have empty ids
    {
        let pi = store.get_item_mut(pi_idx).unwrap();
        if read_pstree_ids(pi, pi_idx, dfd) < 0 {
            return -1;
        }
    }

    1
}

use crate::criu::files::shared_fdt_prepare;
use crate::criu::namespaces::{root_ns_mask_try, set_root_ns_mask};
use crate::criu::options::opts;
use crate::criu::rst_malloc::shmalloc;

static ROOT_IDS: OnceLock<Box<TaskKobjIdsEntry>> = OnceLock::new();

pub fn set_root_ids(ids: Box<TaskKobjIdsEntry>) -> Result<(), Box<TaskKobjIdsEntry>> {
    ROOT_IDS.set(ids)
}

pub fn root_ids() -> Option<&'static TaskKobjIdsEntry> {
    ROOT_IDS.get().map(|b| b.as_ref())
}

pub fn prepare_pstree_for_shell_job(store: &mut PidStore, pid: libc::pid_t) -> i32 {
    let current_sid = unsafe { libc::getsid(pid) };
    let current_gid = unsafe { libc::getpgid(pid) };

    if opts().shell_job == 0 {
        return 0;
    }

    let root_idx = match root_item_idx_try() {
        Some(idx) => idx,
        None => return -1,
    };

    let root_sid = {
        let root = store.get_item(root_idx).unwrap();
        root.sid
    };
    let root_vpid = {
        let root = store.get_item(root_idx).unwrap();
        vpid(root)
    };

    // root_item is a session leader
    if root_sid == root_vpid {
        return 0;
    }

    /*
     * Migration of a root task group leader is a bit tricky.
     * When a task yields SIGSTOP, the kernel notifies the parent
     * with SIGCHLD. This means when task is running in a
     * shell, the shell obtains SIGCHLD and sends a task to
     * the background.
     *
     * The situation gets changed once we restore the
     * program -- our tool become an additional stub between
     * the restored program and the shell. So to be able to
     * notify the shell with SIGCHLD from our restored
     * program -- we make the root task to inherit the
     * process group from us.
     *
     * Not that clever solution but at least it works.
     */

    let old_sid = root_sid;
    if old_sid != current_sid {
        log::info!(
            "Migrating process tree (SID {}->{:?})",
            old_sid,
            current_sid
        );

        let tmp = store.pstree_pid_by_virt(current_sid);
        if tmp.is_some() {
            let tmp_item = store.get_item(tmp.unwrap()).unwrap();
            log::error!(
                "Current sid {} intersects with pid ({:?}) in images",
                current_sid,
                tmp_item.pid.state
            );
            return -1;
        }

        // Update all items with matching sid/pgid
        for idx in 0..store.items.len() {
            let item = store.get_item_mut(idx).unwrap();
            if item.sid == current_sid {
                log::error!(
                    "Current sid {} intersects with sid of ({}) in images",
                    current_sid,
                    vpid(item)
                );
                return -1;
            }
            if item.sid == old_sid {
                item.sid = current_sid;
            }

            if item.pgid == current_sid {
                log::error!(
                    "Current sid {} intersects with pgid of ({}) in images",
                    current_sid,
                    vpid(item)
                );
                return -1;
            }
            if item.pgid == old_sid {
                item.pgid = current_sid;
            }
        }
    }

    // root_item is a group leader
    let root_pgid = store.get_item(root_idx).unwrap().pgid;
    let root_vpid = vpid(store.get_item(root_idx).unwrap());
    if root_pgid == root_vpid {
        // goto add_fake_session_leader
        if old_sid != current_sid && store.lookup_create_item(current_sid).is_none() {
            return -1;
        }
        return 0;
    }

    let old_gid = root_pgid;
    if old_gid != current_gid {
        log::info!(
            "Migrating process tree (GID {}->{:?})",
            old_gid,
            current_gid
        );

        let tmp = store.pstree_pid_by_virt(current_gid);
        if tmp.is_some() {
            let tmp_item = store.get_item(tmp.unwrap()).unwrap();
            log::error!(
                "Current gid {} intersects with pid ({:?}) in images",
                current_gid,
                tmp_item.pid.state
            );
            return -1;
        }

        for idx in 0..store.items.len() {
            let item = store.get_item_mut(idx).unwrap();
            if current_gid != current_sid && item.pgid == current_gid {
                log::error!(
                    "Current gid {} intersects with pgid of ({}) in images",
                    current_gid,
                    vpid(item)
                );
                return -1;
            }
            if item.pgid == old_gid {
                item.pgid = current_gid;
            }
        }
    }

    if old_gid != current_gid && store.lookup_create_item(current_gid).is_none() {
        return -1;
    }
    // add_fake_session_leader:
    if old_sid != current_sid && store.lookup_create_item(current_sid).is_none() {
        return -1;
    }
    0
}

pub fn prepare_pstree_kobj_ids(store: &mut PidStore) -> i32 {
    let root_idx = root_item_idx();

    for idx in 0..store.items.len() {
        let parent_idx = store.get_item(idx).unwrap().parent_idx;
        let item_ids = match store.get_item(idx).unwrap().ids.as_ref() {
            Some(ids) => ids.clone(),
            None => {
                if idx == root_idx {
                    log::error!("No IDS for root task.");
                    log::error!("Images corrupted or too old criu was used for dump.");
                    return -1;
                }
                continue;
            }
        };

        let parent_ids = if let Some(parent_idx) = parent_idx {
            match store.get_item(parent_idx).unwrap().ids.as_ref() {
                Some(ids) => ids.clone(),
                None => {
                    log::error!("No kIDs provided, image corruption");
                    return -1;
                }
            }
        } else {
            match root_ids() {
                Some(ids) => Box::new(ids.clone()),
                None => {
                    log::error!("No kIDs provided, image corruption");
                    return -1;
                }
            }
        };

        let cflags = get_clone_mask(&item_ids, &parent_ids);

        if cflags & libc::CLONE_FILES as u64 != 0 {
            /*
             * There might be a case when kIDs for
             * root task are the same as in root_ids,
             * thus it's image corruption and we should
             * exit out.
             */
            if parent_idx.is_none() {
                log::error!("Image corruption on kIDs data");
                return -1;
            }

            let ret = shared_fdt_prepare(store, idx);
            if ret != 0 {
                return ret;
            }
        }

        let item = store.get_item_mut(idx).unwrap();
        if let Some(rsti) = rsti_mut(item) {
            rsti.clone_flags = cflags;
            if parent_idx.is_some() {
                /*
                 * Mount namespaces are setns()-ed at
                 * restore_task_mnt_ns() explicitly,
                 * no need in creating it with its own
                 * temporary namespace.
                 *
                 * Root task is exceptional -- it will
                 * be born in a fresh new mount namespace
                 * which will be populated with all other
                 * namespaces' entries.
                 */
                rsti.clone_flags &= !(libc::CLONE_NEWNS as u64);
            }
        }

        // Only child reaper can clone with CLONE_NEWPID
        let item_vpid = vpid(store.get_item(idx).unwrap());
        if item_vpid != INIT_PID {
            let item = store.get_item_mut(idx).unwrap();
            if let Some(rsti) = rsti_mut(item) {
                rsti.clone_flags &= !(libc::CLONE_NEWPID as u64);
            }
        }

        let ns_cflags = cflags & CLONE_ALLNS;

        if idx == root_idx {
            log::info!("Will restore in {:x} namespaces", ns_cflags);
            let _ = set_root_ns_mask(ns_cflags);
        } else if ns_cflags & !(root_ns_mask_try().unwrap_or(0) & CLONE_SUBNS) != 0 {
            /*
             * Namespaces from CLONE_SUBNS can be nested, but in
             * this case nobody can't share external namespaces of
             * these types.
             *
             * Workaround for all other namespaces --
             * all tasks should be in one namespace. And
             * this namespace is either inherited from the
             * criu or is created for the init task (only)
             */
            log::error!("Can't restore sub-task in NS (cflags {:x})", ns_cflags);
            return -1;
        }
    }

    log::debug!("NS mask to use {:x}", root_ns_mask_try().unwrap_or(0));
    0
}

pub fn prepare_pstree_ids(store: &mut PidStore, pid: libc::pid_t) -> i32 {
    let current_pgid = unsafe { libc::getpgid(pid) };
    let root_idx = root_item_idx();

    let mut helpers: Vec<usize> = Vec::new();

    /*
     * Some task can be reparented to init. A helper task should be added
     * for restoring sid of such tasks. The helper tasks will be exited
     * immediately after forking children and all children will be
     * reparented to init.
     */
    let root_children: Vec<usize> = store.get_item(root_idx).unwrap().children.clone();
    let root_sid = store.get_item(root_idx).unwrap().sid;

    let mut i = 0;
    while i < root_children.len() {
        let item_idx = root_children[i];
        let item_sid = store.get_item(item_idx).unwrap().sid;
        let item_vpid = vpid(store.get_item(item_idx).unwrap());

        /*
         * If a child belongs to the root task's session or it's
         * a session leader himself -- this is a simple case, we
         * just proceed in a normal way.
         */
        if item_sid == root_sid || item_sid == item_vpid {
            i += 1;
            continue;
        }

        let leader_idx = match store.pstree_item_by_virt(item_sid) {
            Some(idx) => idx,
            None => {
                panic!("BUG: leader is NULL");
            }
        };
        let leader_state = store.get_item(leader_idx).unwrap().pid.state;

        let helper_idx = if leader_state != TaskState::Undef {
            let helper_pid = store.get_free_pid();
            if helper_pid < 0 {
                break;
            }
            match store.lookup_create_item(helper_pid) {
                Some(idx) => {
                    log::info!("Session leader {}", item_sid);

                    let leader_pgid = store.get_item(leader_idx).unwrap().pgid;
                    let leader_ids = store.get_item(leader_idx).unwrap().ids.clone();

                    let helper = store.get_item_mut(idx).unwrap();
                    helper.sid = item_sid;
                    helper.pgid = leader_pgid;
                    helper.ids = leader_ids;
                    helper.parent_idx = Some(leader_idx);

                    // Add helper to leader's children
                    let leader = store.get_item_mut(leader_idx).unwrap();
                    leader.children.push(idx);

                    let helper_vpid = vpid(store.get_item(idx).unwrap());
                    let leader_vpid = vpid(store.get_item(leader_idx).unwrap());
                    log::info!("Attach {} to the task {}", helper_vpid, leader_vpid);

                    idx
                }
                None => return -1,
            }
        } else {
            // Helper IS the leader
            let root_ids = store.get_item(root_idx).unwrap().ids.clone();
            let helper = store.get_item_mut(leader_idx).unwrap();
            helper.sid = item_sid;
            helper.pgid = item_sid;
            helper.parent_idx = Some(root_idx);
            helper.ids = root_ids;

            helpers.push(leader_idx);
            leader_idx
        };

        if init_pstree_helper(store.get_item_mut(helper_idx).unwrap()) != 0 {
            log::error!("Can't init helper");
            return -1;
        }

        let helper_vpid = vpid(store.get_item(helper_idx).unwrap());
        let helper_sid = store.get_item(helper_idx).unwrap().sid;
        log::info!("Add a helper {} for restoring SID {}", helper_vpid, helper_sid);

        /*
         * Stack on helper task all children with target sid.
         */
        // Note: This is simplified from C's list manipulation
        // We need to move children from root to helper
        let mut children_to_move = Vec::new();
        {
            let root = store.get_item(root_idx).unwrap();
            for &child_idx in &root.children {
                if child_idx == item_idx {
                    continue; // Skip the current item
                }
                let child = store.get_item(child_idx).unwrap();
                let child_sid = child.sid;
                let child_vpid_val = vpid(child);
                if child_sid != helper_sid {
                    continue;
                }
                if child_sid == child_vpid_val {
                    continue;
                }
                children_to_move.push(child_idx);
            }
        }

        for child_idx in children_to_move {
            let child_vpid_val = vpid(store.get_item(child_idx).unwrap());
            log::info!(
                "Attach {} to the temporary task {}",
                child_vpid_val,
                helper_vpid
            );

            store.get_item_mut(child_idx).unwrap().parent_idx = Some(helper_idx);

            // Remove from root's children
            let root = store.get_item_mut(root_idx).unwrap();
            root.children.retain(|&c| c != child_idx);

            // Add to helper's children
            let helper = store.get_item_mut(helper_idx).unwrap();
            helper.children.push(child_idx);
        }

        i += 1;
    }

    // Try to connect helpers to session leaders
    for idx in 0..store.items.len() {
        let item_parent_idx = store.get_item(idx).unwrap().parent_idx;
        if item_parent_idx.is_none() {
            continue; // skip the root task
        }

        let item_state = store.get_item(idx).unwrap().pid.state;
        if item_state == TaskState::Helper {
            continue;
        }

        let item_sid = store.get_item(idx).unwrap().sid;
        let item_vpid = vpid(store.get_item(idx).unwrap());
        if item_sid != item_vpid {
            let parent_sid = store.get_item(item_parent_idx.unwrap()).unwrap().sid;
            if parent_sid == item_sid {
                continue;
            }

            // the task could fork a child before and after setsid()
            let mut parent_idx = item_parent_idx;
            while let Some(p_idx) = parent_idx {
                let parent_vpid = vpid(store.get_item(p_idx).unwrap());
                if parent_vpid == item_sid {
                    break;
                }

                let parent = store.get_item_mut(p_idx).unwrap();
                if parent.born_sid != -1 && parent.born_sid != item_sid {
                    log::error!(
                        "Can't figure out which sid ({} or {}) the process {} was born with",
                        parent.born_sid,
                        item_sid,
                        parent_vpid
                    );
                    return -1;
                }
                parent.born_sid = item_sid;
                log::info!("{} was born with sid {}", parent_vpid, item_sid);
                parent_idx = parent.parent_idx;
            }

            if parent_idx.is_none() {
                log::error!("Can't find a session leader for {}", item_sid);
                return -1;
            }
        }
    }

    // All other helpers are session leaders for own sessions
    // Add helpers to root's children
    {
        let root = store.get_item_mut(root_idx).unwrap();
        for helper_idx in helpers {
            root.children.insert(0, helper_idx);
        }
    }

    // Add a process group leader if it is absent
    for idx in 0..store.items.len() {
        let item_pgid = store.get_item(idx).unwrap().pgid;
        let item_vpid = vpid(store.get_item(idx).unwrap());

        if item_pgid == 0 || item_vpid == item_pgid {
            continue;
        }

        let pgid_idx = store.pstree_pid_by_virt(item_pgid);
        let pgid_idx = match pgid_idx {
            Some(idx) => idx,
            None => continue,
        };

        let pgid_state = store.get_item(pgid_idx).unwrap().pid.state;
        if pgid_state != TaskState::Undef {
            assert!(
                pgid_state != TaskState::Thread,
                "BUG: pgid state is THREAD"
            );
            let item = store.get_item_mut(idx).unwrap();
            if let Some(rsti) = rsti_mut(item) {
                rsti.pgrp_leader_idx = Some(pgid_idx);
            }
            continue;
        }

        /*
         * If the PGID is eq to current one -- this
         * means we're inheriting group from the current
         * task so we need to escape creating a helper here.
         */
        if current_pgid == item_pgid {
            continue;
        }

        // Helper is pgid->item
        let helper_idx = pgid_idx;

        let item_sid = store.get_item(idx).unwrap().sid;
        let item_ids = store.get_item(idx).unwrap().ids.clone();

        {
            let helper = store.get_item_mut(helper_idx).unwrap();
            helper.sid = item_sid;
            helper.pgid = item_pgid;
            helper.pid.ns[0].virt = item_pgid;
            helper.parent_idx = Some(idx);
            helper.ids = item_ids;
        }

        if init_pstree_helper(store.get_item_mut(helper_idx).unwrap()) != 0 {
            log::error!("Can't init helper");
            return -1;
        }

        // Add to item's children
        store.get_item_mut(idx).unwrap().children.push(helper_idx);

        // Set pgrp_leader
        let item = store.get_item_mut(idx).unwrap();
        if let Some(rsti) = rsti_mut(item) {
            rsti.pgrp_leader_idx = Some(helper_idx);
        }

        let helper_vpid = vpid(store.get_item(helper_idx).unwrap());
        let helper_pgid = store.get_item(helper_idx).unwrap().pgid;
        log::info!(
            "Add a helper {} for restoring PGID {}",
            helper_vpid,
            helper_pgid
        );
    }

    0
}

pub fn prepare_pstree_rseqs(store: &mut PidStore) -> i32 {
    for idx in 0..store.items.len() {
        let item = store.get_item(idx).unwrap();
        if !task_alive(item) {
            continue;
        }

        let nr_threads = item.nr_threads as usize;
        let sz = std::mem::size_of::<RstRseq>() * nr_threads;

        let rseqs = shmalloc(sz);
        if rseqs.is_null() {
            log::error!("prepare_pstree_rseqs shmalloc({}) failed", sz);
            return -1;
        }

        // Zero the memory
        unsafe {
            std::ptr::write_bytes(rseqs as *mut u8, 0, sz);
        }

        let item = store.get_item_mut(idx).unwrap();
        if let Some(rsti) = rsti_mut(item) {
            rsti.rseqe = Some(unsafe { Box::from_raw(rseqs as *mut RstRseq) });
        }
    }

    0
}

pub fn prepare_pstree(store: &mut PidStore, dfd: RawFd) -> i32 {
    let mut pid_max: i32 = 0;
    let mut kpid_max: i32 = 0;

    // Read kernel pid_max
    const PID_MAX_PATH: &str = "/proc/sys/kernel/pid_max";
    if let Ok(contents) = std::fs::read_to_string(PID_MAX_PATH) {
        if let Ok(val) = contents.trim().parse::<i32>() {
            kpid_max = val;
            log::debug!("kernel pid_max={}", kpid_max);
        }
    }

    let ret = read_pstree_image(store, dfd, &mut pid_max);
    log::debug!("pstree pid_max={}", pid_max);

    if ret != 0 {
        return ret;
    }

    if kpid_max != 0 && pid_max > kpid_max {
        // Try to set kernel pid_max
        let new_pid_max = format!("{}", pid_max + 1);
        if std::fs::write(PID_MAX_PATH, &new_pid_max).is_err() {
            log::error!("Can't set kernel pid_max={}", new_pid_max);
            return -1;
        }
        log::info!("kernel pid_max pushed to {}", new_pid_max);
    }

    let pid = unsafe { libc::getpid() };

    /*
     * Shell job may inherit sid/pgid from the current
     * shell, not from image. Set things up for this.
     */
    if prepare_pstree_for_shell_job(store, pid) != 0 {
        return -1;
    }

    /*
     * Walk the collected tree and prepare for restoring
     * of shared objects at clone time
     */
    if prepare_pstree_kobj_ids(store) != 0 {
        return -1;
    }

    /*
     * Session/Group leaders might be dead. Need to fix
     * pstree with properly injected helper tasks.
     */
    if prepare_pstree_ids(store, pid) != 0 {
        return -1;
    }

    /*
     * We need to alloc shared buffers for RseqEntry'es
     * arrays (one RseqEntry per pstree item thread).
     *
     * We need shared memory because we perform
     * open_core() on the late stage inside
     * restore_one_alive_task(), so that's the only
     * way to transfer that data to the main CRIU process.
     */
    if prepare_pstree_rseqs(store) != 0 {
        return -1;
    }

    0
}

// =============================================================================
// Shared-Memory Pstree Support
// =============================================================================
//
// These structures support cross-fork access to pstree data. They are allocated
// via shmalloc (MAP_SHARED memory) and survive fork boundaries.

use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// Maximum number of children per task for shared memory storage
pub const MAX_SHARED_CHILDREN: usize = 64;

/// Shared-memory futex for cross-process synchronization
#[repr(C)]
pub struct SharedFutex {
    pub raw: AtomicU32,
}

impl SharedFutex {
    pub fn init(&self) {
        self.raw.store(0, Ordering::SeqCst);
    }

    pub fn get(&self) -> u32 {
        self.raw.load(Ordering::SeqCst)
    }

    pub fn set(&self, v: u32) {
        self.raw.store(v, Ordering::SeqCst);
    }

    pub fn set_and_wake(&self, v: u32) {
        self.set(v);
        self.wake();
    }

    pub fn wake(&self) {
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                &self.raw as *const AtomicU32,
                libc::FUTEX_WAKE,
                i32::MAX,
                std::ptr::null::<libc::timespec>(),
                std::ptr::null::<u32>(),
                0u32,
            );
        }
    }

    pub fn wait_until(&self, v: u32) {
        let timeout = libc::timespec {
            tv_sec: 120,
            tv_nsec: 0,
        };
        const FUTEX_ABORT_FLAG: u32 = 0x80000000;
        loop {
            let tmp = self.get();
            if (tmp & FUTEX_ABORT_FLAG) != 0 || tmp == v {
                break;
            }
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    &self.raw as *const AtomicU32,
                    libc::FUTEX_WAIT,
                    tmp as i32,
                    &timeout as *const libc::timespec,
                    std::ptr::null::<u32>(),
                    0u32,
                )
            };
            let errno = unsafe { *libc::__errno_location() };
            if ret == -1 && (errno == libc::ETIMEDOUT || errno == libc::EINTR || errno == libc::EWOULDBLOCK) {
                continue;
            }
            if ret == -1 {
                break;
            }
        }
    }

    pub fn abort_and_wake(&self) {
        const FUTEX_ABORT_FLAG: u32 = 0x80000000;
        self.raw.fetch_or(FUTEX_ABORT_FLAG, Ordering::SeqCst);
        self.wake();
    }
}

/// Shared-memory PID info
#[repr(C)]
pub struct SharedPid {
    pub virt: AtomicI32,
    pub real: AtomicI32,
    pub state: AtomicI32, // TaskState as i32
    pub stop_signo: AtomicI32,
}

impl SharedPid {
    pub fn init(&self) {
        self.virt.store(-1, Ordering::SeqCst);
        self.real.store(-1, Ordering::SeqCst);
        self.state.store(TaskState::Undef as i32, Ordering::SeqCst);
        self.stop_signo.store(-1, Ordering::SeqCst);
    }

    pub fn get_virt(&self) -> i32 {
        self.virt.load(Ordering::SeqCst)
    }

    pub fn set_virt(&self, v: i32) {
        self.virt.store(v, Ordering::SeqCst);
    }

    pub fn get_real(&self) -> i32 {
        self.real.load(Ordering::SeqCst)
    }

    pub fn set_real(&self, v: i32) {
        self.real.store(v, Ordering::SeqCst);
    }

    pub fn get_state(&self) -> TaskState {
        TaskState::from(self.state.load(Ordering::SeqCst))
    }

    pub fn set_state(&self, s: TaskState) {
        self.state.store(s as i32, Ordering::SeqCst);
    }
}

/// Shared-memory restore info (subset needed for fork operations)
#[repr(C)]
pub struct SharedRstInfo {
    pub clone_flags: AtomicU64,
    pub cg_set: AtomicU32,
    pub service_fd_id: AtomicI32,
    pub has_seccomp: AtomicU32, // bool as u32
    pub munmap_restorer: AtomicU64,
    pub breakpoint: AtomicU64,
    pub pgrp_leader_idx: AtomicI32, // -1 if none
    pub pgrp_set: SharedFutex,
    pub shstk_enable: SharedFutex,
    pub shstk_unlock: SharedFutex,
}

impl SharedRstInfo {
    pub fn init(&self) {
        self.clone_flags.store(0, Ordering::SeqCst);
        self.cg_set.store(0, Ordering::SeqCst);
        self.service_fd_id.store(0, Ordering::SeqCst);
        self.has_seccomp.store(0, Ordering::SeqCst);
        self.munmap_restorer.store(0, Ordering::SeqCst);
        self.breakpoint.store(0, Ordering::SeqCst);
        self.pgrp_leader_idx.store(-1, Ordering::SeqCst);
        self.pgrp_set.init();
        self.shstk_enable.init();
        self.shstk_unlock.init();
    }
}

/// Shared-memory pstree item
#[repr(C)]
pub struct SharedPstreeItem {
    pub idx: AtomicI32,
    pub parent_idx: AtomicI32, // -1 if root
    pub pid: SharedPid,
    pub pgid: AtomicI32,
    pub sid: AtomicI32,
    pub born_sid: AtomicI32,
    pub nr_threads: AtomicI32,
    pub nr_children: AtomicI32,
    pub children: [AtomicI32; MAX_SHARED_CHILDREN], // indices of children
    pub rst: SharedRstInfo,
    pub task_st: SharedFutex,
}

impl SharedPstreeItem {
    pub fn init(&self, idx: i32) {
        self.idx.store(idx, Ordering::SeqCst);
        self.parent_idx.store(-1, Ordering::SeqCst);
        self.pid.init();
        self.pgid.store(0, Ordering::SeqCst);
        self.sid.store(0, Ordering::SeqCst);
        self.born_sid.store(-1, Ordering::SeqCst);
        self.nr_threads.store(0, Ordering::SeqCst);
        self.nr_children.store(0, Ordering::SeqCst);
        for c in &self.children {
            c.store(-1, Ordering::SeqCst);
        }
        self.rst.init();
        self.task_st.init();
    }

    pub fn get_child(&self, i: usize) -> Option<i32> {
        if i >= MAX_SHARED_CHILDREN {
            return None;
        }
        let idx = self.children[i].load(Ordering::SeqCst);
        if idx < 0 {
            None
        } else {
            Some(idx)
        }
    }

    pub fn add_child(&self, child_idx: i32) -> bool {
        let nr = self.nr_children.load(Ordering::SeqCst) as usize;
        if nr >= MAX_SHARED_CHILDREN {
            return false;
        }
        self.children[nr].store(child_idx, Ordering::SeqCst);
        self.nr_children.fetch_add(1, Ordering::SeqCst);
        true
    }

    pub fn vpid(&self) -> i32 {
        self.pid.get_virt()
    }

    pub fn is_alive(&self) -> bool {
        matches!(self.pid.get_state(), TaskState::Alive | TaskState::Stopped)
    }
}

/// Maximum number of shared pstree items
pub const MAX_SHARED_ITEMS: usize = 4096;

/// Header for shared pstree storage
#[repr(C)]
pub struct SharedPstreeHeader {
    pub count: AtomicI32,
    pub root_idx: AtomicI32,
}

/// Global pointer to current shared pstree item (set after fork)
static mut CURRENT_SHARED: *mut SharedPstreeItem = std::ptr::null_mut();

/// Get the current shared pstree item
pub fn current_shared() -> Option<&'static SharedPstreeItem> {
    unsafe {
        if CURRENT_SHARED.is_null() {
            None
        } else {
            Some(&*CURRENT_SHARED)
        }
    }
}

/// Get mutable reference to current shared pstree item
pub fn current_shared_mut() -> Option<&'static mut SharedPstreeItem> {
    unsafe {
        if CURRENT_SHARED.is_null() {
            None
        } else {
            Some(&mut *CURRENT_SHARED)
        }
    }
}

/// Set the current shared pstree item
pub fn set_current_shared(item: *mut SharedPstreeItem) {
    unsafe {
        CURRENT_SHARED = item;
    }
}

/// Global pointer to shared pstree store
static mut SHARED_STORE: *mut SharedPstreeStore = std::ptr::null_mut();

/// Shared pstree store - lives in shared memory
#[repr(C)]
pub struct SharedPstreeStore {
    pub header: SharedPstreeHeader,
    pub items: [SharedPstreeItem; MAX_SHARED_ITEMS],
}

impl SharedPstreeStore {
    /// Allocate a new shared pstree store in shared memory
    pub fn alloc() -> *mut Self {
        let size = std::mem::size_of::<Self>();
        let ptr = shmalloc(size) as *mut Self;
        if ptr.is_null() {
            return std::ptr::null_mut();
        }

        // Initialize header
        unsafe {
            (*ptr).header.count.store(0, Ordering::SeqCst);
            (*ptr).header.root_idx.store(-1, Ordering::SeqCst);
        }

        ptr
    }

    /// Allocate a new item in the store
    pub fn alloc_item(&self) -> Option<i32> {
        let idx = self.header.count.fetch_add(1, Ordering::SeqCst);
        if idx as usize >= MAX_SHARED_ITEMS {
            self.header.count.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        self.items[idx as usize].init(idx);
        Some(idx)
    }

    /// Get item by index
    pub fn get_item(&self, idx: i32) -> Option<&SharedPstreeItem> {
        if idx < 0 || idx as usize >= MAX_SHARED_ITEMS {
            return None;
        }
        let count = self.header.count.load(Ordering::SeqCst);
        if idx >= count {
            return None;
        }
        Some(&self.items[idx as usize])
    }

    /// Get mutable item by index
    pub fn get_item_mut(&mut self, idx: i32) -> Option<&mut SharedPstreeItem> {
        if idx < 0 || idx as usize >= MAX_SHARED_ITEMS {
            return None;
        }
        let count = self.header.count.load(Ordering::SeqCst);
        if idx >= count {
            return None;
        }
        Some(&mut self.items[idx as usize])
    }

    /// Get item count
    pub fn items_count(&self) -> i32 {
        self.header.count.load(Ordering::SeqCst)
    }

    /// Set root item index
    pub fn set_root(&self, idx: i32) {
        self.header.root_idx.store(idx, Ordering::SeqCst);
    }

    /// Get root item index
    pub fn get_root(&self) -> i32 {
        self.header.root_idx.load(Ordering::SeqCst)
    }
}

/// Initialize the global shared pstree store
pub fn init_shared_pstree() -> Result<(), ()> {
    let store = SharedPstreeStore::alloc();
    if store.is_null() {
        return Err(());
    }
    unsafe {
        SHARED_STORE = store;
    }
    Ok(())
}

/// Get the global shared pstree store
pub fn shared_store() -> Option<&'static SharedPstreeStore> {
    unsafe {
        if SHARED_STORE.is_null() {
            None
        } else {
            Some(&*SHARED_STORE)
        }
    }
}

/// Get mutable reference to the global shared pstree store
pub fn shared_store_mut() -> Option<&'static mut SharedPstreeStore> {
    unsafe {
        if SHARED_STORE.is_null() {
            None
        } else {
            Some(&mut *SHARED_STORE)
        }
    }
}

/// Copy a PstreeItem to SharedPstreeItem
pub fn copy_to_shared(store: &PidStore, shared_store: &mut SharedPstreeStore) -> Result<(), ()> {
    let count = store.items_count();

    for idx in 0..count {
        let item = match store.get_item(idx) {
            Some(i) => i,
            None => continue,
        };

        let shared_idx = match shared_store.alloc_item() {
            Some(i) => i,
            None => return Err(()),
        };

        let shared = match shared_store.get_item_mut(shared_idx) {
            Some(s) => s,
            None => return Err(()),
        };

        // Copy basic fields
        shared.pid.set_virt(vpid(item));
        shared.pid.set_real(item.pid.real);
        shared.pid.set_state(item.pid.state);
        shared.pid.stop_signo.store(item.pid.stop_signo, Ordering::SeqCst);

        shared.pgid.store(item.pgid, Ordering::SeqCst);
        shared.sid.store(item.sid, Ordering::SeqCst);
        shared.born_sid.store(item.born_sid, Ordering::SeqCst);
        shared.nr_threads.store(item.nr_threads, Ordering::SeqCst);

        // Copy parent index
        if let Some(parent_idx) = item.parent_idx {
            shared.parent_idx.store(parent_idx as i32, Ordering::SeqCst);
        } else {
            shared.parent_idx.store(-1, Ordering::SeqCst);
        }

        // Copy children indices
        shared.nr_children.store(item.children.len() as i32, Ordering::SeqCst);
        for (i, &child_idx) in item.children.iter().enumerate() {
            if i >= MAX_SHARED_CHILDREN {
                break;
            }
            shared.children[i].store(child_idx as i32, Ordering::SeqCst);
        }

        // Copy restore info
        if let Some(rst) = rsti(item) {
            shared.rst.clone_flags.store(rst.clone_flags, Ordering::SeqCst);
            shared.rst.cg_set.store(rst.cg_set, Ordering::SeqCst);
            shared.rst.service_fd_id.store(rst.service_fd_id, Ordering::SeqCst);
            shared.rst.has_seccomp.store(if rst.has_seccomp { 1 } else { 0 }, Ordering::SeqCst);
            shared.rst.munmap_restorer.store(rst.munmap_restorer, Ordering::SeqCst);
            shared.rst.breakpoint.store(rst.breakpoint, Ordering::SeqCst);
            if let Some(pgrp_idx) = rst.pgrp_leader_idx {
                shared.rst.pgrp_leader_idx.store(pgrp_idx as i32, Ordering::SeqCst);
            }
        }

        // Set root if this is the root item
        if root_item_idx_try() == Some(idx) {
            shared_store.set_root(shared_idx);
        }
    }

    Ok(())
}

/// Sync real PIDs from shared store back to PidStore
pub fn sync_from_shared(store: &mut PidStore, shared_store: &SharedPstreeStore) {
    let count = shared_store.items_count();

    for idx in 0..count {
        let shared = match shared_store.get_item(idx) {
            Some(s) => s,
            None => continue,
        };

        if let Some(item) = store.get_item_mut(idx as usize) {
            // Sync real PID (updated by forked children)
            item.pid.real = shared.pid.get_real();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_pstree_item_restore() {
        let item = alloc_pstree_item(true);

        assert!(matches!(item.mode_info, Some(ModeInfo::Restore(_))));
        assert_eq!(item.pid.ns[0].virt, -1);
        assert_eq!(item.pid.real, -1);
        assert_eq!(item.pid.state, TaskState::Undef);
        assert_eq!(item.pid.stop_signo, -1);
        assert_eq!(item.born_sid, -1);
    }

    #[test]
    fn test_alloc_pstree_item_dump() {
        let item = alloc_pstree_item(false);

        assert!(matches!(item.mode_info, Some(ModeInfo::Dump(_))));
        assert_eq!(item.pid.ns[0].virt, -1);
        assert_eq!(item.pid.real, -1);
    }

    #[test]
    fn test_rsti_accessor() {
        let item = alloc_pstree_item(true);
        let rst = rsti(&item);
        assert!(rst.is_some());
    }

    #[test]
    fn test_dmpi_accessor() {
        let item = alloc_pstree_item(false);
        let dmp = dmpi(&item);
        assert!(dmp.is_some());
    }

    #[test]
    fn test_task_state_from_i32() {
        assert_eq!(TaskState::from(0x1), TaskState::Alive);
        assert_eq!(TaskState::from(0x2), TaskState::Dead);
        assert_eq!(TaskState::from(0xff), TaskState::Undef);
        assert_eq!(TaskState::from(999), TaskState::Undef);
    }

    #[test]
    fn test_pid_store_new() {
        let store = PidStore::new();
        assert!(store.pid_root.is_empty());
        assert!(store.items.is_empty());
    }

    #[test]
    fn test_lookup_create_pid_creates_new() {
        let mut store = PidStore::new();

        let idx = store.lookup_create_pid(100, None);
        assert!(idx.is_some());
        let idx = idx.unwrap();

        let item = store.get_item(idx).unwrap();
        assert_eq!(item.pid.ns[0].virt, 100);
    }

    #[test]
    fn test_lookup_create_pid_finds_existing() {
        let mut store = PidStore::new();

        let idx1 = store.lookup_create_pid(100, None).unwrap();
        let idx2 = store.lookup_create_pid(100, None).unwrap();

        assert_eq!(idx1, idx2);
        assert_eq!(store.items.len(), 1);
    }

    #[test]
    fn test_lookup_create_pid_multiple_pids() {
        let mut store = PidStore::new();

        let idx1 = store.lookup_create_pid(100, None).unwrap();
        let idx2 = store.lookup_create_pid(50, None).unwrap();
        let idx3 = store.lookup_create_pid(150, None).unwrap();

        assert_ne!(idx1, idx2);
        assert_ne!(idx2, idx3);
        assert_ne!(idx1, idx3);
        assert_eq!(store.items.len(), 3);

        assert_eq!(store.get_item(idx1).unwrap().pid.ns[0].virt, 100);
        assert_eq!(store.get_item(idx2).unwrap().pid.ns[0].virt, 50);
        assert_eq!(store.get_item(idx3).unwrap().pid.ns[0].virt, 150);
    }

    #[test]
    fn test_lookup_create_pid_sorted_order() {
        let mut store = PidStore::new();

        for pid in [50, 25, 75, 10, 30, 60, 90] {
            store.lookup_create_pid(pid, None);
        }

        assert_eq!(store.items.len(), 7);

        let idx_50 = store.lookup_create_pid(50, None).unwrap();
        let idx_25 = store.lookup_create_pid(25, None).unwrap();
        let idx_75 = store.lookup_create_pid(75, None).unwrap();

        assert_eq!(store.get_item(idx_50).unwrap().pid.ns[0].virt, 50);
        assert_eq!(store.get_item(idx_25).unwrap().pid.ns[0].virt, 25);
        assert_eq!(store.get_item(idx_75).unwrap().pid.ns[0].virt, 75);
    }

    #[test]
    fn test_pstree_pid_by_virt_found() {
        let mut store = PidStore::new();
        store.lookup_create_pid(100, None);
        store.lookup_create_pid(50, None);
        store.lookup_create_pid(150, None);

        let idx = store.pstree_pid_by_virt(50);
        assert!(idx.is_some());
        assert_eq!(store.get_item(idx.unwrap()).unwrap().pid.ns[0].virt, 50);
    }

    #[test]
    fn test_pstree_pid_by_virt_not_found() {
        let mut store = PidStore::new();
        store.lookup_create_pid(100, None);

        let idx = store.pstree_pid_by_virt(999);
        assert!(idx.is_none());
    }

    #[test]
    fn test_pstree_pid_by_virt_empty_tree() {
        let store = PidStore::new();
        let idx = store.pstree_pid_by_virt(100);
        assert!(idx.is_none());
    }

    #[test]
    fn test_lookup_create_item() {
        let mut store = PidStore::new();

        let idx = store.lookup_create_item(100);
        assert!(idx.is_some());
        assert_eq!(store.get_item(idx.unwrap()).unwrap().pid.ns[0].virt, 100);
    }

    #[test]
    #[should_panic(expected = "BUG: lookup_create_item called on thread")]
    fn test_lookup_create_item_thread_panics() {
        let mut store = PidStore::new();
        let idx = store.lookup_create_pid(100, None).unwrap();
        store.get_item_mut(idx).unwrap().pid.state = TaskState::Thread;
        store.lookup_create_item(100);
    }

    #[test]
    fn test_pstree_item_by_virt_found() {
        let mut store = PidStore::new();
        store.lookup_create_pid(100, None);
        store.lookup_create_pid(50, None);

        let idx = store.pstree_item_by_virt(50);
        assert!(idx.is_some());
        assert_eq!(store.get_item(idx.unwrap()).unwrap().pid.ns[0].virt, 50);
    }

    #[test]
    fn test_pstree_item_by_virt_not_found() {
        let mut store = PidStore::new();
        store.lookup_create_pid(100, None);

        let idx = store.pstree_item_by_virt(999);
        assert!(idx.is_none());
    }

    #[test]
    #[should_panic(expected = "BUG: pstree_item_by_virt called on thread")]
    fn test_pstree_item_by_virt_thread_panics() {
        let mut store = PidStore::new();
        let idx = store.lookup_create_pid(100, None).unwrap();
        store.get_item_mut(idx).unwrap().pid.state = TaskState::Thread;
        store.pstree_item_by_virt(100);
    }

    #[test]
    fn test_get_clone_mask_same_namespaces() {
        let item = TaskKobjIdsEntry {
            vm_id: 1,
            files_id: 2,
            fs_id: 3,
            sighand_id: 4,
            pid_ns_id: Some(5),
            net_ns_id: Some(6),
            ipc_ns_id: Some(7),
            uts_ns_id: Some(8),
            mnt_ns_id: Some(9),
            user_ns_id: Some(10),
            cgroup_ns_id: None,
            time_ns_id: Some(11),
        };
        let parent = item.clone();

        let mask = get_clone_mask(&item, &parent);
        assert_eq!(mask, libc::CLONE_FILES as u64);
    }

    #[test]
    fn test_get_clone_mask_different_namespaces() {
        let item = TaskKobjIdsEntry {
            vm_id: 1,
            files_id: 2,
            fs_id: 3,
            sighand_id: 4,
            pid_ns_id: Some(100),
            net_ns_id: Some(101),
            ipc_ns_id: Some(7),
            uts_ns_id: Some(8),
            mnt_ns_id: Some(9),
            user_ns_id: Some(10),
            cgroup_ns_id: None,
            time_ns_id: Some(11),
        };
        let parent = TaskKobjIdsEntry {
            vm_id: 1,
            files_id: 2,
            fs_id: 3,
            sighand_id: 4,
            pid_ns_id: Some(5),
            net_ns_id: Some(6),
            ipc_ns_id: Some(7),
            uts_ns_id: Some(8),
            mnt_ns_id: Some(9),
            user_ns_id: Some(10),
            cgroup_ns_id: None,
            time_ns_id: Some(11),
        };

        let mask = get_clone_mask(&item, &parent);
        assert!(mask & libc::CLONE_FILES as u64 != 0);
        assert!(mask & libc::CLONE_NEWPID as u64 != 0);
        assert!(mask & libc::CLONE_NEWNET as u64 != 0);
        assert!(mask & libc::CLONE_NEWIPC as u64 == 0);
    }

    #[test]
    fn test_get_clone_mask_different_files() {
        let item = TaskKobjIdsEntry {
            vm_id: 1,
            files_id: 999,
            fs_id: 3,
            sighand_id: 4,
            pid_ns_id: Some(5),
            net_ns_id: Some(6),
            ipc_ns_id: Some(7),
            uts_ns_id: Some(8),
            mnt_ns_id: Some(9),
            user_ns_id: Some(10),
            cgroup_ns_id: None,
            time_ns_id: Some(11),
        };
        let parent = TaskKobjIdsEntry {
            vm_id: 1,
            files_id: 2,
            fs_id: 3,
            sighand_id: 4,
            pid_ns_id: Some(5),
            net_ns_id: Some(6),
            ipc_ns_id: Some(7),
            uts_ns_id: Some(8),
            mnt_ns_id: Some(9),
            user_ns_id: Some(10),
            cgroup_ns_id: None,
            time_ns_id: Some(11),
        };

        let mask = get_clone_mask(&item, &parent);
        assert!(mask & libc::CLONE_FILES as u64 == 0);
    }

    #[test]
    fn test_get_free_pid_empty_tree() {
        let store = PidStore::new();
        let pid = store.get_free_pid();
        assert_eq!(pid, -1);
    }

    #[test]
    fn test_get_free_pid_single_pid() {
        let mut store = PidStore::new();
        store.lookup_create_pid(400, None);

        let pid = store.get_free_pid();
        assert_eq!(pid, 401);
    }

    #[test]
    fn test_get_free_pid_gap_in_sequence() {
        let mut store = PidStore::new();
        // Create PIDs 400, 401, 403 (gap at 402)
        store.lookup_create_pid(400, None);
        store.lookup_create_pid(401, None);
        store.lookup_create_pid(403, None);

        let pid = store.get_free_pid();
        assert_eq!(pid, 402);
    }

    #[test]
    fn test_get_free_pid_continuous_sequence() {
        let mut store = PidStore::new();
        // Create continuous sequence 400-404
        for p in 400..=404 {
            store.lookup_create_pid(p, None);
        }

        let pid = store.get_free_pid();
        assert_eq!(pid, 405);
    }

    #[test]
    fn test_get_free_pid_skips_reserved() {
        let mut store = PidStore::new();
        // Create PID 100 which is below RESERVED_PIDS (300)
        store.lookup_create_pid(100, None);

        // Should skip to RESERVED_PIDS + 1 = 301
        let pid = store.get_free_pid();
        assert_eq!(pid, RESERVED_PIDS + 1);
    }

    #[test]
    fn test_get_free_pid_multiple_gaps() {
        let mut store = PidStore::new();
        // Create PIDs with gaps: 400, 402, 405
        store.lookup_create_pid(400, None);
        store.lookup_create_pid(402, None);
        store.lookup_create_pid(405, None);

        // Should find first gap (401)
        let pid = store.get_free_pid();
        assert_eq!(pid, 401);
    }

    #[test]
    fn test_vpid() {
        let mut item = alloc_pstree_item(true);
        item.pid.ns[0].virt = 1234;
        assert_eq!(vpid(&item), 1234);
    }

    #[test]
    fn test_is_alive_state() {
        assert!(is_alive_state(TaskState::Alive));
        assert!(is_alive_state(TaskState::Stopped));
        assert!(!is_alive_state(TaskState::Dead));
        assert!(!is_alive_state(TaskState::Helper));
        assert!(!is_alive_state(TaskState::Thread));
        assert!(!is_alive_state(TaskState::Undef));
    }

    #[test]
    fn test_task_alive() {
        let mut item = alloc_pstree_item(true);

        item.pid.state = TaskState::Alive;
        assert!(task_alive(&item));

        item.pid.state = TaskState::Stopped;
        assert!(task_alive(&item));

        item.pid.state = TaskState::Dead;
        assert!(!task_alive(&item));

        item.pid.state = TaskState::Helper;
        assert!(!task_alive(&item));
    }

    #[test]
    fn test_task_dead() {
        let mut item = alloc_pstree_item(true);

        item.pid.state = TaskState::Dead;
        assert!(task_dead(&item));

        item.pid.state = TaskState::Alive;
        assert!(!task_dead(&item));
    }

    #[test]
    fn test_pid_rst_prio() {
        assert!(pid_rst_prio(100, 200));
        assert!(!pid_rst_prio(200, 100));
        assert!(!pid_rst_prio(100, 100));
    }

    #[test]
    fn test_pid_rst_prio_eq() {
        assert!(pid_rst_prio_eq(100, 200));
        assert!(!pid_rst_prio_eq(200, 100));
        assert!(pid_rst_prio_eq(100, 100));
    }
}
