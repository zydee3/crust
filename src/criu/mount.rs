use std::cell::UnsafeCell;
use std::ffi::{c_void, CString};
use std::os::unix::io::RawFd;
use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock};

use crate::criu::clone::clone_noasan;
use crate::criu::external::{external_lookup_by_key, External, ExternalLookupResult};
use crate::criu::image::{close_image, open_image};
use crate::criu::image_desc::CrFdType;
use crate::criu::namespaces::{NsId, NsIdData};
use crate::criu::options::opts;
use crate::criu::protobuf::pb_read_one_eof;
use crate::criu::task_entries::{lock_last_pid, unlock_last_pid};
use crate::criu::util::is_sub_path;
use crate::proto::MntEntry;

static ROOT_MNT_NS_ID: OnceLock<u32> = OnceLock::new();
static MNT_ROOTS: Mutex<Option<String>> = Mutex::new(None);
static ROOT_YARD_MP: Mutex<Option<usize>> = Mutex::new(None);

pub const HELPER_MNT_ID: i32 = 0;

pub fn set_root_mnt_ns_id(id: u32) -> Result<(), u32> {
    ROOT_MNT_NS_ID.set(id)
}

pub fn root_mnt_ns_id() -> u32 {
    *ROOT_MNT_NS_ID.get().expect("root_mnt_ns_id not initialized")
}

pub fn root_mnt_ns_id_try() -> Option<u32> {
    ROOT_MNT_NS_ID.get().copied()
}

pub fn mnt_roots() -> Option<String> {
    MNT_ROOTS.lock().ok()?.clone()
}

pub fn create_mnt_roots() -> Result<(), i32> {
    let mut guard = MNT_ROOTS.lock().map_err(|_| -1)?;

    if guard.is_some() {
        return Ok(());
    }

    let template = CString::new("/tmp/.criu.mntns.XXXXXX").map_err(|_| -1)?;
    let mut buf = template.into_bytes_with_nul();

    let result = unsafe { libc::mkdtemp(buf.as_mut_ptr() as *mut libc::c_char) };

    if result.is_null() {
        log::error!("Unable to create a temporary directory");
        return Err(-1);
    }

    buf.pop();
    let path = String::from_utf8(buf).map_err(|_| -1)?;

    let path_cstr = CString::new(path.as_str()).map_err(|_| -1)?;
    unsafe {
        libc::chmod(path_cstr.as_ptr(), 0o777);
    }

    *guard = Some(path);
    Ok(())
}

pub fn cleanup_mnt_ns() {
    let guard = match MNT_ROOTS.lock() {
        Ok(g) => g,
        Err(_) => return,
    };

    if let Some(ref path) = *guard {
        let path_cstr = match CString::new(path.as_str()) {
            Ok(c) => c,
            Err(_) => return,
        };
        if unsafe { libc::rmdir(path_cstr.as_ptr()) } != 0 {
            log::error!("Can't remove the directory {}", path);
        }
    }
}

/*
 * Don't exit after a first error, because this function
 * can be used to rollback in a error case.
 * Don't worry about MNT_DETACH, because files are restored after this
 * and nobody will not be restored from a wrong mount namespace.
 */
pub fn __depopulate_roots_yard() -> i32 {
    let guard = match MNT_ROOTS.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    let path = match *guard {
        Some(ref p) => p.clone(),
        None => return 0,
    };

    let path_cstr = match CString::new(path.as_str()) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    let none_cstr = CString::new("none").unwrap();

    let mut ret = 0;

    if unsafe {
        libc::mount(
            none_cstr.as_ptr(),
            path_cstr.as_ptr(),
            none_cstr.as_ptr(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        log::error!("Can't remount root with MS_PRIVATE");
        ret = 1;
    }

    if unsafe { libc::umount2(path_cstr.as_ptr(), libc::MNT_DETACH) } != 0 {
        log::error!("Can't unmount {}", path);
        ret = -1;
    }

    if unsafe { libc::rmdir(path_cstr.as_ptr()) } != 0 {
        log::error!("Can't remove the directory {}", path);
        ret = -1;
    }

    ret
}

pub fn depopulate_roots_yard(
    mntns_fd: RawFd,
    only_ghosts: bool,
    store: &MountInfoStore,
    mntns_compat_mode: bool,
) -> i32 {
    use crate::criu::files_reg::try_clean_remaps;

    let mut ret = 0;

    if mntns_fd < 0 {
        ret |= try_clean_remaps(store, mntns_compat_mode, only_ghosts);
        cleanup_mnt_ns();
        return ret;
    }

    log::info!("Switching to new ns to clean ghosts");

    let dot_cstr = CString::new(".").unwrap();
    let old_cwd = unsafe { libc::open(dot_cstr.as_ptr(), libc::O_PATH) };
    if old_cwd < 0 {
        log::error!("Unable to open cwd");
        return -1;
    }

    let ns_path = CString::new("/proc/self/ns/mnt").unwrap();
    let old_ns = unsafe { libc::open(ns_path.as_ptr(), libc::O_RDONLY) };
    if old_ns < 0 {
        log::error!("Can't keep old ns");
        unsafe { libc::close(old_cwd) };
        return -1;
    }

    if unsafe { libc::setns(mntns_fd, libc::CLONE_NEWNS) } < 0 {
        log::error!("Can't switch");
        unsafe {
            libc::close(old_ns);
            libc::close(old_cwd);
        }
        return -1;
    }

    if try_clean_remaps(store, mntns_compat_mode, only_ghosts) != 0 {
        ret = -1;
    }

    if __depopulate_roots_yard() != 0 {
        ret = -1;
    }

    if unsafe { libc::setns(old_ns, libc::CLONE_NEWNS) } < 0 {
        log::error!("Fail to switch back!");
        ret = -1;
    }
    unsafe { libc::close(old_ns) };

    if unsafe { libc::fchdir(old_cwd) } != 0 {
        log::error!("Unable to restore cwd");
        ret = -1;
    }
    unsafe { libc::close(old_cwd) };

    ret
}

pub fn mntns_maybe_create_roots(root_ns_mask: u64) -> Result<(), i32> {
    if root_ns_mask & libc::CLONE_NEWNS as u64 == 0 {
        return Ok(());
    }
    create_mnt_roots()
}

pub fn call_helper_process<F>(call: F, arg: *mut c_void) -> i32
where
    F: FnOnce(*mut c_void) -> i32,
{
    let mut exit_code = -1;

    /*
     * Running new helper process on the restore must be
     * done under last_pid mutex: other tasks may be restoring
     * threads and the PID we need there might be occupied by
     * this clone() call.
     */
    lock_last_pid();

    let pid = clone_noasan(
        call,
        libc::CLONE_VFORK | libc::CLONE_VM | libc::CLONE_FILES | libc::CLONE_IO | libc::CLONE_SIGHAND | libc::CLONE_SYSVSEM,
        arg,
    );
    if pid == -1 {
        log::error!("Can't clone helper process: {}", std::io::Error::last_os_error());
        unlock_last_pid();
        return exit_code;
    }

    let mut status: i32 = 0;
    unsafe {
        *libc::__errno_location() = 0;
    }
    let ret = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
    if ret != pid {
        log::error!("Unable to wait {}: {}", pid, std::io::Error::last_os_error());
        unlock_last_pid();
        return exit_code;
    }

    if status != 0 {
        log::error!("Bad child exit status: {}", status);
        unlock_last_pid();
        return exit_code;
    }

    exit_code = 0;
    unlock_last_pid();
    exit_code
}

pub fn try_remount_writable(
    store: &MountInfoStore,
    mi_idx: usize,
    ns: bool,
    root_ns_mask: u64,
) -> i32 {
    let remounted = if ns { REMOUNTED_RW } else { REMOUNTED_RW_SERVICE };

    /* Don't remount if we are in host mntns to be on the safe side */
    if root_ns_mask & libc::CLONE_NEWNS as u64 == 0 {
        return 0;
    }

    let mi = match store.get(mi_idx) {
        Some(m) => m,
        None => return -1,
    };

    let mi_flags = mi.flags as u64;
    let mi_sb_flags = mi.sb_flags as u64;
    let mi_mnt_id = mi.mnt_id;
    let current_remounted_rw = mi.remounted_rw;

    if (mi_flags & libc::MS_RDONLY) != 0 && (current_remounted_rw & remounted) == 0 {
        if store.mnt_is_overmounted(mi_idx) {
            log::error!("The mount {} is overmounted so paths are invisible", mi_mnt_id);
            return -1;
        }

        /* There should be no ghost files on mounts with ro sb */
        if (mi_sb_flags & libc::MS_RDONLY) != 0 {
            log::error!("The mount {} has readonly sb", mi_mnt_id);
            return -1;
        }

        let mp = service_mountpoint(mi, false, true);
        log::info!("Remount {}:{} writable", mi_mnt_id, mp.unwrap_or(""));

        if !ns {
            let mp_cstr = match mp.and_then(|s| CString::new(s).ok()) {
                Some(c) => c,
                None => return -1,
            };

            let mount_flags = libc::MS_REMOUNT | libc::MS_BIND | (mi_flags & !(MS_PROPAGATE | libc::MS_RDONLY));
            let ret = unsafe {
                libc::mount(
                    std::ptr::null(),
                    mp_cstr.as_ptr(),
                    std::ptr::null(),
                    mount_flags,
                    std::ptr::null(),
                )
            };
            if ret == -1 {
                log::error!(
                    "Failed to remount {}:{} writable: {}",
                    mi_mnt_id,
                    mp.unwrap_or(""),
                    std::io::Error::last_os_error()
                );
                return -1;
            }
        } else {
            // ns=true case: would call ns_remount_writable via call_helper_process
            // This requires namespace switching infrastructure not yet fully implemented
            log::error!("ns_remount_writable not yet implemented");
            return -1;
        }

        // Update remounted_rw - need mutable access
        // Note: In CRIU this updates mi->rmi->remounted_rw, we update mi.remounted_rw
        // This requires unsafe access to update the mount info
    }

    0
}

pub const PATH_MAX: usize = 4096;
pub const EXTERNAL_DEV_MOUNT: &str = "CRIU:EXTERNAL_DEV";
pub const NO_ROOT_MOUNT: &str = ".";
pub const AUTODETECTED_MOUNT: &str = "CRIU:AUTODETECTED";
pub const REMOUNTED_RW: i32 = 1;
pub const REMOUNTED_RW_SERVICE: i32 = 2;
pub const MS_PROPAGATE: u64 = libc::MS_SHARED | libc::MS_PRIVATE | libc::MS_UNBINDABLE | libc::MS_SLAVE;
const CONTEXT_OPT: &str = "context=";

/*
 * If the user specified a different mount_context we need
 * to replace the existing mount context in the mount
 * options with the one specified by the user.
 *
 * The original mount options will be something like:
 *
 *  context="system_u:object_r:container_file_t:s0:c82,c137",inode64
 *
 * and it needs to be replaced with opts.lsm_mount_context.
 *
 * The content between 'context=' and ',inode64' will be replaced
 * with opts.lsm_mount_context in quotes.
 */
pub fn mount_update_lsm_context(mount_opts: &str, lsm_mount_context: Option<&str>) -> Option<String> {
    let context_pos = match mount_opts.find(CONTEXT_OPT) {
        Some(pos) => pos,
        None => return Some(mount_opts.to_string()),
    };

    let new_context = match lsm_mount_context {
        Some(ctx) => ctx,
        None => return Some(mount_opts.to_string()),
    };

    /* Skip 'context=' */
    let context_start_pos = context_pos + CONTEXT_OPT.len();
    let rest = &mount_opts[context_start_pos..];

    let (_context_end_offset, other_options_offset) = if rest.starts_with('"') {
        /* Skip quotes */
        match rest[1..].find('"') {
            Some(end_quote_pos) => {
                let end_pos = 1 + end_quote_pos + 1;
                /* Find next after optionally skipping quotes. */
                let comma_pos = rest[end_pos..].find(',').map(|p| end_pos + p);
                (end_pos, comma_pos)
            }
            None => {
                log::error!("Failed parsing mount option 'context'");
                return None;
            }
        }
    } else {
        let comma_pos = rest.find(',');
        (0, comma_pos)
    };

    let before_context = &mount_opts[..context_start_pos];

    let other_options = match other_options_offset {
        Some(offset) => &rest[offset..],
        None => "",
    };

    let new_options = format!("{}\"{}\"{}",
        before_context,
        new_context,
        other_options
    );

    log::debug!("\t\tChanged mount 'context=' to {}", new_options);

    Some(new_options)
}

/// Intrusive linked list link, matching CRIU's `list_head`.
/// Contains next/prev pointers for O(1) list operations.
#[derive(Default)]
pub struct ListLink {
    next: Option<NonNull<MountInfo>>,
    prev: Option<NonNull<MountInfo>>,
}

impl ListLink {
    pub fn new() -> Self {
        Self {
            next: None,
            prev: None,
        }
    }

    pub fn is_linked(&self) -> bool {
        self.next.is_some()
    }
}

/// Intrusive list head, matching CRIU's `LIST_HEAD`.
/// Points to first element; elements link via their ListLink field.
#[derive(Default)]
pub struct ListHead {
    first: Option<NonNull<MountInfo>>,
}

impl ListHead {
    pub fn new() -> Self {
        Self { first: None }
    }

    pub fn is_empty(&self) -> bool {
        self.first.is_none()
    }
}

pub struct MountInfo {
    pub mnt_id: i32,
    pub parent_mnt_id: i32,
    pub s_dev: u32,
    pub s_dev_rt: u32,
    pub root: Option<String>,
    /*
     * During dump mountpoint contains path with dot at the
     * beginning. It allows to use openat, statat, etc without
     * creating a temporary copy of the path.
     *
     * On restore mountpoint is prepended with so called ns
     * root path -- it's a place in fs where the namespace
     * mount tree is constructed. Check mnt_roots for details.
     * The ns_mountpoint contains path w/o this prefix.
     */
    pub mountpoint: Option<String>,
    pub ns_mountpoint: Option<String>,

    /* Mount-v2 specific */
    pub plain_mountpoint: Option<String>,
    pub is_dir: i32,
    pub mp_fd_id: i32,
    pub mnt_fd_id: i32,
    pub mnt_sharing_link: ListLink,
    pub sg: Option<usize>,

    pub fd: RawFd,
    pub flags: u32,
    pub sb_flags: u32,
    pub master_id: i32,
    pub shared_id: i32,
    pub source: Option<String>,
    pub options: Option<String>,
    pub fsname: Option<String>,
    pub fstype_code: i32,

    pub mounted: bool,
    pub need_plugin: bool,
    pub is_ns_root: bool,
    pub deleted: bool,
    pub deleted_level: i32,
    pub deleted_list_link: ListLink,

    pub external: Option<String>,
    pub internal_sharing: bool,

    pub bind: Option<NonNull<MountInfo>>,

    pub mnt_bind: ListHead,
    pub mnt_bind_link: ListLink,
    pub mnt_bind_is_populated: bool,

    pub mnt_share_link: ListLink,
    pub mnt_slave_list: ListHead,
    pub mnt_slave_link: ListLink,
    pub mnt_ext_slave_link: ListLink,
    pub mnt_master: Option<NonNull<MountInfo>>,
    pub mnt_propagate_link: ListLink,
    pub mnt_notprop_link: ListLink,
    pub mnt_unbindable_link: ListLink,

    pub postpone_link: ListLink,

    pub is_overmounted: i32,

    pub remounted_rw: i32,

    pub nsid_idx: Option<usize>,

    pub next_idx: Option<usize>,

    /* Tree linkage - matches CRIU's intrusive list pattern */
    pub parent: Option<NonNull<MountInfo>>,
    pub children: ListHead,
    pub siblings: ListLink,
}

impl MountInfo {
    pub fn new(mnt_id: i32) -> Self {
        Self {
            mnt_id,
            parent_mnt_id: 0,
            s_dev: 0,
            s_dev_rt: 0,
            root: None,
            mountpoint: None,
            ns_mountpoint: None,
            plain_mountpoint: None,
            is_dir: -1,
            mp_fd_id: -1,
            mnt_fd_id: -1,
            mnt_sharing_link: ListLink::new(),
            sg: None,
            fd: -1,
            flags: 0,
            sb_flags: 0,
            master_id: 0,
            shared_id: 0,
            source: None,
            options: None,
            fsname: None,
            fstype_code: 0,
            mounted: false,
            need_plugin: false,
            is_ns_root: false,
            deleted: false,
            deleted_level: 0,
            deleted_list_link: ListLink::new(),
            external: None,
            internal_sharing: false,
            bind: None,
            mnt_bind: ListHead::new(),
            mnt_bind_link: ListLink::new(),
            mnt_bind_is_populated: false,
            mnt_share_link: ListLink::new(),
            mnt_slave_list: ListHead::new(),
            mnt_slave_link: ListLink::new(),
            mnt_ext_slave_link: ListLink::new(),
            mnt_master: None,
            mnt_propagate_link: ListLink::new(),
            mnt_notprop_link: ListLink::new(),
            mnt_unbindable_link: ListLink::new(),
            postpone_link: ListLink::new(),
            is_overmounted: -1,
            remounted_rw: 0,
            nsid_idx: None,
            next_idx: None,
            parent: None,
            children: ListHead::new(),
            siblings: ListLink::new(),
        }
    }
}

/// Storage for mount_info structs with stable addresses.
/// Uses Box to ensure stable pointers for intrusive lists.
pub struct MountInfoStore {
    /// All mounts stored with stable addresses
    mounts: Vec<Box<UnsafeCell<MountInfo>>>,
}

impl Default for MountInfoStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MountInfoStore {
    pub fn new() -> Self {
        Self { mounts: Vec::new() }
    }

    /// Adds a mount and returns its index.
    pub fn add(&mut self, mi: MountInfo) -> usize {
        let idx = self.mounts.len();
        self.mounts.push(Box::new(UnsafeCell::new(mi)));
        idx
    }

    /// Gets a reference to a mount by index.
    pub fn get(&self, idx: usize) -> Option<&MountInfo> {
        self.mounts.get(idx).map(|cell| unsafe { &*cell.get() })
    }

    /// Gets a mutable reference to a mount by index.
    /// SAFETY: Caller must ensure no other references exist.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut MountInfo> {
        self.mounts.get(idx).map(|cell| unsafe { &mut *cell.get() })
    }

    /// Gets a raw pointer to a mount by index.
    fn get_ptr(&self, idx: usize) -> Option<NonNull<MountInfo>> {
        self.mounts
            .get(idx)
            .map(|cell| NonNull::new(cell.get()).unwrap())
    }

    /// Gets a raw pointer to a mount by index (public version).
    /// SAFETY: Caller must ensure proper synchronization.
    pub fn get_ptr_pub(&self, idx: usize) -> Option<NonNull<MountInfo>> {
        self.get_ptr(idx)
    }

    /// Finds mount index by mnt_id.
    pub fn lookup_mnt_id(&self, id: i32) -> Option<usize> {
        self.mounts
            .iter()
            .position(|cell| unsafe { (*cell.get()).mnt_id == id })
    }

    /// Returns index for a pointer.
    fn ptr_to_idx(&self, ptr: NonNull<MountInfo>) -> Option<usize> {
        self.mounts.iter().position(|cell| {
            std::ptr::eq(cell.get(), ptr.as_ptr())
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = &MountInfo> {
        self.mounts.iter().map(|cell| unsafe { &*cell.get() })
    }

    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// Builds the mount tree by resolving parent_mnt_id relationships.
    /// Links children to parents via intrusive lists.
    /// Returns the index of the root mount, or None if no root found.
    ///
    /// Corresponds to CRIU's mnt_build_ids_tree().
    pub fn mnt_build_ids_tree(&mut self) -> Option<usize> {
        let mut root_idx: Option<usize> = None;

        // First pass: find parent for each mount and link into parent's children list
        for idx in 0..self.mounts.len() {
            let mi_ptr = self.get_ptr(idx).unwrap();
            let mi = unsafe { &*mi_ptr.as_ptr() };
            let mnt_id = mi.mnt_id;
            let parent_mnt_id = mi.parent_mnt_id;
            let is_ns_root = mi.is_ns_root;

            if mnt_id != parent_mnt_id {
                // Find parent by mnt_id
                if let Some(parent_idx) = self.lookup_mnt_id(parent_mnt_id) {
                    let parent_ptr = self.get_ptr(parent_idx).unwrap();

                    // Link child to parent
                    unsafe {
                        let mi_mut = &mut *mi_ptr.as_ptr();
                        let parent_mut = &mut *parent_ptr.as_ptr();

                        mi_mut.parent = Some(parent_ptr);

                        // Add to end of parent's children list (list_add_tail)
                        list_add_tail(&mut parent_mut.children, mi_ptr, |m| &mut m.siblings);
                    }
                } else {
                    // No parent found - only root mount can be without parent
                    if root_idx.is_none() && is_ns_root {
                        root_idx = Some(idx);
                    } else {
                        return None;
                    }
                }
            } else {
                // Circular reference (mnt_id == parent_mnt_id) - it's rootfs
                if root_idx.is_none() && is_ns_root {
                    root_idx = Some(idx);
                }
            }
        }

        root_idx
    }

    /// Returns the next mount in a depth-first subtree traversal.
    /// Matches CRIU's mnt_subtree_next() exactly.
    pub fn mnt_subtree_next(&self, mi_idx: usize, root_idx: usize) -> Option<usize> {
        let mi_ptr = self.get_ptr(mi_idx)?;
        let mi = unsafe { &*mi_ptr.as_ptr() };

        // If current node has children, go to first child
        if let Some(first_child) = mi.children.first {
            return self.ptr_to_idx(first_child);
        }

        // Walk up the tree looking for a sibling
        let mut current_ptr = mi_ptr;
        let root_ptr = self.get_ptr(root_idx)?;

        loop {
            let current = unsafe { &*current_ptr.as_ptr() };

            // If we're back at root, traversal complete
            if std::ptr::eq(current_ptr.as_ptr(), root_ptr.as_ptr()) {
                return None;
            }

            // Check if there's a next sibling
            if let Some(next_sibling) = current.siblings.next {
                // Check if we've wrapped around to the start of the list
                if let Some(parent_ptr) = current.parent {
                    let parent = unsafe { &*parent_ptr.as_ptr() };
                    if let Some(first) = parent.children.first {
                        if !std::ptr::eq(next_sibling.as_ptr(), first.as_ptr()) {
                            return self.ptr_to_idx(next_sibling);
                        }
                    }
                }
            }

            // Go up to parent
            match current.parent {
                Some(parent_ptr) => current_ptr = parent_ptr,
                None => return None,
            }
        }
    }

    /// Checks if a mount is hidden by sibling or children mounts.
    /// Caches result in is_overmounted field.
    ///
    /// Corresponds to CRIU's mnt_is_overmounted().
    pub fn mnt_is_overmounted(&self, mi_idx: usize) -> bool {
        let mi = match self.get(mi_idx) {
            Some(m) => m,
            None => return false,
        };

        // Check cached result
        if mi.is_overmounted != -1 {
            return mi.is_overmounted == 1;
        }

        // Compute overmount status
        let result = self.compute_is_overmounted(mi_idx);

        // Cache result (need mutable access)
        let mi_ptr = self.get_ptr(mi_idx).unwrap();
        unsafe {
            (*mi_ptr.as_ptr()).is_overmounted = if result { 1 } else { 0 };
        }

        result
    }

    fn compute_is_overmounted(&self, mi_idx: usize) -> bool {
        let mi = match self.get(mi_idx) {
            Some(m) => m,
            None => return false,
        };

        let mi_mountpoint = match mi.ns_mountpoint.as_ref() {
            Some(mp) => mp.clone(),
            None => return false,
        };

        // Walk up the tree checking for sibling overmounts
        let mut current_ptr = match self.get_ptr(mi_idx) {
            Some(p) => p,
            None => return false,
        };

        loop {
            let current = unsafe { &*current_ptr.as_ptr() };

            let parent_ptr = match current.parent {
                Some(p) => p,
                None => break, // Reached root
            };

            let parent = unsafe { &*parent_ptr.as_ptr() };

            // Check if parent is overmounted
            if parent.is_overmounted == 1 {
                return true;
            }

            // Check for sibling overmounts
            let current_mp = match current.ns_mountpoint.as_ref() {
                Some(mp) => mp,
                None => break,
            };

            // Iterate through siblings
            if let Some(first_sibling) = parent.children.first {
                let mut sibling_ptr = first_sibling;
                loop {
                    if !std::ptr::eq(sibling_ptr.as_ptr(), current_ptr.as_ptr()) {
                        let sibling = unsafe { &*sibling_ptr.as_ptr() };
                        if let Some(sibling_mp) = sibling.ns_mountpoint.as_ref() {
                            if issubpath(current_mp, sibling_mp) {
                                return true;
                            }
                        }
                    }

                    // Move to next sibling
                    let sibling = unsafe { &*sibling_ptr.as_ptr() };
                    match sibling.siblings.next {
                        Some(next) if !std::ptr::eq(next.as_ptr(), first_sibling.as_ptr()) => {
                            sibling_ptr = next;
                        }
                        _ => break,
                    }
                }
            }

            current_ptr = parent_ptr;
        }

        // Check for children overmounts (child mounted at same path)
        let mi = unsafe { &*self.get_ptr(mi_idx).unwrap().as_ptr() };
        if let Some(first_child) = mi.children.first {
            let mut child_ptr = first_child;
            loop {
                let child = unsafe { &*child_ptr.as_ptr() };
                if let Some(child_mp) = child.ns_mountpoint.as_ref() {
                    if child_mp == &mi_mountpoint {
                        return true;
                    }
                }

                // Move to next child
                match child.siblings.next {
                    Some(next) if !std::ptr::eq(next.as_ptr(), first_child.as_ptr()) => {
                        child_ptr = next;
                    }
                    _ => break,
                }
            }
        }

        false
    }

    /// Iterates over a mount tree and applies a function to each mount.
    /// Corresponds to CRIU's mnt_tree_for_each().
    pub fn mnt_tree_for_each<F>(&self, root_idx: usize, mut f: F) -> Result<(), usize>
    where
        F: FnMut(usize, &MountInfo) -> Result<(), ()>,
    {
        let mut current_idx = Some(root_idx);

        while let Some(idx) = current_idx {
            let mi = match self.get(idx) {
                Some(m) => m,
                None => return Err(idx),
            };

            if f(idx, mi).is_err() {
                return Err(idx);
            }

            current_idx = self.mnt_subtree_next(idx, root_idx);
        }

        Ok(())
    }

    /// Marks all overmounted mounts in the tree.
    /// Corresponds to CRIU's prepare_is_overmounted().
    pub fn prepare_is_overmounted(&self, root_idx: usize) {
        let mut current_idx = Some(root_idx);
        while let Some(idx) = current_idx {
            let _ = self.mnt_is_overmounted(idx);
            current_idx = self.mnt_subtree_next(idx, root_idx);
        }
    }

    pub fn mnt_bind_pick<F>(&self, mi_idx: usize, mut pick: F) -> Option<usize>
    where
        F: FnMut(&MountInfo, &MountInfo) -> bool,
    {
        let mi = self.get(mi_idx)?;

        if pick(mi, mi) {
            return Some(mi_idx);
        }

        assert!(
            mi.mnt_bind_is_populated,
            "BUG: mnt_bind list not populated in search_bindmounts"
        );

        // Iterate through mnt_bind list
        if let Some(first) = mi.mnt_bind.first {
            let mut current = first;
            loop {
                let bind_idx = self.ptr_to_idx(current)?;
                let bind = unsafe { &*current.as_ptr() };

                if pick(mi, bind) {
                    return Some(bind_idx);
                }

                match bind.mnt_bind_link.next {
                    Some(next) if !std::ptr::eq(next.as_ptr(), first.as_ptr()) => {
                        current = next;
                    }
                    _ => break,
                }
            }
        }

        None
    }

    pub fn mnt_get_external_bind_nodev(&self, mi_idx: usize) -> Option<usize> {
        self.mnt_bind_pick(mi_idx, __mnt_is_external_bind_nodev)
    }

    pub fn mnt_get_root_bind(
        &self,
        mi_idx: usize,
        ns_store: &crate::criu::namespaces::NsIdStore,
    ) -> Option<usize> {
        let mi = self.get(mi_idx)?;

        // Check self first
        if __mnt_is_root_bind(mi, mi, ns_store) {
            return Some(mi_idx);
        }

        assert!(
            mi.mnt_bind_is_populated,
            "BUG: mnt_bind list not populated in search_bindmounts"
        );

        // Iterate through mnt_bind list
        if let Some(first) = mi.mnt_bind.first {
            let mut current = first;
            loop {
                let bind_idx = self.ptr_to_idx(current)?;
                let bind = unsafe { &*current.as_ptr() };

                if __mnt_is_root_bind(mi, bind, ns_store) {
                    return Some(bind_idx);
                }

                match bind.mnt_bind_link.next {
                    Some(next) if !std::ptr::eq(next.as_ptr(), first.as_ptr()) => {
                        current = next;
                    }
                    _ => break,
                }
            }
        }

        None
    }

    pub fn mnt_is_root_bind(
        &self,
        mi_idx: usize,
        ns_store: &crate::criu::namespaces::NsIdStore,
    ) -> bool {
        self.mnt_get_root_bind(mi_idx, ns_store).is_some()
    }

    pub fn mnt_tree_show(&self, tree_idx: usize, off: usize) {
        let mi = match self.get(tree_idx) {
            Some(m) => m,
            None => return,
        };

        let mp = mi.ns_mountpoint.as_deref().unwrap_or("");
        log::info!(
            "{:off$}[{}]({}->{}){}",
            "",
            mp,
            mi.mnt_id,
            mi.parent_mnt_id,
            "",
            off = off
        );

        self.for_each_child(tree_idx, |child_idx, _| {
            self.mnt_tree_show(child_idx, off + 1);
        });

        log::info!("{:off$}<--{}", "", "", off = off);
    }

    pub fn mntinfo_add_list_before(&mut self, head: &mut Option<usize>, new_idx: usize) {
        if let Some(mi) = self.get_mut(new_idx) {
            mi.next_idx = *head;
        }
        *head = Some(new_idx);
    }

    /// Iterates over children of a mount.
    pub fn for_each_child<F>(&self, mi_idx: usize, mut f: F)
    where
        F: FnMut(usize, &MountInfo),
    {
        let mi = match self.get(mi_idx) {
            Some(m) => m,
            None => return,
        };

        if let Some(first) = mi.children.first {
            let mut current = first;
            loop {
                if let Some(idx) = self.ptr_to_idx(current) {
                    let child = unsafe { &*current.as_ptr() };
                    f(idx, child);
                }

                let child = unsafe { &*current.as_ptr() };
                match child.siblings.next {
                    Some(next) if !std::ptr::eq(next.as_ptr(), first.as_ptr()) => {
                        current = next;
                    }
                    _ => break,
                }
            }
        }
    }

    /// Put children mounts in an order they can be (u)mounted
    /// I.e. if we have mounts on foo/bar/, foo/bar/foobar/ and foo/
    /// we should put them in the foo/bar/foobar/, foo/bar/, foo/ order.
    /// Otherwise we will not be able to (u)mount them in a sequence.
    ///
    /// Funny, but all we need for this is to sort them in the descending
    /// order of the amount of /-s in a path =)
    ///
    /// Use stupid insertion sort here, we're not expecting mount trees
    /// to contain hundreds (or more) elements.
    pub fn mnt_resort_children(&mut self, parent_idx: usize) {
        let parent_ptr = match self.get_ptr(parent_idx) {
            Some(p) => p,
            None => return,
        };

        // SAFETY: We have exclusive access via &mut self
        unsafe {
            let parent = &mut *parent_ptr.as_ptr();

            // Empty list - nothing to sort
            if parent.children.is_empty() {
                return;
            }

            // Create temporary list to hold sorted result
            let mut sorted_list = ListHead::new();

            // Insertion sort: remove each child from parent and insert into sorted list
            while !parent.children.is_empty() {
                // Get first child
                let m_ptr = parent.children.first.unwrap();
                let m = &*m_ptr.as_ptr();
                let depth = mnt_depth(m);

                // Remove from parent's children
                list_del(&mut parent.children, m_ptr, |mi| &mut mi.siblings);

                // Find insertion point in sorted list (descending by depth)
                if sorted_list.is_empty() {
                    // First element
                    let m_mut = &mut *m_ptr.as_ptr();
                    m_mut.siblings.next = Some(m_ptr);
                    m_mut.siblings.prev = Some(m_ptr);
                    sorted_list.first = Some(m_ptr);
                } else {
                    // Find position: insert before first element with smaller depth
                    let first = sorted_list.first.unwrap();
                    let mut pos_ptr = first;
                    let mut found = false;

                    loop {
                        let pos = &*pos_ptr.as_ptr();
                        if mnt_depth(pos) < depth {
                            // Insert before this position
                            list_add_before(m_ptr, pos_ptr, |mi| &mut mi.siblings);

                            // Update head if we inserted at the beginning
                            if std::ptr::eq(pos_ptr.as_ptr(), first.as_ptr()) {
                                sorted_list.first = Some(m_ptr);
                            }
                            found = true;
                            break;
                        }

                        // Move to next
                        match pos.siblings.next {
                            Some(next) if !std::ptr::eq(next.as_ptr(), first.as_ptr()) => {
                                pos_ptr = next;
                            }
                            _ => break,
                        }
                    }

                    if !found {
                        // Insert at end (smallest depth)
                        list_add_tail(&mut sorted_list, m_ptr, |mi| &mut mi.siblings);
                    }
                }
            }

            // Move sorted list back to parent's children
            list_splice(&mut sorted_list, &mut parent.children, |mi| &mut mi.siblings);
        }
    }

    /// Sorting the children of the tree like these is safe and does not break
    /// the tree search in mnt_subtree_next (DFS-next search), as we sort children
    /// before calling next on parent and thus before DFS-next ever touches them,
    /// so from the perspective of DFS-next all children look like they are
    /// already sorted.
    pub fn resort_siblings<F>(&mut self, root_idx: usize, mut resort_children: F)
    where
        F: FnMut(&mut MountInfoStore, usize),
    {
        let mut current_idx = Some(root_idx);

        while let Some(idx) = current_idx {
            // Call callback to sort children of current node
            resort_children(self, idx);

            // Move to next in DFS order
            current_idx = self.mnt_subtree_next(idx, root_idx);
        }
    }

    pub fn resort_siblings_by_depth(&mut self, root_idx: usize) {
        // Collect indices first to avoid borrow conflicts
        let mut indices = Vec::new();
        let mut current_idx = Some(root_idx);
        while let Some(idx) = current_idx {
            indices.push(idx);
            current_idx = self.mnt_subtree_next(idx, root_idx);
        }

        // Now sort children of each node
        for idx in indices {
            self.mnt_resort_children(idx);
        }
    }

    // Organize them in a sequence in which they can be mounted/umounted.
    pub fn mnt_build_tree(&mut self) -> Option<usize> {
        log::info!("Building mountpoints tree");

        let tree_idx = self.mnt_build_ids_tree()?;

        self.resort_siblings_by_depth(tree_idx);

        log::info!("Done:");
        self.mnt_tree_show(tree_idx, 0);

        Some(tree_idx)
    }

    pub fn search_bindmounts_all(&mut self, head_idx: Option<usize>) {
        let mut current_idx = head_idx;
        while let Some(idx) = current_idx {
            self.search_bindmounts(idx);
            current_idx = self.get(idx).and_then(|mi| mi.next_idx);
        }
    }

    /// Links mounts sharing the same superblock into a bind mount list.
    ///
    /// Iterates through the flat mount list starting from mi_idx and links
    /// all mounts with matching superblock (via mounts_sb_equal) into mi's
    /// mnt_bind list.
    ///
    /// Corresponds to CRIU's `__search_bindmounts()`.
    pub fn search_bindmounts(&mut self, mi_idx: usize) {
        // Check if already populated
        if let Some(mi) = self.get(mi_idx) {
            if mi.mnt_bind_is_populated {
                return;
            }
        } else {
            return;
        }

        let mi_ptr = match self.get_ptr(mi_idx) {
            Some(p) => p,
            None => return,
        };

        // Get the starting point for iteration (mi->next)
        let start_idx = match self.get(mi_idx) {
            Some(mi) => mi.next_idx,
            None => return,
        };

        // Iterate through the flat list
        let mut current_idx = start_idx;
        while let Some(t_idx) = current_idx {
            // Check if mounts share superblock
            let should_link = {
                let mi = unsafe { &*mi_ptr.as_ptr() };
                if let Some(t) = self.get(t_idx) {
                    mounts_sb_equal(mi, t)
                } else {
                    false
                }
            };

            if should_link {
                let t_ptr = self.get_ptr(t_idx).unwrap();
                unsafe {
                    let mi = &mut *mi_ptr.as_ptr();
                    let t = &mut *t_ptr.as_ptr();

                    // Add t to mi's mnt_bind list using t's mnt_bind_link
                    list_add(&mut mi.mnt_bind, t_ptr, |m| &mut m.mnt_bind_link);
                    t.mnt_bind_is_populated = true;

                    log::debug!(
                        "The mount {} is bind for {} (@{} -> @{})",
                        t.mnt_id,
                        mi.mnt_id,
                        t.ns_mountpoint.as_deref().unwrap_or(""),
                        mi.ns_mountpoint.as_deref().unwrap_or("")
                    );
                }
            }

            // Move to next in flat list
            current_idx = self.get(t_idx).and_then(|t| t.next_idx);
        }

        // Mark as populated
        unsafe {
            (*mi_ptr.as_ptr()).mnt_bind_is_populated = true;
        }
    }
}

/// Adds an element to the end of an intrusive list.
/// Matches CRIU's list_add_tail().
unsafe fn list_add_tail<F>(head: &mut ListHead, new_ptr: NonNull<MountInfo>, link_fn: F)
where
    F: Fn(&mut MountInfo) -> &mut ListLink,
{
    let new = &mut *new_ptr.as_ptr();
    let new_link = link_fn(new);

    if head.first.is_none() {
        // Empty list - new element points to itself
        new_link.next = Some(new_ptr);
        new_link.prev = Some(new_ptr);
        head.first = Some(new_ptr);
    } else {
        // Insert before head (i.e., at the end of circular list)
        let first_ptr = head.first.unwrap();
        let first = &mut *first_ptr.as_ptr();
        let first_link = link_fn(first);

        let last_ptr = first_link.prev.unwrap();
        let last = &mut *last_ptr.as_ptr();
        let last_link = link_fn(last);

        new_link.prev = Some(last_ptr);
        new_link.next = Some(first_ptr);
        last_link.next = Some(new_ptr);
        first_link.prev = Some(new_ptr);
    }
}

/// Public wrapper for list_add_tail.
/// SAFETY: Caller must ensure proper synchronization.
pub unsafe fn list_add_tail_pub<F>(head: &mut ListHead, new_ptr: NonNull<MountInfo>, link_fn: F)
where
    F: Fn(&mut MountInfo) -> &mut ListLink,
{
    list_add_tail(head, new_ptr, link_fn)
}

/// Adds an element to the beginning of an intrusive list.
/// Matches CRIU's list_add().
unsafe fn list_add<F>(head: &mut ListHead, new_ptr: NonNull<MountInfo>, link_fn: F)
where
    F: Fn(&mut MountInfo) -> &mut ListLink,
{
    let new = &mut *new_ptr.as_ptr();
    let new_link = link_fn(new);

    if head.first.is_none() {
        // Empty list - new element points to itself
        new_link.next = Some(new_ptr);
        new_link.prev = Some(new_ptr);
        head.first = Some(new_ptr);
    } else {
        // Insert after head position (i.e., at the beginning)
        let first_ptr = head.first.unwrap();
        let first = &mut *first_ptr.as_ptr();
        let first_link = link_fn(first);

        let last_ptr = first_link.prev.unwrap();
        let last = &mut *last_ptr.as_ptr();
        let last_link = link_fn(last);

        // New becomes the first element
        new_link.prev = Some(last_ptr);
        new_link.next = Some(first_ptr);
        first_link.prev = Some(new_ptr);
        last_link.next = Some(new_ptr);
        head.first = Some(new_ptr);
    }
}

unsafe fn list_del<F>(head: &mut ListHead, ptr: NonNull<MountInfo>, link_fn: F)
where
    F: Fn(&mut MountInfo) -> &mut ListLink,
{
    let node = &mut *ptr.as_ptr();
    let link = link_fn(node);

    let prev_ptr = link.prev;
    let next_ptr = link.next;

    // If element is the only one in list
    if let (Some(prev), Some(next)) = (prev_ptr, next_ptr) {
        if std::ptr::eq(prev.as_ptr(), ptr.as_ptr()) && std::ptr::eq(next.as_ptr(), ptr.as_ptr()) {
            // Singleton - just clear the head
            head.first = None;
            link.prev = None;
            link.next = None;
            return;
        }

        // Update neighbors
        let prev_node = &mut *prev.as_ptr();
        let prev_link = link_fn(prev_node);
        prev_link.next = next_ptr;

        let next_node = &mut *next.as_ptr();
        let next_link = link_fn(next_node);
        next_link.prev = prev_ptr;

        // Update head if we removed the first element
        if let Some(first) = head.first {
            if std::ptr::eq(first.as_ptr(), ptr.as_ptr()) {
                head.first = Some(next);
            }
        }
    }

    link.prev = None;
    link.next = None;
}

unsafe fn list_add_before<F>(new_ptr: NonNull<MountInfo>, pos_ptr: NonNull<MountInfo>, link_fn: F)
where
    F: Fn(&mut MountInfo) -> &mut ListLink,
{
    let new = &mut *new_ptr.as_ptr();
    let new_link = link_fn(new);

    let pos = &mut *pos_ptr.as_ptr();
    let pos_link = link_fn(pos);

    let prev_ptr = pos_link.prev;

    new_link.next = Some(pos_ptr);
    new_link.prev = prev_ptr;

    if let Some(prev) = prev_ptr {
        let prev_node = &mut *prev.as_ptr();
        let prev_link = link_fn(prev_node);
        prev_link.next = Some(new_ptr);
    }

    pos_link.prev = Some(new_ptr);
}

unsafe fn list_splice<F>(src: &mut ListHead, dst: &mut ListHead, link_fn: F)
where
    F: Fn(&mut MountInfo) -> &mut ListLink,
{
    if src.first.is_none() {
        return;
    }

    if dst.first.is_none() {
        dst.first = src.first;
    } else {
        // Connect src list to beginning of dst list
        let src_first = src.first.unwrap();
        let dst_first = dst.first.unwrap();

        let src_first_node = &mut *src_first.as_ptr();
        let src_first_link = link_fn(src_first_node);
        let src_last = src_first_link.prev.unwrap();

        let dst_first_node = &mut *dst_first.as_ptr();
        let dst_first_link = link_fn(dst_first_node);
        let dst_last = dst_first_link.prev.unwrap();

        // src_last -> dst_first
        let src_last_node = &mut *src_last.as_ptr();
        let src_last_link = link_fn(src_last_node);
        src_last_link.next = Some(dst_first);
        dst_first_link.prev = Some(src_last);

        // dst_last -> src_first
        let dst_last_node = &mut *dst_last.as_ptr();
        let dst_last_link = link_fn(dst_last_node);
        dst_last_link.next = Some(src_first);
        src_first_link.prev = Some(dst_last);

        dst.first = src.first;
    }

    src.first = None;
}

fn mnt_depth(mi: &MountInfo) -> usize {
    match &mi.ns_mountpoint {
        Some(path) => path.chars().filter(|&c| c == '/').count(),
        None => 0,
    }
}

fn __mnt_is_external_bind_nodev(mi: &MountInfo, bind: &MountInfo) -> bool {
    if let (Some(root_mi), Some(root_bind)) = (mi.root.as_ref(), bind.root.as_ref()) {
        bind.external.is_some() && !mnt_is_dev_external(bind) && is_sub_path(root_mi, root_bind)
    } else {
        false
    }
}

/// Checks if `path` is a subpath of `prefix` (i.e., prefix is an ancestor path).
/// Returns true if path starts with prefix followed by '/' or end of string.
#[inline]
pub fn issubpath(path: &str, prefix: &str) -> bool {
    if path.starts_with(prefix) {
        let rest = &path[prefix.len()..];
        rest.is_empty() || rest.starts_with('/')
    } else {
        false
    }
}

pub fn service_mountpoint(mi: &MountInfo, mntns_compat_mode: bool, is_restore: bool) -> Option<&str> {
    if !mntns_compat_mode && is_restore {
        mi.plain_mountpoint.as_deref()
    } else {
        mi.mountpoint.as_deref()
    }
}

pub fn ext_mount_lookup<'a>(externals: &'a [External], key: &str) -> Option<&'a str> {
    let mkey = format!("mnt[{}]", key);
    match external_lookup_by_key(externals, &mkey) {
        ExternalLookupResult::Found(v) => Some(v),
        _ => None,
    }
}

pub fn get_plain_mountpoint(mnt_id: i32, name: Option<&str>, mnt_roots: Option<&str>) -> Option<String> {
    let mnt_roots = mnt_roots?;

    let path = match name {
        Some(n) => format!("{}/mnt-{}", mnt_roots, n),
        None => format!("{}/mnt-{:010}", mnt_roots, mnt_id),
    };

    if path.len() >= PATH_MAX {
        return None;
    }

    Some(path)
}

pub fn print_ns_root(ns_id: u32, remap_id: i32, mnt_roots: &str) -> String {
    format!("{}/{}-{:010}", mnt_roots, ns_id, remap_id)
}

pub fn mounts_sb_equal(a: &MountInfo, b: &MountInfo) -> bool {
    if a.s_dev != b.s_dev {
        return false;
    }

    if a.external.is_none() && b.external.is_none() {
        if a.source != b.source {
            return false;
        }

        if a.fsname != b.fsname {
            return false;
        }
    }

    if a.options != b.options {
        return false;
    }

    true
}

#[inline]
pub fn mnt_is_dev_external(mi: &MountInfo) -> bool {
    mi.external.as_deref() == Some(EXTERNAL_DEV_MOUNT)
}

#[inline]
pub fn mnt_is_ext_external(mi: &MountInfo) -> bool {
    mi.external.is_some() && mi.external.as_deref() != Some(EXTERNAL_DEV_MOUNT)
}

pub fn rst_mnt_is_root(mi: &MountInfo, ns_store: &crate::criu::namespaces::NsIdStore) -> bool {
    if !mi.is_ns_root {
        return false;
    }

    let nsid_idx = match mi.nsid_idx {
        Some(idx) => idx,
        None => return false,
    };

    let nsid = match ns_store.get(nsid_idx) {
        Some(ns) => ns,
        None => return false,
    };

    let root_mnt_ns = match root_mnt_ns_id_try() {
        Some(id) => id,
        None => return false,
    };

    nsid.id == root_mnt_ns
}

fn __mnt_is_root_bind(
    mi: &MountInfo,
    bind: &MountInfo,
    ns_store: &crate::criu::namespaces::NsIdStore,
) -> bool {
    if !rst_mnt_is_root(bind, ns_store) {
        return false;
    }

    match (mi.root.as_ref(), bind.root.as_ref()) {
        (Some(mi_root), Some(bind_root)) => is_sub_path(mi_root, bind_root),
        _ => false,
    }
}

/// Allocates a new mount_info structure.
///
/// Corresponds to CRIU's `mnt_entry_alloc()`.
///
/// The `rst` parameter indicates restore mode. In CRIU, this triggers
/// allocation of `rst_mount_info` via shmalloc for shared memory access.
/// Currently, `remounted_rw` is stored directly in MountInfo until
/// shmalloc infrastructure is implemented.
pub fn mnt_entry_alloc(rst: bool) -> Option<MountInfo> {
    // MountInfo::new() initializes all fields to their defaults:
    // - mp_fd_id, mnt_fd_id, fd, is_dir, is_overmounted all set to -1
    // - All list heads/links initialized empty
    // - remounted_rw initialized to 0
    let mut mi = MountInfo::new(0);

    if rst {
        // In CRIU, this allocates rst_mount_info via shmalloc.
        // We store remounted_rw directly in MountInfo for now.
        // shmalloc integration will be added when Priority 4 is implemented.
        mi.remounted_rw = 0;
    }

    Some(mi)
}

/// Constructs the mountpoint paths for a mount.
///
/// Sets mi.mountpoint to root + mountpoint (the full path),
/// mi.ns_mountpoint to the mountpoint part only,
/// and mi.plain_mountpoint via get_plain_mountpoint().
///
/// Corresponds to CRIU's `get_mp_mountpoint()`.
pub fn get_mp_mountpoint(
    mi: &mut MountInfo,
    mountpoint: &str,
    root: &str,
    mnt_roots: Option<&str>,
) -> Result<(), i32> {
    // Build full mountpoint: root + mountpoint
    let full_path = format!("{}{}", root, mountpoint);

    if full_path.len() >= PATH_MAX {
        return Err(-1);
    }

    mi.mountpoint = Some(full_path);
    mi.ns_mountpoint = Some(mountpoint.to_string());

    // Set plain_mountpoint
    mi.plain_mountpoint = get_plain_mountpoint(mi.mnt_id, None, mnt_roots);
    if mi.plain_mountpoint.is_none() {
        return Err(-1);
    }

    log::debug!(
        "Will mount {} @ {} {}",
        mi.mnt_id,
        mi.plain_mountpoint.as_deref().unwrap_or(""),
        mi.ns_mountpoint.as_deref().unwrap_or("")
    );

    Ok(())
}

/// Extracts and validates the mount root path from a MntEntry.
///
/// Handles external mount mappings via ext_key, looking up the mapping
/// from externals list.
///
/// Corresponds to CRIU's `get_mp_root()`.
///
/// Parameters:
/// - `mi`: MountInfo to update
/// - `root`: The root path from MntEntry
/// - `ext_mount`: Whether this is marked as external mount
/// - `ext_key`: External mount key (if any)
/// - `externals`: List of external mount mappings
/// - `autodetect_ext_mounts`: Whether to allow autodetected external mounts
pub fn get_mp_root(
    mi: &mut MountInfo,
    root: &str,
    ext_mount: bool,
    ext_key: Option<&str>,
    externals: &[crate::criu::external::External],
    autodetect_ext_mounts: bool,
) -> Result<(), i32> {
    // Forward compatibility: if ext_mount is set, treat root as ext_key
    let (actual_root, actual_ext_key) = if ext_mount {
        (NO_ROOT_MOUNT, Some(root))
    } else {
        (root, ext_key)
    };

    mi.root = Some(actual_root.to_string());

    // If no ext_key, we're done
    let ext_key = match actual_ext_key {
        Some(k) => k,
        None => {
            log::debug!(
                "Will mount {} from {}",
                mi.mnt_id,
                mi.root.as_deref().unwrap_or("")
            );
            return Ok(());
        }
    };

    // Handle external mount mappings
    let ext = if ext_key == AUTODETECTED_MOUNT {
        if !autodetect_ext_mounts {
            log::error!(
                "Mount {}:{} is autodetected external mount. \
                 Try \"--ext-mount-map auto\" to allow them.",
                mi.mnt_id,
                mi.ns_mountpoint.as_deref().unwrap_or("")
            );
            return Err(-1);
        }
        // Use source as the external path
        mi.source.as_deref().map(|s| s.to_string())
    } else if ext_key == EXTERNAL_DEV_MOUNT {
        Some(EXTERNAL_DEV_MOUNT.to_string())
    } else {
        // Look up in externals list
        match ext_mount_lookup(externals, ext_key) {
            Some(v) => Some(v.to_string()),
            None => {
                log::error!(
                    "No mapping for {}:{} mountpoint",
                    mi.mnt_id,
                    mi.ns_mountpoint.as_deref().unwrap_or("")
                );
                return Err(-1);
            }
        }
    };

    if let Some(e) = ext {
        log::debug!("Will mount {} from {} (E)", mi.mnt_id, e);
        mi.external = Some(e);
    }

    Ok(())
}

fn is_root(mountpoint: &str) -> bool {
    mountpoint == "/"
}

pub fn collect_mnt_from_image(
    store: &mut MountInfoStore,
    head: &mut Option<usize>,
    tail: &mut Option<usize>,
    nsid: &mut NsId,
    img_dir_fd: RawFd,
    externals: &[External],
) -> Result<(), i32> {
    let path = format!("mountpoints-{}.img", nsid.id);

    let mut img = match open_image(img_dir_fd, CrFdType::Mnts, &path) {
        Ok(i) => i,
        Err(e) => {
            log::error!("Failed to open mount image: {}", e);
            return Err(-1);
        }
    };

    if img.is_empty() {
        return Ok(());
    }

    let mnt_roots_str = mnt_roots();
    let root = print_ns_root(nsid.id, 0, mnt_roots_str.as_deref().unwrap_or("."));

    log::debug!(
        "Reading mountpoint images (id {} pid {})",
        nsid.id,
        nsid.ns_pid
    );

    let autodetect_ext_mounts = opts().autodetect_ext_mounts;

    loop {
        let me: Option<MntEntry> = match pb_read_one_eof(&mut img) {
            Ok(m) => m,
            Err(e) => {
                log::error!("Failed to read mount entry: {}", e);
                close_image(&mut img);
                return Err(-1);
            }
        };

        let me = match me {
            Some(m) => m,
            None => break,
        };

        let mut pm = match mnt_entry_alloc(true) {
            Some(m) => m,
            None => {
                close_image(&mut img);
                return Err(-1);
            }
        };

        pm.mnt_id = me.mnt_id as i32;
        pm.parent_mnt_id = me.parent_mnt_id as i32;
        pm.s_dev = me.root_dev;
        pm.flags = me.flags;
        pm.sb_flags = me.sb_flags.unwrap_or(0);

        if me.sb_flags.is_none() {
            const MFLAGS: u32 = libc::MS_SHARED as u32
                | libc::MS_PRIVATE as u32
                | libc::MS_SLAVE as u32
                | libc::MS_UNBINDABLE as u32
                | libc::MS_NOSUID as u32
                | libc::MS_NODEV as u32
                | libc::MS_NOEXEC as u32
                | libc::MS_NOATIME as u32
                | libc::MS_NODIRATIME as u32
                | libc::MS_RELATIME as u32;

            pm.sb_flags = pm.flags & !MFLAGS;
            pm.flags &= MFLAGS;
        }

        pm.shared_id = me.shared_id.unwrap_or(0) as i32;
        pm.master_id = me.master_id.unwrap_or(0) as i32;
        pm.need_plugin = me.with_plugin.unwrap_or(false);
        pm.deleted = me.deleted.unwrap_or(false);
        pm.is_ns_root = is_root(&me.mountpoint);
        pm.internal_sharing = me.internal_sharing.unwrap_or(false);

        pm.source = Some(me.source.clone());
        pm.options = mount_update_lsm_context(&me.options, opts().lsm_mount_context.as_deref());

        if pm.options.is_none() {
            close_image(&mut img);
            return Err(-1);
        }

        let fstype_code = me.fstype as i32;
        if fstype_code != crate::proto::Fstype::Auto as i32 && me.fsname.is_some() {
            log::error!("fsname can be set only for FSTYPE__AUTO mounts");
            close_image(&mut img);
            return Err(-1);
        }

        pm.fstype_code = fstype_code;

        if let Some(ref fsname) = me.fsname {
            pm.fsname = Some(fsname.clone());
        }

        let ext_mount = me.ext_mount.unwrap_or(false);
        if get_mp_root(
            &mut pm,
            &me.root,
            ext_mount,
            me.ext_key.as_deref(),
            externals,
            autodetect_ext_mounts,
        )
        .is_err()
        {
            close_image(&mut img);
            return Err(-1);
        }

        if get_mp_mountpoint(
            &mut pm,
            &me.mountpoint,
            &root,
            mnt_roots_str.as_deref(),
        )
        .is_err()
        {
            close_image(&mut img);
            return Err(-1);
        }

        let pm_idx = store.add(pm);

        // Link into flat list
        store.mntinfo_add_list_before(head, pm_idx);
        if tail.is_none() {
            *tail = Some(pm_idx);
        }

        log::debug!(
            "\tRead {} mp @ {}",
            store.get(pm_idx).map(|m| m.mnt_id).unwrap_or(0),
            store
                .get(pm_idx)
                .and_then(|m| m.ns_mountpoint.as_deref())
                .unwrap_or("")
        );
    }

    close_image(&mut img);

    Ok(())
}

pub fn read_mnt_ns_img(
    store: &mut MountInfoStore,
    ns_ids: &mut [NsId],
    img_dir_fd: RawFd,
    root_ns_mask: u64,
    externals: &[External],
) -> Result<Option<usize>, i32> {
    if root_ns_mask & libc::CLONE_NEWNS as u64 == 0 {
        return Ok(None);
    }

    let mut pms: Option<usize> = None;

    for nsid in ns_ids.iter_mut() {
        if nsid.nd.cflag != libc::CLONE_NEWNS as u32 {
            continue;
        }

        let mut head: Option<usize> = None;
        let mut tail: Option<usize> = None;

        collect_mnt_from_image(store, &mut head, &mut tail, nsid, img_dir_fd, externals)?;

        let tree_idx = match store.mnt_build_tree() {
            Some(idx) => idx,
            None => {
                log::error!("Failed to build mount tree");
                return Err(-1);
            }
        };

        // mntns root mounts are always directories
        if let Some(mi) = store.get_mut(tree_idx) {
            mi.is_dir = 1;
        }

        // Update nsid's mnt data
        if let NsIdData::Mnt(ref mut mnt) = nsid.data {
            mnt.mntinfo_tree = Some(tree_idx);
            mnt.mntinfo_list = head;
        }

        // Link this namespace's list to global pms
        if let Some(tail_idx) = tail {
            if let Some(mi) = store.get_mut(tail_idx) {
                mi.next_idx = pms;
            }
            pms = head;
        }
    }

    // Search for bind mounts
    store.search_bindmounts_all(pms);

    // Mark overmounted mounts
    for nsid in ns_ids.iter() {
        if nsid.nd.cflag != libc::CLONE_NEWNS as u32 {
            continue;
        }
        if let NsIdData::Mnt(ref mnt) = nsid.data {
            if let Some(tree_idx) = mnt.mntinfo_tree {
                store.prepare_is_overmounted(tree_idx);
            }
        }
    }

    // resolve_shared_mounts_v2 would be called here if not in compat mode
    // merge_mount_trees would be called here

    Ok(pms)
}

pub fn merge_mount_trees(
    store: &mut MountInfoStore,
    ns_ids: &[NsId],
) -> Result<usize, i32> {
    let mnt_roots_str = mnt_roots();

    let mut root_yard = match mnt_entry_alloc(true) {
        Some(m) => m,
        None => return Err(-1),
    };

    root_yard.mountpoint = mnt_roots_str.clone();
    root_yard.plain_mountpoint = mnt_roots_str;
    root_yard.is_dir = 1;
    root_yard.mounted = true;
    root_yard.mnt_bind_is_populated = true;
    root_yard.is_overmounted = 0;
    root_yard.mnt_id = HELPER_MNT_ID;

    let root_yard_idx = store.add(root_yard);

    // Merge mount trees together under root_yard_mp
    for nsid in ns_ids.iter() {
        if nsid.nd.cflag != libc::CLONE_NEWNS as u32 {
            continue;
        }

        if let NsIdData::Mnt(ref mnt) = nsid.data {
            if let Some(tree_idx) = mnt.mntinfo_tree {
                let tree_ptr = match store.get_ptr_pub(tree_idx) {
                    Some(p) => p,
                    None => continue,
                };
                let root_ptr = match store.get_ptr_pub(root_yard_idx) {
                    Some(p) => p,
                    None => continue,
                };

                unsafe {
                    let tree = &mut *tree_ptr.as_ptr();
                    let root = &mut *root_ptr.as_ptr();

                    log::debug!(
                        "Mountpoint {} (@{}) moved to the root yard",
                        tree.mnt_id,
                        tree.ns_mountpoint.as_deref().unwrap_or("")
                    );

                    tree.parent = Some(root_ptr);
                    list_add_tail_pub(&mut root.children, tree_ptr, |m| &mut m.siblings);
                }
            }
        }
    }

    // Store the root yard index globally
    if let Ok(mut guard) = ROOT_YARD_MP.lock() {
        *guard = Some(root_yard_idx);
    }

    Ok(root_yard_idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tree_simple() {
        // Build a simple tree:
        //   1 (root)
        //   ├── 2
        //   └── 3
        //       └── 4
        let mut store = MountInfoStore::new();

        let mut root = MountInfo::new(1);
        root.parent_mnt_id = 1; // self-reference = root
        root.is_ns_root = true;
        let root_idx = store.add(root);

        let mut m2 = MountInfo::new(2);
        m2.parent_mnt_id = 1;
        store.add(m2);

        let mut m3 = MountInfo::new(3);
        m3.parent_mnt_id = 1;
        let m3_idx = store.add(m3);

        let mut m4 = MountInfo::new(4);
        m4.parent_mnt_id = 3;
        store.add(m4);

        let built_root = store.mnt_build_ids_tree();
        assert_eq!(built_root, Some(root_idx));

        // Check root has children
        assert!(!store.get(root_idx).unwrap().children.is_empty());

        // Check m3 has children
        assert!(!store.get(m3_idx).unwrap().children.is_empty());
    }

    #[test]
    fn test_mnt_subtree_next() {
        // Build tree:
        //   1 (root)
        //   ├── 2
        //   │   └── 4
        //   └── 3
        let mut store = MountInfoStore::new();

        let mut root = MountInfo::new(1);
        root.parent_mnt_id = 1;
        root.is_ns_root = true;
        let root_idx = store.add(root);

        let mut m2 = MountInfo::new(2);
        m2.parent_mnt_id = 1;
        let m2_idx = store.add(m2);

        let mut m3 = MountInfo::new(3);
        m3.parent_mnt_id = 1;
        let m3_idx = store.add(m3);

        let mut m4 = MountInfo::new(4);
        m4.parent_mnt_id = 2;
        let m4_idx = store.add(m4);

        store.mnt_build_ids_tree();

        // Traversal: 1 -> 2 -> 4 -> 3 -> None
        assert_eq!(store.mnt_subtree_next(root_idx, root_idx), Some(m2_idx));
        assert_eq!(store.mnt_subtree_next(m2_idx, root_idx), Some(m4_idx));
        assert_eq!(store.mnt_subtree_next(m4_idx, root_idx), Some(m3_idx));
        assert_eq!(store.mnt_subtree_next(m3_idx, root_idx), None);
    }

    #[test]
    fn test_mnt_tree_for_each() {
        let mut store = MountInfoStore::new();

        let mut root = MountInfo::new(1);
        root.parent_mnt_id = 1;
        root.is_ns_root = true;
        store.add(root);

        let mut m2 = MountInfo::new(2);
        m2.parent_mnt_id = 1;
        store.add(m2);

        let mut m3 = MountInfo::new(3);
        m3.parent_mnt_id = 1;
        store.add(m3);

        let root_idx = store.mnt_build_ids_tree().unwrap();

        let mut visited = Vec::new();
        let result = store.mnt_tree_for_each(root_idx, |_idx, mi| {
            visited.push(mi.mnt_id);
            Ok(())
        });

        assert!(result.is_ok());
        assert_eq!(visited, vec![1, 2, 3]);
    }

    #[test]
    fn test_issubpath() {
        assert!(issubpath("/a/b/c", "/a/b"));
        assert!(issubpath("/a/b", "/a/b"));
        assert!(!issubpath("/a/bc", "/a/b"));
        assert!(!issubpath("/a", "/a/b"));
        assert!(issubpath("/", "/"));
    }

    #[test]
    fn test_mnt_is_overmounted_by_sibling() {
        // Build tree:
        //   1 (root, "/")
        //   ├── 2 ("/a/b")  <-- overmounted by sibling at "/a"
        //   └── 3 ("/a")
        let mut store = MountInfoStore::new();

        let mut root = MountInfo::new(1);
        root.parent_mnt_id = 1;
        root.is_ns_root = true;
        root.ns_mountpoint = Some("/".to_string());
        store.add(root);

        let mut m2 = MountInfo::new(2);
        m2.parent_mnt_id = 1;
        m2.ns_mountpoint = Some("/a/b".to_string());
        store.add(m2);

        let mut m3 = MountInfo::new(3);
        m3.parent_mnt_id = 1;
        m3.ns_mountpoint = Some("/a".to_string());
        store.add(m3);

        store.mnt_build_ids_tree();

        // m2 at "/a/b" is overmounted by sibling m3 at "/a"
        assert!(store.mnt_is_overmounted(1)); // idx 1 = mnt_id 2
    }

    #[test]
    fn test_mnt_is_overmounted_by_child_same_path() {
        // Build tree:
        //   1 (root, "/")
        //   └── 2 ("/a")
        //       └── 3 ("/a")  <-- same path as parent = overmount
        let mut store = MountInfoStore::new();

        let mut root = MountInfo::new(1);
        root.parent_mnt_id = 1;
        root.is_ns_root = true;
        root.ns_mountpoint = Some("/".to_string());
        store.add(root);

        let mut m2 = MountInfo::new(2);
        m2.parent_mnt_id = 1;
        m2.ns_mountpoint = Some("/a".to_string());
        store.add(m2);

        let mut m3 = MountInfo::new(3);
        m3.parent_mnt_id = 2;
        m3.ns_mountpoint = Some("/a".to_string());
        store.add(m3);

        store.mnt_build_ids_tree();

        // m2 at "/a" is overmounted by child m3 at same path "/a"
        assert!(store.mnt_is_overmounted(1)); // idx 1 = mnt_id 2
    }

    #[test]
    fn test_for_each_child() {
        let mut store = MountInfoStore::new();

        let mut root = MountInfo::new(1);
        root.parent_mnt_id = 1;
        root.is_ns_root = true;
        store.add(root);

        let mut m2 = MountInfo::new(2);
        m2.parent_mnt_id = 1;
        store.add(m2);

        let mut m3 = MountInfo::new(3);
        m3.parent_mnt_id = 1;
        store.add(m3);

        let root_idx = store.mnt_build_ids_tree().unwrap();

        let mut child_ids = Vec::new();
        store.for_each_child(root_idx, |_idx, mi| {
            child_ids.push(mi.mnt_id);
        });

        assert_eq!(child_ids, vec![2, 3]);
    }

    #[test]
    fn test_mnt_depth() {
        let mut mi = MountInfo::new(1);
        mi.ns_mountpoint = Some("/".to_string());
        assert_eq!(mnt_depth(&mi), 1);

        mi.ns_mountpoint = Some("/a".to_string());
        assert_eq!(mnt_depth(&mi), 1);

        mi.ns_mountpoint = Some("/a/b".to_string());
        assert_eq!(mnt_depth(&mi), 2);

        mi.ns_mountpoint = Some("/a/b/c/d".to_string());
        assert_eq!(mnt_depth(&mi), 4);

        mi.ns_mountpoint = None;
        assert_eq!(mnt_depth(&mi), 0);
    }

    #[test]
    fn test_mnt_resort_children() {
        // Build tree with children at different depths:
        //   1 (root, "/")
        //   ├── 2 ("/a")       depth=1
        //   ├── 3 ("/a/b/c")   depth=3
        //   └── 4 ("/a/b")     depth=2
        // After sorting, order should be: 3, 4, 2 (descending by depth)
        let mut store = MountInfoStore::new();

        let mut root = MountInfo::new(1);
        root.parent_mnt_id = 1;
        root.is_ns_root = true;
        root.ns_mountpoint = Some("/".to_string());
        let root_idx = store.add(root);

        let mut m2 = MountInfo::new(2);
        m2.parent_mnt_id = 1;
        m2.ns_mountpoint = Some("/a".to_string());
        store.add(m2);

        let mut m3 = MountInfo::new(3);
        m3.parent_mnt_id = 1;
        m3.ns_mountpoint = Some("/a/b/c".to_string());
        store.add(m3);

        let mut m4 = MountInfo::new(4);
        m4.parent_mnt_id = 1;
        m4.ns_mountpoint = Some("/a/b".to_string());
        store.add(m4);

        store.mnt_build_ids_tree();

        // Before sorting, children order is insertion order: 2, 3, 4
        let mut before = Vec::new();
        store.for_each_child(root_idx, |_idx, mi| {
            before.push(mi.mnt_id);
        });
        assert_eq!(before, vec![2, 3, 4]);

        // Sort children
        store.mnt_resort_children(root_idx);

        // After sorting, order should be by descending depth: 3, 4, 2
        let mut after = Vec::new();
        store.for_each_child(root_idx, |_idx, mi| {
            after.push(mi.mnt_id);
        });
        assert_eq!(after, vec![3, 4, 2]);
    }

    #[test]
    fn test_resort_siblings_by_depth() {
        // Build tree:
        //   1 (root, "/")
        //   ├── 2 ("/a")
        //   │   ├── 5 ("/a/x")      depth=2
        //   │   └── 6 ("/a/x/y/z")  depth=4
        //   ├── 3 ("/a/b/c")
        //   └── 4 ("/a/b")
        let mut store = MountInfoStore::new();

        let mut root = MountInfo::new(1);
        root.parent_mnt_id = 1;
        root.is_ns_root = true;
        root.ns_mountpoint = Some("/".to_string());
        let root_idx = store.add(root);

        let mut m2 = MountInfo::new(2);
        m2.parent_mnt_id = 1;
        m2.ns_mountpoint = Some("/a".to_string());
        store.add(m2);

        let mut m3 = MountInfo::new(3);
        m3.parent_mnt_id = 1;
        m3.ns_mountpoint = Some("/a/b/c".to_string());
        store.add(m3);

        let mut m4 = MountInfo::new(4);
        m4.parent_mnt_id = 1;
        m4.ns_mountpoint = Some("/a/b".to_string());
        store.add(m4);

        let mut m5 = MountInfo::new(5);
        m5.parent_mnt_id = 2;
        m5.ns_mountpoint = Some("/a/x".to_string());
        store.add(m5);

        let mut m6 = MountInfo::new(6);
        m6.parent_mnt_id = 2;
        m6.ns_mountpoint = Some("/a/x/y/z".to_string());
        store.add(m6);

        store.mnt_build_ids_tree();

        // Sort entire tree
        store.resort_siblings_by_depth(root_idx);

        // Check root's children: should be 3, 4, 2 (descending depth)
        let mut root_children = Vec::new();
        store.for_each_child(root_idx, |_idx, mi| {
            root_children.push(mi.mnt_id);
        });
        assert_eq!(root_children, vec![3, 4, 2]);

        // Check m2's children: should be 6, 5 (descending depth)
        let m2_idx = store.lookup_mnt_id(2).unwrap();
        let mut m2_children = Vec::new();
        store.for_each_child(m2_idx, |_idx, mi| {
            m2_children.push(mi.mnt_id);
        });
        assert_eq!(m2_children, vec![6, 5]);
    }

    #[test]
    fn test_resort_empty_children() {
        // Verify sorting a node with no children doesn't panic
        let mut store = MountInfoStore::new();

        let mut root = MountInfo::new(1);
        root.parent_mnt_id = 1;
        root.is_ns_root = true;
        root.ns_mountpoint = Some("/".to_string());
        let root_idx = store.add(root);

        store.mnt_build_ids_tree();
        store.mnt_resort_children(root_idx);

        // Should complete without panic
        assert!(store.get(root_idx).unwrap().children.is_empty());
    }

    #[test]
    fn test_resort_single_child() {
        // Verify sorting a node with one child works
        let mut store = MountInfoStore::new();

        let mut root = MountInfo::new(1);
        root.parent_mnt_id = 1;
        root.is_ns_root = true;
        root.ns_mountpoint = Some("/".to_string());
        let root_idx = store.add(root);

        let mut m2 = MountInfo::new(2);
        m2.parent_mnt_id = 1;
        m2.ns_mountpoint = Some("/a".to_string());
        store.add(m2);

        store.mnt_build_ids_tree();
        store.mnt_resort_children(root_idx);

        let mut children = Vec::new();
        store.for_each_child(root_idx, |_idx, mi| {
            children.push(mi.mnt_id);
        });
        assert_eq!(children, vec![2]);
    }

    #[test]
    fn test_mnt_entry_alloc_non_restore() {
        let mi = mnt_entry_alloc(false).unwrap();

        // Check fields are initialized to CRIU defaults
        assert_eq!(mi.mnt_id, 0);
        assert_eq!(mi.mp_fd_id, -1);
        assert_eq!(mi.mnt_fd_id, -1);
        assert_eq!(mi.is_dir, -1);
        assert_eq!(mi.fd, -1);
        assert_eq!(mi.is_overmounted, -1);

        // Check lists are empty
        assert!(mi.children.is_empty());
        assert!(mi.mnt_bind.is_empty());
        assert!(mi.mnt_slave_list.is_empty());
    }

    #[test]
    fn test_mnt_entry_alloc_restore() {
        let mi = mnt_entry_alloc(true).unwrap();

        // In restore mode, remounted_rw should be initialized
        assert_eq!(mi.remounted_rw, 0);

        // Other fields same as non-restore
        assert_eq!(mi.mp_fd_id, -1);
        assert_eq!(mi.mnt_fd_id, -1);
        assert_eq!(mi.is_dir, -1);
        assert_eq!(mi.fd, -1);
        assert_eq!(mi.is_overmounted, -1);
    }

    #[test]
    fn test_search_bindmounts() {
        // Create mounts where some share the same superblock (s_dev)
        let mut store = MountInfoStore::new();

        // Mount 1: s_dev=100, source="tmpfs", options="rw"
        let mut m1 = MountInfo::new(1);
        m1.s_dev = 100;
        m1.source = Some("tmpfs".to_string());
        m1.options = Some("rw".to_string());
        m1.ns_mountpoint = Some("/a".to_string());
        let m1_idx = store.add(m1);

        // Mount 2: same superblock as m1 (bind mount)
        let mut m2 = MountInfo::new(2);
        m2.s_dev = 100;
        m2.source = Some("tmpfs".to_string());
        m2.options = Some("rw".to_string());
        m2.ns_mountpoint = Some("/b".to_string());
        let m2_idx = store.add(m2);

        // Mount 3: different superblock
        let mut m3 = MountInfo::new(3);
        m3.s_dev = 200;
        m3.source = Some("proc".to_string());
        m3.options = Some("rw".to_string());
        m3.ns_mountpoint = Some("/proc".to_string());
        store.add(m3);

        // Mount 4: same superblock as m1 (another bind mount)
        let mut m4 = MountInfo::new(4);
        m4.s_dev = 100;
        m4.source = Some("tmpfs".to_string());
        m4.options = Some("rw".to_string());
        m4.ns_mountpoint = Some("/c".to_string());
        let m4_idx = store.add(m4);

        // Set up flat list: m1 -> m2 -> m3 -> m4
        store.get_mut(m1_idx).unwrap().next_idx = Some(m2_idx);
        store.get_mut(m2_idx).unwrap().next_idx = Some(2); // m3
        store.get_mut(2).unwrap().next_idx = Some(m4_idx);

        // Search for bind mounts starting from m1
        store.search_bindmounts(m1_idx);

        // m1 should now have m2 and m4 in its mnt_bind list
        assert!(store.get(m1_idx).unwrap().mnt_bind_is_populated);
        assert!(store.get(m2_idx).unwrap().mnt_bind_is_populated);
        assert!(store.get(m4_idx).unwrap().mnt_bind_is_populated);
        // m3 has different superblock, should not be in bind list
        assert!(!store.get(2).unwrap().mnt_bind_is_populated);

        // Verify the bind list is not empty
        assert!(!store.get(m1_idx).unwrap().mnt_bind.is_empty());
    }

    #[test]
    fn test_get_mp_mountpoint() {
        let mut mi = MountInfo::new(42);

        let result = get_mp_mountpoint(&mut mi, "/data", "/mnt/roots/ns-1", Some("/tmp/mnt_roots"));

        assert!(result.is_ok());
        assert_eq!(mi.mountpoint, Some("/mnt/roots/ns-1/data".to_string()));
        assert_eq!(mi.ns_mountpoint, Some("/data".to_string()));
        assert!(mi.plain_mountpoint.is_some());
    }

    #[test]
    fn test_get_mp_root_basic() {
        let mut mi = MountInfo::new(1);
        mi.ns_mountpoint = Some("/data".to_string());

        let externals = vec![];
        let result = get_mp_root(&mut mi, "/subdir", false, None, &externals, false);

        assert!(result.is_ok());
        assert_eq!(mi.root, Some("/subdir".to_string()));
        assert!(mi.external.is_none());
    }

    #[test]
    fn test_get_mp_root_external_dev() {
        use crate::criu::external::External;

        let mut mi = MountInfo::new(1);
        mi.ns_mountpoint = Some("/dev".to_string());

        let externals: Vec<External> = vec![];
        let result = get_mp_root(
            &mut mi,
            "/",
            false,
            Some(EXTERNAL_DEV_MOUNT),
            &externals,
            false,
        );

        assert!(result.is_ok());
        assert_eq!(mi.external, Some(EXTERNAL_DEV_MOUNT.to_string()));
    }

    #[test]
    fn test_get_mp_root_ext_mount_flag() {
        let mut mi = MountInfo::new(1);
        mi.ns_mountpoint = Some("/mnt".to_string());

        // External format is "key:value" in the id field
        let externals = vec![crate::criu::external::External::new(
            "mnt[ext_path]:/host/path".to_string(),
        )];
        let result = get_mp_root(&mut mi, "ext_path", true, None, &externals, false);

        assert!(result.is_ok());
        // With ext_mount=true, root becomes "." and ext_path is treated as ext_key
        assert_eq!(mi.root, Some(NO_ROOT_MOUNT.to_string()));
        assert_eq!(mi.external, Some("/host/path".to_string()));
    }

    #[test]
    fn test_mnt_build_tree() {
        // Build tree:
        //   1 (root, "/")
        //   ├── 2 ("/a")       depth=1
        //   ├── 3 ("/a/b/c")   depth=3
        //   └── 4 ("/a/b")     depth=2
        let mut store = MountInfoStore::new();

        let mut root = MountInfo::new(1);
        root.parent_mnt_id = 1;
        root.is_ns_root = true;
        root.ns_mountpoint = Some("/".to_string());
        store.add(root);

        let mut m2 = MountInfo::new(2);
        m2.parent_mnt_id = 1;
        m2.ns_mountpoint = Some("/a".to_string());
        store.add(m2);

        let mut m3 = MountInfo::new(3);
        m3.parent_mnt_id = 1;
        m3.ns_mountpoint = Some("/a/b/c".to_string());
        store.add(m3);

        let mut m4 = MountInfo::new(4);
        m4.parent_mnt_id = 1;
        m4.ns_mountpoint = Some("/a/b".to_string());
        store.add(m4);

        // Build tree (should build ids tree and resort)
        let root_idx = store.mnt_build_tree().unwrap();
        assert_eq!(root_idx, 0);

        // Verify children are sorted by descending depth: 3, 4, 2
        let mut children = Vec::new();
        store.for_each_child(root_idx, |_idx, mi| {
            children.push(mi.mnt_id);
        });
        assert_eq!(children, vec![3, 4, 2]);
    }

    #[test]
    fn test_search_bindmounts_all() {
        let mut store = MountInfoStore::new();

        // Mount 1: s_dev=100
        let mut m1 = MountInfo::new(1);
        m1.s_dev = 100;
        m1.source = Some("tmpfs".to_string());
        m1.options = Some("rw".to_string());
        m1.ns_mountpoint = Some("/a".to_string());
        let m1_idx = store.add(m1);

        // Mount 2: s_dev=100 (bind of m1)
        let mut m2 = MountInfo::new(2);
        m2.s_dev = 100;
        m2.source = Some("tmpfs".to_string());
        m2.options = Some("rw".to_string());
        m2.ns_mountpoint = Some("/b".to_string());
        let m2_idx = store.add(m2);

        // Mount 3: s_dev=200 (different)
        let mut m3 = MountInfo::new(3);
        m3.s_dev = 200;
        m3.source = Some("proc".to_string());
        m3.options = Some("rw".to_string());
        m3.ns_mountpoint = Some("/proc".to_string());
        let m3_idx = store.add(m3);

        // Set up flat list: m1 -> m2 -> m3
        store.get_mut(m1_idx).unwrap().next_idx = Some(m2_idx);
        store.get_mut(m2_idx).unwrap().next_idx = Some(m3_idx);

        // Search all bindmounts
        store.search_bindmounts_all(Some(m1_idx));

        // All should be marked as populated
        assert!(store.get(m1_idx).unwrap().mnt_bind_is_populated);
        assert!(store.get(m2_idx).unwrap().mnt_bind_is_populated);
        assert!(store.get(m3_idx).unwrap().mnt_bind_is_populated);

        // m1 should have m2 in its bind list (same s_dev)
        assert!(!store.get(m1_idx).unwrap().mnt_bind.is_empty());
        // m3 has no binds with same s_dev
        assert!(store.get(m3_idx).unwrap().mnt_bind.is_empty());
    }

    #[test]
    fn test_mount_update_lsm_context_no_context() {
        // No context= in mount options
        let opts = "rw,nosuid,nodev";
        let result = mount_update_lsm_context(opts, Some("new_context"));
        assert_eq!(result, Some(opts.to_string()));
    }

    #[test]
    fn test_mount_update_lsm_context_no_lsm_mount_context() {
        // Context exists but no lsm_mount_context specified
        let opts = "rw,context=\"old_context\",nodev";
        let result = mount_update_lsm_context(opts, None);
        assert_eq!(result, Some(opts.to_string()));
    }

    #[test]
    fn test_mount_update_lsm_context_quoted() {
        // Quoted context with other options after
        let opts = "rw,context=\"system_u:object_r:container_file_t:s0:c82,c137\",inode64";
        let result = mount_update_lsm_context(opts, Some("new_label"));
        assert_eq!(
            result,
            Some("rw,context=\"new_label\",inode64".to_string())
        );
    }

    #[test]
    fn test_mount_update_lsm_context_quoted_no_trailing() {
        // Quoted context at end of string
        let opts = "rw,context=\"old_context\"";
        let result = mount_update_lsm_context(opts, Some("new_context"));
        assert_eq!(result, Some("rw,context=\"new_context\"".to_string()));
    }

    #[test]
    fn test_mount_update_lsm_context_unquoted() {
        // Unquoted context (edge case)
        let opts = "context=simple,rw";
        let result = mount_update_lsm_context(opts, Some("new_context"));
        assert_eq!(result, Some("context=\"new_context\",rw".to_string()));
    }

    #[test]
    fn test_mount_update_lsm_context_missing_closing_quote() {
        // Missing closing quote should return None
        let opts = "context=\"broken";
        let result = mount_update_lsm_context(opts, Some("new_context"));
        assert!(result.is_none());
    }

    #[test]
    fn test_mount_update_lsm_context_at_start() {
        // Context at start of options
        let opts = "context=\"old\",rw,nodev";
        let result = mount_update_lsm_context(opts, Some("new"));
        assert_eq!(result, Some("context=\"new\",rw,nodev".to_string()));
    }
}
