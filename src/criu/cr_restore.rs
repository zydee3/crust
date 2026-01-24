use std::ffi::c_void;
use std::io;
use std::os::unix::io::RawFd;

use crate::criu::cgroup::{fini_cgroup, prepare_cgroup};
use crate::criu::clone::{clone3_with_pid_noasan, clone_noasan};
use crate::criu::cpu::{cpu_init, cpu_validate_cpuinfo};
use crate::criu::fdstore::{fdstore_init, FdstoreDesc};
use crate::criu::files::{files_collected, inherit_fd_lookup_id, inherit_fd_move_to_fdstore, prepare_files};
use crate::criu::files_reg::collect_remaps_and_regfiles;
use crate::criu::image::{check_img_inventory, close_image, open_image};
use crate::criu::lsm::lsm_check_opts;
use crate::criu::image_desc::CrFdType;
use crate::criu::kerndat::kdat;
use crate::criu::memfd::prepare_memfd_inodes;
use crate::criu::namespaces::{lookup_ns_by_id_ptr, ns_desc, root_ns_mask, switch_ns_by_fd};
use crate::criu::options::opts;
use crate::criu::plugin::{cr_plugin_fini, cr_plugin_init, run_scripts, CrPluginStage, ScriptAction};
use crate::criu::protobuf::pb_read_one;
use crate::criu::pstree::{
    current_shared, current_shared_mut, prepare_pstree, root_item_idx, root_item_idx_try, rsti,
    rsti_mut, set_current_shared, shared_store_mut, task_alive, vpid, Futex, Pid, PidStore,
    PstreeItem, SharedPstreeItem, SharedPstreeStore, TaskState,
};
use crate::criu::servicefd::{init_service_fd, ServiceFdState, SfdType};
use crate::criu::stats::{init_stats, timing_start, RestoreTime, RESTORE_STATS};
use crate::criu::task_entries::{
    lock_last_pid, prepare_task_entries, restore_finish_stage, set_cr_errno, task_entries,
    unlock_last_pid, CrState,
};
use crate::criu::tty::{tty_init_restore, tty_prep_fds};
use crate::criu::uffd::prepare_lazy_pages_socket;
use crate::criu::vdso::vdso_init_restore;
use crate::criu::util::{prepare_userns_hook, restore_origin_ns_hook, set_next_pid};
use crate::proto::{core_entry, CoreEntry};

pub const INIT_PID: i32 = 1;

pub const ARCH_SHSTK_SHSTK: u64 = 1 << 0;
pub const ARCH_SHSTK_WRSS: u64 = 1 << 1;
pub const ARCH_SHSTK_UNLOCK: i32 = 0x5004;

#[cfg(target_arch = "x86_64")]
const PTRACE_ARCH_PRCTL: libc::c_uint = 30;

#[cfg(target_arch = "x86_64")]
pub const CORE_ENTRY_MARCH: i32 = core_entry::March::X8664 as i32;

#[cfg(target_arch = "aarch64")]
pub const CORE_ENTRY_MARCH: i32 = core_entry::March::Aarch64 as i32;

pub fn check_core(core: &mut CoreEntry, me: &mut PstreeItem) -> i32 {
    if core.mtype != CORE_ENTRY_MARCH {
        log::error!("Core march mismatch {}", core.mtype);
        return -1;
    }

    let tc = match &core.tc {
        Some(tc) => tc,
        None => {
            log::error!("Core task state data missed");
            return -1;
        }
    };

    if tc.task_state != TaskState::Dead as u32 {
        if core.ids.is_none() && me.ids.is_none() {
            log::error!("Core IDS data missed for non-zombie");
            return -1;
        }

        #[cfg(target_arch = "x86_64")]
        let has_arch_info = core.thread_info.is_some();

        #[cfg(target_arch = "aarch64")]
        let has_arch_info = core.ti_aarch64.is_some();

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let has_arch_info = false;

        if !has_arch_info {
            log::error!("Core info data missed for non-zombie");
            return -1;
        }

        /*
         * Seccomp are moved to per-thread origin,
         * so for old images we need to move per-task
         * data into proper place.
         */
        if let Some(thread_core) = &mut core.thread_core {
            if tc.old_seccomp_mode.is_some() {
                thread_core.seccomp_mode = tc.old_seccomp_mode;
            }
            if tc.old_seccomp_filter.is_some() {
                thread_core.seccomp_filter = tc.old_seccomp_filter;
                if let Some(rsti) = rsti_mut(me) {
                    rsti.has_old_seccomp_filter = true;
                }
            }
        }
    }

    0
}

pub fn open_core(pid: i32, dfd: RawFd) -> io::Result<CoreEntry> {
    let path = format!("core-{}.img", pid);
    let mut img = open_image(dfd, CrFdType::Core, &path)?;

    if img.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Can't open core data for {}", pid),
        ));
    }

    let core: CoreEntry = pb_read_one(&mut img)?;
    close_image(&mut img);

    Ok(core)
}

pub fn maybe_clone_parent(item: &mut PstreeItem, core: &CoreEntry) {
    /*
     * zdtm runs in kernel 3.11, which has the problem described below. We
     * avoid this by including the pdeath_sig test. Once users/zdtm migrate
     * off of 3.11, this condition can be simplified to just test the
     * options and not have the pdeath_sig test.
     */
    if opts().restore_sibling != 0 {
        /*
         * This means we're called from lib's criu_restore_child().
         * In that case create the root task as the child one to
         * the caller. This is the only way to correctly restore the
         * pdeath_sig of the root task. But also looks nice.
         *
         * Alternatively, if we are --restore-detached, a similar trick is
         * needed to correctly restore pdeath_sig and prevent processes from
         * dying once restored.
         *
         * There were a problem in kernel 3.11 -- CLONE_PARENT can't be
         * set together with CLONE_NEWPID, which has been solved in further
         * versions of the kernels, but we treat 3.11 as a base, so at
         * least warn a user about potential problems.
         */
        if let Some(rsti) = rsti_mut(item) {
            rsti.clone_flags |= libc::CLONE_PARENT as u64;
            if rsti.clone_flags & libc::CLONE_NEWPID as u64 != 0 {
                log::warn!(
                    "Set CLONE_PARENT | CLONE_NEWPID but it might cause restore problem, \
                     because not all kernels support such clone flags combinations!"
                );
            }
        }
    } else if opts().restore_detach != 0 {
        if let Some(thread_core) = &core.thread_core {
            if thread_core.pdeath_sig.is_some() && thread_core.pdeath_sig.unwrap() != 0 {
                log::warn!(
                    "Root task has pdeath_sig configured, so it will receive one _right_ \
                     after restore on CRIU exit"
                );
            }
        }
    }
}

pub struct CrCloneArg {
    pub item_idx: usize,
    pub clone_flags: u64,
    pub core: Option<CoreEntry>,
    pub sfd_map: u32,
    pub sfd_arr: [RawFd; 16],
    pub service_fd_base: RawFd,
    pub service_fd_id: i32,
    pub manage_cgroups: u32,
    pub cg_set: u32,
    pub parent_cg_set: Option<u32>,
    pub has_parent: bool,
    pub parent_has_fdt: bool,
    pub max_fd: i32,
    pub fdt_nr: i32,
    pub dfd: RawFd,
    pub shared_item: *mut SharedPstreeItem,
    pub shared_store: *mut SharedPstreeStore,
}

static mut CURRENT_ITEM_IDX: Option<usize> = None;

pub fn current_item_idx() -> Option<usize> {
    unsafe { CURRENT_ITEM_IDX }
}

pub fn set_current_item_idx(idx: Option<usize>) {
    unsafe { CURRENT_ITEM_IDX = idx };
}

pub fn needs_prep_creds(item: &PstreeItem) -> bool {
    /*
     * Before the 4.13 kernel, it was impossible to set
     * an exe_file if uid or gid isn't zero.
     */
    item.parent_idx.is_none() && ((root_ns_mask() & libc::CLONE_NEWUSER as u64) != 0 || unsafe { libc::getuid() } != 0)
}

pub fn restore_before_setsid(child: &PstreeItem, parent: &PstreeItem) -> bool {
    let csid = if child.born_sid == -1 {
        child.sid
    } else {
        child.born_sid
    };

    parent.born_sid == csid
}

pub fn restore_finish_ns_stage(_store: &PidStore, from: CrState, to: CrState) -> i32 {
    if root_ns_mask() != 0 {
        return restore_finish_stage(from);
    }

    // Nobody waits for this stage change, just go ahead
    __restore_switch_stage_nw(to);
    0
}

fn __restore_switch_stage_nw(to: CrState) {
    let te = task_entries();
    te.start.set(to as u32);
}

pub fn restore_sid(store: &PidStore, current_idx: usize) {
    let item = store.get_item(current_idx).unwrap();
    let current_vpid = vpid(item);
    let current_sid = item.sid;
    let is_root = item.parent_idx.is_none();

    /*
     * SID can only be reset to pid or inherited from parent.
     * Thus we restore it right here to let our kids inherit
     * one in case they need it.
     *
     * PGIDs are restored late when all tasks are forked and
     * we can call setpgid() on custom values.
     */

    if current_vpid == current_sid {
        log::info!("Restoring {} to {} sid", current_vpid, current_sid);
        let sid = unsafe { libc::setsid() };
        if sid != current_sid {
            log::error!("Can't restore sid ({})", sid);
            unsafe { libc::exit(1) };
        }
    } else {
        let sid = unsafe { libc::getsid(0) };
        if sid != current_sid {
            // Skip the root task if it's not init
            if is_root && current_vpid != INIT_PID {
                return;
            }
            log::error!(
                "Requested sid {} doesn't match inherited {}",
                current_sid,
                sid
            );
            unsafe { libc::exit(1) };
        }
    }
}

/// Restore SID using shared pstree item.
fn restore_sid_shared() {
    use std::sync::atomic::Ordering;

    let current = match current_shared() {
        Some(c) => c,
        None => return,
    };

    let current_vpid = current.vpid();
    let current_sid = current.sid.load(Ordering::SeqCst);
    let is_root = current.parent_idx.load(Ordering::SeqCst) < 0;

    if current_vpid == current_sid {
        log::info!("Restoring {} to {} sid", current_vpid, current_sid);
        let sid = unsafe { libc::setsid() };
        if sid != current_sid {
            log::error!("Can't restore sid ({})", sid);
            unsafe { libc::exit(1) };
        }
    } else {
        let sid = unsafe { libc::getsid(0) };
        if sid != current_sid {
            // Skip the root task if it's not init
            if is_root && current_vpid != INIT_PID {
                return;
            }
            log::error!(
                "Requested sid {} doesn't match inherited {}",
                current_sid,
                sid
            );
            unsafe { libc::exit(1) };
        }
    }
}

pub fn restore_pgid(store: &PidStore, current_idx: usize) {
    /*
     * Unlike sessions, process groups (a.k.a. pgids) can be joined
     * by any task, provided the task with pid == pgid (group leader)
     * exists. Thus, in order to restore pgid we must make sure that
     * group leader was born and created the group, then join one.
     *
     * We do this _before_ finishing the forking stage to make sure
     * helpers are still with us.
     */

    let item = store.get_item(current_idx).unwrap();
    let current_vpid = vpid(item);
    let my_pgid = item.pgid;

    log::info!("Restoring {} to {} pgid", current_vpid, my_pgid);

    let pgid = unsafe { libc::getpgrp() };
    if my_pgid == pgid {
        return;
    }

    if my_pgid != current_vpid {
        /*
         * Wait for leader to become such.
         * Missing leader means we're going to crtools
         * group (-j option).
         */
        if let Some(rst_info) = rsti(item) {
            if let Some(leader_idx) = rst_info.pgrp_leader_idx {
                let leader = store.get_item(leader_idx).unwrap();
                assert!(
                    my_pgid == vpid(leader),
                    "BUG: pgid != vpid(leader)"
                );
                if let Some(leader_rsti) = rsti(leader) {
                    leader_rsti.pgrp_set.wait_until(1);
                }
            }
        }
    }

    log::info!("\twill call setpgid, mine pgid is {}", pgid);
    if unsafe { libc::setpgid(0, my_pgid) } != 0 {
        log::error!(
            "Can't restore pgid ({}/{}->{}))",
            current_vpid,
            pgid,
            my_pgid
        );
        unsafe { libc::exit(1) };
    }

    if my_pgid == current_vpid {
        if let Some(rst_info) = rsti(item) {
            rst_info.pgrp_set.set_and_wake(1);
        }
    }
}

pub fn create_children_and_session<F>(
    store: &mut PidStore,
    current_idx: usize,
    dfd: RawFd,
    sfd_state: &ServiceFdState,
    callback: F,
) -> i32
where
    F: FnOnce(*mut c_void) -> i32 + Copy,
{
    let mut ret: libc::pid_t;

    log::info!("Restoring children in alien sessions:");

    // First pass: children that need to be forked before setsid
    let children_before_setsid: Vec<usize> = {
        let item = store.get_item(current_idx).unwrap();
        let parent = item;
        item.children
            .iter()
            .filter(|&&child_idx| {
                let child = store.get_item(child_idx).unwrap();
                restore_before_setsid(child, parent)
            })
            .copied()
            .collect()
    };

    for child_idx in children_before_setsid {
        {
            let child = store.get_item(child_idx).unwrap();
            let _item = store.get_item(current_idx).unwrap();
            let child_born_sid = if child.born_sid == -1 {
                child.sid
            } else {
                child.born_sid
            };
            assert!(
                child_born_sid == -1 || unsafe { libc::getsid(0) } == child_born_sid,
                "BUG: born_sid mismatch"
            );
        }

        ret = fork_with_pid(store, child_idx, dfd, sfd_state, callback);
        if ret < 0 {
            return ret;
        }
    }

    // Restore session ID if we have a parent
    {
        let item = store.get_item(current_idx).unwrap();
        if item.parent_idx.is_some() {
            restore_sid(store, current_idx);
        }
    }

    log::info!("Restoring children in our session:");

    // Second pass: children that need to be forked after setsid
    let children_after_setsid: Vec<usize> = {
        let item = store.get_item(current_idx).unwrap();
        let parent = item;
        item.children
            .iter()
            .filter(|&&child_idx| {
                let child = store.get_item(child_idx).unwrap();
                !restore_before_setsid(child, parent)
            })
            .copied()
            .collect()
    };

    for child_idx in children_after_setsid {
        ret = fork_with_pid(store, child_idx, dfd, sfd_state, callback);
        if ret < 0 {
            return ret;
        }
    }

    0
}

pub fn fork_with_pid<F>(
    store: &mut PidStore,
    item_idx: usize,
    dfd: RawFd,
    sfd_state: &ServiceFdState,
    callback: F,
) -> libc::pid_t
where
    F: FnOnce(*mut c_void) -> i32 + Copy,
{
    let (pid, is_helper, parent_idx) = {
        let item = match store.get_item(item_idx) {
            Some(i) => i,
            None => return -1,
        };
        (vpid(item), item.pid.state == TaskState::Helper, item.parent_idx)
    };

    let mut external_pidns = false;

    // Get cgroup parameters
    let (cg_set, parent_cg_set, parent_has_fdt) = {
        let item = store.get_item(item_idx).unwrap();
        let cg_set = rsti(item).map(|r| r.cg_set).unwrap_or(0);
        let parent_cg_set = parent_idx.and_then(|pidx| {
            store.get_item(pidx).and_then(|p| rsti(p).map(|r| r.cg_set))
        });
        let parent_has_fdt = parent_idx
            .and_then(|pidx| store.get_item(pidx).and_then(|p| rsti(p)))
            .map(|r| r.fdt.is_some())
            .unwrap_or(false);
        (cg_set, parent_cg_set, parent_has_fdt)
    };

    // Copy service fd state for child
    let mut sfd_arr = [-1i32; 16];
    for i in 0..16 {
        let sfd_type = unsafe { std::mem::transmute::<i32, SfdType>(i) };
        sfd_arr[i as usize] = sfd_state.get_service_fd(sfd_type);
    }

    let service_fd_id = {
        let item = store.get_item(item_idx).unwrap();
        rsti(item).map(|r| r.service_fd_id).unwrap_or(0)
    };

    // Get shared store and shared item pointers
    let shared_store_ptr = shared_store_mut()
        .map(|s| s as *mut SharedPstreeStore)
        .unwrap_or(std::ptr::null_mut());

    let shared_item_ptr = if !shared_store_ptr.is_null() {
        unsafe {
            let store_ref = &mut *shared_store_ptr;
            store_ref
                .get_item_mut(item_idx as i32)
                .map(|i| i as *mut SharedPstreeItem)
                .unwrap_or(std::ptr::null_mut())
        }
    } else {
        std::ptr::null_mut()
    };

    let mut ca = CrCloneArg {
        item_idx,
        clone_flags: 0,
        core: None,
        sfd_map: 0, // Will be computed from sfd_arr
        sfd_arr,
        service_fd_base: sfd_state.get_service_fd_base(),
        service_fd_id,
        manage_cgroups: opts().manage_cgroups,
        cg_set,
        parent_cg_set,
        has_parent: parent_idx.is_some(),
        parent_has_fdt,
        max_fd: 0, // Will be computed
        fdt_nr: 1, // Default, updated if fdt exists
        dfd,
        shared_item: shared_item_ptr,
        shared_store: shared_store_ptr,
    };

    if !is_helper {
        let mut core = match open_core(pid, dfd) {
            Ok(c) => c,
            Err(_) => return -1,
        };

        {
            let item = store.get_item_mut(item_idx).unwrap();
            if check_core(&mut core, item) != 0 {
                return -1;
            }

            let tc = core.tc.as_ref().unwrap();
            item.pid.state = TaskState::from(tc.task_state as i32);

            /*
             * Zombie tasks' cgroup is not dumped/restored.
             * cg_set == 0 is skipped in prepare_task_cgroup()
             */
            if item.pid.state == TaskState::Dead {
                if let Some(rsti) = rsti_mut(item) {
                    rsti.cg_set = 0;
                }
            } else {
                let cg_set = if let Some(thread_core) = &core.thread_core {
                    if thread_core.cg_set.is_some() {
                        thread_core.cg_set.unwrap()
                    } else {
                        tc.cg_set.unwrap_or(0)
                    }
                } else {
                    tc.cg_set.unwrap_or(0)
                };
                if let Some(rsti) = rsti_mut(item) {
                    rsti.cg_set = cg_set;
                }
            }

            if tc.stop_signo.is_some() {
                item.pid.stop_signo = tc.stop_signo.unwrap() as i32;
            }

            if item.pid.state != TaskState::Dead && !task_alive(item) {
                log::error!("Unknown task state {:?}", item.pid.state);
                return -1;
            }

            /*
             * By default we assume that seccomp is not
             * used at all (especially on dead task). Later
             * we will walk over all threads and check in
             * details if filter is present setting up
             * this flag as appropriate.
             */
            if let Some(rsti) = rsti_mut(item) {
                rsti.has_seccomp = false;
            }

            if root_item_idx_try() == Some(item_idx) {
                maybe_clone_parent(item, &core);
            }
        }

        ca.core = Some(core);
    } else {
        /*
         * Helper entry will not get moved around and thus
         * will live in the parent's cgset.
         */
        if let Some(parent_idx) = parent_idx {
            let parent_cg_set = store
                .get_item(parent_idx)
                .and_then(|p| rsti(p))
                .map(|r| r.cg_set)
                .unwrap_or(0);

            if let Some(item) = store.get_item_mut(item_idx) {
                if let Some(rsti) = rsti_mut(item) {
                    rsti.cg_set = parent_cg_set;
                }
            }
        }
    }

    {
        let item = store.get_item(item_idx).unwrap();
        if let Some(ref ids) = item.ids {
            if let Some(pid_ns_id) = ids.pid_ns_id {
                let pid_ns = lookup_ns_by_id_ptr(pid_ns_id, &ns_desc::PID);
                if !pid_ns.is_null() {
                    let pid_ns_ref = unsafe { &*pid_ns };
                    if current_item_idx().is_none() && pid_ns_ref.ext_key.is_some() {
                        external_pidns = true;
                    }
                }
            }
        }
    }

    if external_pidns {
        if pid == INIT_PID {
            log::error!("Unable to restore into an empty PID namespace");
            return -1;
        }

        let item = store.get_item(item_idx).unwrap();
        let ids = item.ids.as_ref().unwrap();
        let pid_ns_id = ids.pid_ns_id.unwrap();
        let pid_ns = lookup_ns_by_id_ptr(pid_ns_id, &ns_desc::PID);
        let ext_key = unsafe { (*pid_ns).ext_key.as_ref().unwrap() };

        let fd = inherit_fd_lookup_id(ext_key);
        if fd < 0 {
            log::error!("Unable to find an external pidns: {}", ext_key);
            return -1;
        }

        let ret = switch_ns_by_fd(fd, &ns_desc::PID, false);
        unsafe { libc::close(fd) };
        if ret.is_err() {
            log::error!("Unable to enter existing PID namespace");
            return -1;
        }

        log::info!("Inheriting external pidns {} for {}", ext_key, pid);
    }

    let clone_flags = {
        let item = store.get_item(item_idx).unwrap();
        rsti(item).map(|r| r.clone_flags).unwrap_or(0)
    };
    ca.clone_flags = clone_flags;

    assert!(
        (clone_flags & libc::CLONE_VM as u64) == 0,
        "BUG: CLONE_VM set"
    );

    log::info!(
        "Forking task with {} pid (flags 0x{:x})",
        pid,
        clone_flags
    );

    let ret: libc::pid_t;

    if (clone_flags & libc::CLONE_NEWPID as u64) == 0 {
        lock_last_pid();

        if !kdat().has_clone3_set_tid {
            let set_pid_result = set_next_pid(pid);

            if set_pid_result.is_err() {
                log::error!("Setting PID failed");
                unlock_last_pid();
                return -1;
            }
        }
    } else if !external_pidns && pid != INIT_PID {
        log::error!(
            "First PID in a PID namespace needs to be {} and not {}",
            INIT_PID,
            pid
        );
        return -1;
    }

    let ca_ptr = Box::into_raw(Box::new(ca));

    let clone_flags_int =
        clone_flags as i32 & !(libc::CLONE_NEWNET | libc::CLONE_NEWCGROUP | 0x00000080);

    if kdat().has_clone3_set_tid {
        ret = clone3_with_pid_noasan(
            callback,
            ca_ptr as *mut c_void,
            clone_flags_int,
            libc::SIGCHLD,
            pid,
        );
    } else {
        /*
         * Some kernel modules, such as network packet generator
         * run kernel thread upon net-namespace creation taking
         * the @pid we've been requesting via LAST_PID_PATH interface
         * so that we can't restore a take with pid needed.
         *
         * Here is an idea -- unshare net namespace in callee instead.
         */
        /*
         * The cgroup namespace is also unshared explicitly in the
         * move_in_cgroup(), so drop this flag here as well.
         */
        let flags = clone_flags_int | libc::SIGCHLD;
        ret = clone_noasan(callback, flags, ca_ptr as *mut c_void);
    }

    let ca_box = unsafe { Box::from_raw(ca_ptr) };

    if ret < 0 {
        log::error!("Can't fork for {}", pid);
        let errno = unsafe { *libc::__errno_location() };
        if errno == libc::EEXIST {
            set_cr_errno(libc::EEXIST);
        }
        if (clone_flags & libc::CLONE_NEWPID as u64) == 0 {
            unlock_last_pid();
        }
        return ret;
    }

    if root_item_idx_try() == Some(item_idx) {
        let item = store.get_item_mut(item_idx).unwrap();
        item.pid.real = ret;
        log::debug!("PID: real {} virt {}", item.pid.real, vpid(item));
    }

    let item = store.get_item(item_idx).unwrap();
    arch_shstk_unlock(item, ca_box.core.as_ref(), pid);

    if (clone_flags & libc::CLONE_NEWPID as u64) == 0 {
        unlock_last_pid();
    }

    ret
}

#[cfg(target_arch = "x86_64")]
fn task_needs_shstk(item: &PstreeItem, core: &CoreEntry) -> bool {
    if !task_alive(item) {
        return false;
    }

    if let Some(thread_info) = &core.thread_info {
        if let Some(xsave) = &thread_info.fpregs.xsave {
            if let Some(cet) = &xsave.cet {
                if cet.cet & ARCH_SHSTK_SHSTK != 0 {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(not(target_arch = "x86_64"))]
fn task_needs_shstk(_item: &PstreeItem, _core: &CoreEntry) -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
pub fn arch_shstk_unlock(item: &PstreeItem, core: Option<&CoreEntry>, pid: libc::pid_t) -> i32 {
    let core = match core {
        Some(c) => c,
        None => return 0,
    };

    /*
     * CRIU runs with no shadow stack and the task does not need one,
     * nothing to do.
     */
    if !kdat().has_shstk && !task_needs_shstk(item, core) {
        return 0;
    }

    let rsti = match rsti(item) {
        Some(r) => r,
        None => return 0,
    };

    rsti.shstk_enable.wait_until(1);

    let mut ret: i32 = -1;

    if unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, 0, 0) } != 0 {
        log::error!("Cannot attach to {}", pid);
        goto_futex_wake(&rsti.shstk_unlock);
        return ret;
    }

    if unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, pid, 0, 0) } != 0 {
        log::error!("Cannot interrupt the {} task", pid);
        goto_detach(pid, &rsti.shstk_unlock);
        return ret;
    }

    let mut status: i32 = 0;
    if unsafe { libc::wait4(pid, &mut status, libc::__WALL, std::ptr::null_mut()) } != pid {
        log::error!("waitpid({}) failed", pid);
        goto_detach(pid, &rsti.shstk_unlock);
        return ret;
    }

    let features = ARCH_SHSTK_SHSTK | ARCH_SHSTK_WRSS;
    if unsafe {
        libc::ptrace(
            PTRACE_ARCH_PRCTL,
            pid,
            features as libc::c_ulong,
            ARCH_SHSTK_UNLOCK as libc::c_ulong,
        )
    } != 0
    {
        log::error!("Cannot unlock CET for {} task", pid);
        goto_detach(pid, &rsti.shstk_unlock);
        return ret;
    }

    if unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, std::ptr::null::<()>(), 0) } != 0 {
        log::error!("Unable to detach {}", pid);
        goto_futex_wake(&rsti.shstk_unlock);
        return ret;
    }

    ret = 0;
    rsti.shstk_unlock.set_and_wake(1);

    ret
}

#[cfg(target_arch = "x86_64")]
fn goto_detach(pid: libc::pid_t, shstk_unlock: &Futex) {
    unsafe {
        libc::ptrace(libc::PTRACE_DETACH, pid, std::ptr::null::<()>(), 0);
    }
    goto_futex_wake(shstk_unlock);
}

#[cfg(target_arch = "x86_64")]
fn goto_futex_wake(shstk_unlock: &Futex) {
    shstk_unlock.set_and_wake(1);
}

#[cfg(not(target_arch = "x86_64"))]
pub fn arch_shstk_unlock(
    _item: &PstreeItem,
    _core: Option<&CoreEntry>,
    _pid: libc::pid_t,
) -> i32 {
    0
}

#[cfg(target_arch = "x86_64")]
pub fn arch_shstk_trampoline<F>(
    item: &PstreeItem,
    core: &CoreEntry,
    func: F,
    arg: *mut c_void,
) -> i32
where
    F: FnOnce(*mut c_void) -> i32,
{
    /*
     * If task does not need shadow stack but CRIU runs with shadow
     * stack enabled, we should disable it before continuing with
     * restore
     */
    if !task_needs_shstk(item, core) {
        // TODO: if kdat.has_shstk && shstk_disable(item) { return -1; }
        return func(arg);
    }

    // For full shadow stack support, inline assembly would be needed here.
    // For now, just call the function directly.
    func(arg)
}

#[cfg(not(target_arch = "x86_64"))]
pub fn arch_shstk_trampoline<F>(
    _item: &PstreeItem,
    _core: &CoreEntry,
    func: F,
    arg: *mut c_void,
) -> i32
where
    F: FnOnce(*mut c_void) -> i32,
{
    func(arg)
}

pub fn restore_task_with_children(arg: *mut c_void) -> i32 {
    let ca = unsafe { &*(arg as *const CrCloneArg) };

    // Get item and core from the clone arg
    // Note: In the full implementation, this would get item from store
    // and core from ca.core. For now, we return an error since we need
    // more infrastructure.

    if ca.core.is_none() {
        // Helper task - no core entry
        return __restore_task_with_children(arg);
    }

    let _core = ca.core.as_ref().unwrap();

    // For now, call the inner function directly since we don't have
    // the full item/store infrastructure passed through.
    __restore_task_with_children(arg)
}

static mut HELPERS: Vec<libc::pid_t> = Vec::new();
static mut ZOMBIES: Vec<libc::pid_t> = Vec::new();

pub fn add_helper_pid(pid: libc::pid_t) {
    unsafe { HELPERS.push(pid) };
}

pub fn add_zombie_pid(pid: libc::pid_t) {
    unsafe { ZOMBIES.push(pid) };
}

extern "C" fn sigchld_handler(
    _signal: libc::c_int,
    siginfo: *mut libc::siginfo_t,
    _data: *mut libc::c_void,
) {
    unsafe {
        let si = &*siginfo;
        let pid = si.si_pid();
        let status = si.si_status();

        // We can ignore helpers that die, we expect them to after
        // CR_STATE_RESTORE is finished.
        for &h in HELPERS.iter() {
            if pid == h {
                return;
            }
        }
        for &z in ZOMBIES.iter() {
            if pid == z {
                return;
            }
        }

        let reason = match si.si_code {
            libc::CLD_EXITED => "exited, status=",
            libc::CLD_KILLED => "killed by signal",
            libc::CLD_DUMPED => "terminated abnormally with",
            libc::CLD_TRAPPED => "trapped with",
            libc::CLD_STOPPED => "stopped with",
            _ => "disappeared with",
        };

        // Cannot use log! macros in signal handler, use write to stderr
        let msg = format!("Task {} {} {}\n", pid, reason, status);
        libc::write(2, msg.as_ptr() as *const _, msg.len());

        // Abort task_entries
        let te = task_entries();
        te.nr_in_progress.abort_and_wake();

        // sa_restorer may be unmapped, so we can't go back to userspace
        libc::kill(libc::getpid(), libc::SIGSTOP);
        libc::_exit(1);
    }
}

pub fn criu_signals_setup() -> i32 {
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };

    let ret = unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut act) };
    if ret < 0 {
        log::error!("sigaction() failed");
        return -1;
    }

    act.sa_flags |= libc::SA_NOCLDSTOP | libc::SA_SIGINFO | libc::SA_RESTART;
    act.sa_sigaction = sigchld_handler as usize;
    unsafe {
        libc::sigemptyset(&mut act.sa_mask);
        libc::sigaddset(&mut act.sa_mask, libc::SIGCHLD);
    }

    let ret = unsafe { libc::sigaction(libc::SIGCHLD, &act, std::ptr::null_mut()) };
    if ret < 0 {
        log::error!("sigaction() failed");
        return -1;
    }

    /*
     * The block mask will be restored in sigreturn.
     *
     * TODO: This code should be removed, when a freezer will be added.
     */
    let mut blockmask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigfillset(&mut blockmask);
        libc::sigdelset(&mut blockmask, libc::SIGCHLD);
    }

    /*
     * Here we use SIG_SETMASK instead of SIG_BLOCK to avoid the case where
     * we've been forked from a parent who had blocked SIGCHLD. If SIGCHLD
     * is blocked when a task dies (e.g. if the task fails to restore
     * somehow), we hang because our SIGCHLD handler is never run. Since we
     * depend on SIGCHLD being unblocked, let's set the mask explicitly.
     */
    let ret = unsafe { libc::sigprocmask(libc::SIG_SETMASK, &blockmask, std::ptr::null_mut()) };
    if ret < 0 {
        log::error!("Can't block signals");
        return -1;
    }

    0
}

pub fn ignore_kids() {
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
    }
}

pub fn reap_zombies() {
    unsafe {
        for &z in ZOMBIES.iter() {
            libc::waitpid(z, std::ptr::null_mut(), 0);
        }
    }
}

fn write_pidfile(pid: libc::pid_t) -> i32 {
    use std::ffi::CString;

    let pidfile = match &opts().pidfile {
        Some(p) => p.clone(),
        None => return 0,
    };

    let c_pidfile = match CString::new(pidfile.as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            log::error!("pidfile: Invalid path");
            return -1;
        }
    };

    let fd = unsafe {
        libc::open(
            c_pidfile.as_ptr(),
            libc::O_WRONLY | libc::O_EXCL | libc::O_CREAT,
            0o600,
        )
    };
    if fd < 0 {
        log::error!("pidfile: Can't open {}", pidfile);
        return -1;
    }

    let pid_str = format!("{}", pid);
    let written = unsafe { libc::write(fd, pid_str.as_ptr() as *const _, pid_str.len()) };

    let result = if written < 0 {
        log::error!("pidfile: Can't write pid {} to {}", pid, pidfile);
        -1
    } else if (written as usize) < pid_str.len() {
        log::error!("pidfile: Can't write pid {} to {}", pid, pidfile);
        -1
    } else {
        log::debug!(
            "pidfile: Wrote pid {} to {} ({} bytes)",
            pid,
            pidfile,
            written
        );
        0
    };

    unsafe { libc::close(fd) };
    result
}

pub fn write_restored_pid() -> i32 {
    use crate::criu::pstree::root_item_pid_real;

    if opts().pidfile.is_none() {
        return 0;
    }

    let pid = root_item_pid_real();

    if write_pidfile(pid) < 0 {
        log::error!("Can't write pidfile");
        return -1;
    }

    0
}

fn open_detach_mount(dir: &str) -> RawFd {
    use std::ffi::CString;

    let c_dir = match CString::new(dir) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    let fd = unsafe { libc::open(c_dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY, 0) };
    if fd < 0 {
        log::error!("Can't open directory {}", dir);
        return -1;
    }

    let ret = unsafe { libc::umount2(c_dir.as_ptr(), libc::MNT_DETACH) };
    if ret != 0 {
        log::error!("Can't detach mount {}", dir);
        unsafe { libc::close(fd) };
        return -1;
    }

    let ret = unsafe { libc::rmdir(c_dir.as_ptr()) };
    if ret != 0 {
        log::error!("Can't remove tmp dir {}", dir);
        unsafe { libc::close(fd) };
        return -1;
    }

    fd
}

fn __legacy_mount_proc() -> RawFd {
    use std::ffi::CString;

    let proc_mountpoint = "/tmp/crtools-proc.XXXXXX";
    let mut template = proc_mountpoint.as_bytes().to_vec();
    template.push(0);

    let tmpdir = unsafe { libc::mkdtemp(template.as_mut_ptr() as *mut i8) };
    if tmpdir.is_null() {
        log::error!("mkdtemp failed {}", proc_mountpoint);
        return -1;
    }

    let dir = unsafe { std::ffi::CStr::from_ptr(tmpdir) };
    let dir_str = match dir.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    log::info!("Mount procfs in {}", dir_str);

    let fstype = CString::new("proc").unwrap();
    let source = CString::new("proc").unwrap();
    let flags = libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV;

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            tmpdir,
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };

    if ret != 0 {
        log::error!("mount failed");
        unsafe { libc::rmdir(tmpdir) };
        return -1;
    }

    open_detach_mount(dir_str)
}

fn mount_detached_fs(fsname: &str) -> RawFd {
    // fsopen/fsmount APIs - requires kernel 5.2+
    // For now, fall back to legacy mount
    let _ = fsname;
    -1
}

fn set_proc_fd(sfd_state: &mut ServiceFdState, fd: RawFd) -> i32 {
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        log::error!("dup() failed");
        return -1;
    }

    if sfd_state.install_service_fd(SfdType::ProcFdOff, dup_fd) < 0 {
        return -1;
    }

    0
}

pub fn mount_proc(sfd_state: &mut ServiceFdState) -> i32 {
    let ns_mask = root_ns_mask();

    let fd = if ns_mask == 0 {
        unsafe { libc::open(b"/proc\0".as_ptr() as *const i8, libc::O_DIRECTORY) }
    } else if kdat().has_fsopen {
        mount_detached_fs("proc")
    } else {
        __legacy_mount_proc()
    };

    if fd < 0 {
        return fd;
    }

    let ret = set_proc_fd(sfd_state, fd);
    unsafe { libc::close(fd) };
    ret
}

const SIGMAX: i32 = 64;

fn sig_fatal(sig: i32) -> bool {
    match sig {
        libc::SIGHUP | libc::SIGINT | libc::SIGQUIT | libc::SIGILL |
        libc::SIGABRT | libc::SIGFPE | libc::SIGKILL | libc::SIGSEGV |
        libc::SIGPIPE | libc::SIGALRM | libc::SIGTERM | libc::SIGUSR1 |
        libc::SIGUSR2 | libc::SIGBUS | libc::SIGPOLL | libc::SIGPROF |
        libc::SIGSYS | libc::SIGTRAP | libc::SIGVTALRM | libc::SIGXCPU |
        libc::SIGXFSZ | libc::SIGSTKFLT | libc::SIGPWR => true,
        _ => false,
    }
}

fn zombie_prepare_signals() {
    unsafe {
        let mut blockmask: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut blockmask);
        libc::sigprocmask(libc::SIG_UNBLOCK, &blockmask, std::ptr::null_mut());

        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = libc::SIG_DFL;

        for sig in 1..=SIGMAX {
            libc::sigaction(sig, &act, std::ptr::null_mut());
        }
    }
}

fn restore_one_zombie(item: &PstreeItem, core: &CoreEntry) -> i32 {
    let tc = match &core.tc {
        Some(tc) => tc,
        None => {
            log::error!("restore_one_zombie: missing tc");
            return -1;
        }
    };

    let exit_code = tc.exit_code as i32;
    log::info!("Restoring zombie with {} code", exit_code);

    // prepare_fds(current) - stub for now
    // lazy_pages_setup_zombie - stub for now

    let comm = tc.comm.as_bytes();
    if comm.len() > 0 {
        unsafe {
            libc::prctl(libc::PR_SET_NAME, comm.as_ptr() as libc::c_ulong, 0, 0, 0);
        }
    }

    // wait_exiting_children and zombie_prepare_signals are needed for full impl
    zombie_prepare_signals();

    if (exit_code & 0x7f) != 0 {
        let mut signr = exit_code & 0x7f;

        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };

        if !sig_fatal(signr) {
            log::warn!("Exit with non fatal signal ignored");
            signr = libc::SIGABRT;
        }

        let pid = vpid(item);
        if unsafe { libc::kill(pid, signr) } < 0 {
            log::error!("Can't kill myself, will just exit");
        }

        unsafe { libc::exit(0) };
    }

    unsafe { libc::exit((exit_code >> 8) & 0x7f) };
}

fn restore_one_helper(item: &PstreeItem, sfd_state: &ServiceFdState) -> i32 {
    let _ = (item, sfd_state);
    // prepare_fds(current)
    // wait_exiting_children()
    // close_image_dir()
    // close_proc()
    // close service fds

    log::info!("restore_one_helper: stub implementation");
    0
}

fn restore_one_alive_task(_item: &PstreeItem, _core: &CoreEntry) -> i32 {
    // This is the most complex restore function.
    // It requires:
    // - rst_mem_switch_to_private
    // - prepare_fds
    // - prepare_file_locks
    // - open_vmas
    // - prepare_aios
    // - fixup_sysv_shmems
    // - open_cores
    // - prepare_signals
    // - prepare_posix_timers
    // - prepare_rlimits
    // - collect_helper_pids
    // - collect_zombie_pids
    // - collect_inotify_fds
    // - prepare_proc_misc
    // - prepare_tcp_socks
    // - prepare_timerfds
    // - seccomp_prepare_threads
    // - prepare_itimers
    // - prepare_mm
    // - prepare_vmas
    // - restore_task_net_ns
    // - setup_uffd
    // - arch_shstk_prepare
    // - sigreturn_restore

    log::warn!("restore_one_alive_task: stub implementation - needs full memory/fd restoration");
    -1
}

pub fn restore_one_task(
    item: &PstreeItem,
    core: Option<&CoreEntry>,
    sfd_state: &ServiceFdState,
) -> i32 {
    let core = match core {
        Some(c) => c,
        None => {
            log::error!("restore_one_task: missing core entry");
            return -1;
        }
    };

    let ret = if task_alive(item) {
        restore_one_alive_task(item, core)
    } else if item.pid.state == TaskState::Dead {
        restore_one_zombie(item, core)
    } else if item.pid.state == TaskState::Helper {
        restore_one_helper(item, sfd_state)
    } else {
        let state = match &core.tc {
            Some(tc) => tc.task_state,
            None => 0,
        };
        log::error!("Unknown state in code {}", state);
        -1
    };

    ret
}

fn __restore_task_with_children(arg: *mut c_void) -> i32 {
    use crate::criu::cgroup::restore_task_cgroup;
    use crate::criu::log::log_init_by_pid;

    let ca = unsafe { &*(arg as *const CrCloneArg) };
    let item_idx = ca.item_idx;
    let is_root = !ca.has_parent;

    set_current_item_idx(Some(item_idx));

    // Set up shared pstree access for this process
    if !ca.shared_item.is_null() {
        set_current_shared(ca.shared_item);
    }

    let pid = unsafe { libc::getpid() };

    // For non-root tasks, update the real PID in shared memory
    if !is_root {
        if let Some(shared) = current_shared_mut() {
            // Read real PID from /proc/self (the PID in CRIU's namespace)
            let proc_self = std::fs::read_link("/proc/self");
            if let Ok(target) = proc_self {
                if let Some(pid_str) = target.to_str() {
                    if let Ok(real_pid) = pid_str.parse::<i32>() {
                        shared.pid.set_real(real_pid);
                        log::debug!("PID: real {} virt {}", real_pid, shared.vpid());
                    }
                }
            }
        }
    }

    // Verify our PID matches expected
    if let Some(shared) = current_shared() {
        let expected_vpid = shared.vpid();
        if expected_vpid != pid {
            log::error!("Pid {} does not match expected {}", pid, expected_vpid);
            goto_err();
            return -1;
        }
    }

    if log_init_by_pid(pid) != 0 {
        goto_err();
        return -1;
    }

    let mut sfd_state = ServiceFdState::new();
    sfd_state.set_service_fd_base(ca.service_fd_base);
    sfd_state.set_service_fd_id(ca.service_fd_id);
    for i in 1..16 {
        if ca.sfd_arr[i] >= 0 {
            let sfd_type = unsafe { std::mem::transmute::<i32, SfdType>(i as i32) };
            sfd_state.set_service_fd(sfd_type, ca.sfd_arr[i]);
        }
    }

    let cgroup_yard_fd = sfd_state.get_service_fd(SfdType::CgroupYard);

    if is_root {
        let ns_mask = root_ns_mask();

        /*
         * The root task has to be in its namespaces before executing
         * ACT_SETUP_NS scripts, so the root netns has to be created here
         */
        if (ns_mask & libc::CLONE_NEWNET as u64) != 0 {
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                log::error!("Can't unshare net-namespace");
                goto_err();
                return -1;
            }
        }

        // TODO: prepare_timens, set_opts_cap_eff
        // TODO: restore_finish_ns_stage(CR_STATE_ROOT_TASK, CR_STATE_PREPARE_NAMESPACES)
        // TODO: prepare_cgroup_namespace
    }

    // TODO: prepare_userns_creds if needed

    /*
     * Call this _before_ forking to optimize cgroups
     * restore -- if all tasks live in one set of cgroups
     * we will only move the root one there, others will
     * just have it inherited.
     */
    if restore_task_cgroup(
        ca.manage_cgroups,
        ca.cg_set,
        ca.parent_cg_set,
        cgroup_yard_fd,
    ) < 0
    {
        goto_err();
        return -1;
    }

    if is_root {
        // TODO: join_namespaces
        // TODO: restore_sid (for init)

        /*
         * We need non /proc proc mount for restoring pid and mount
         * namespaces and do not care for the rest of the cases.
         * Thus -- mount proc at custom location for any new namespace
         */
        if root_ns_mask() != 0 {
            if mount_proc(&mut sfd_state) != 0 {
                goto_err();
                return -1;
            }
        }

        // TODO: collect_images, prepare_namespace
        // TODO: restore_finish_ns_stage(CR_STATE_PREPARE_NAMESPACES, CR_STATE_FORKING)
        // TODO: root_prepare_shared
        // TODO: populate_root_fd_off
    }

    if setup_newborn_fds(
        &mut sfd_state,
        ca.has_parent,
        ca.parent_has_fdt,
        ca.clone_flags,
        ca.service_fd_id,
        ca.max_fd,
        ca.fdt_nr,
    ) != 0
    {
        goto_err();
        return -1;
    }

    // TODO: restore_task_mnt_ns, prepare_mappings, prepare_sigactions, open_transport_socket

    timing_start(RestoreTime::Fork as usize);

    if create_children_and_session_shared(ca.dfd, &sfd_state) != 0 {
        goto_err();
        return -1;
    }

    // Timing stop is handled after populate_pid_proc in CRIU

    let mut open_proc_self_pid: libc::pid_t = -1;
    let mut open_proc_pid: libc::pid_t = -1;
    if populate_pid_proc(&mut sfd_state, &mut open_proc_self_pid, &mut open_proc_pid, pid) != 0 {
        goto_err();
        return -1;
    }

    // TODO: unmap_guard_pages
    // TODO: restore_pgid
    // TODO: For root: restore_wait_other_tasks() / For child: restore_finish_stage(CR_STATE_FORKING)
    // TODO: restore_one_task(vpid(current), ca.core)

    0
}

fn populate_pid_proc(
    sfd_state: &mut ServiceFdState,
    open_proc_self_pid: &mut libc::pid_t,
    open_proc_pid: &mut libc::pid_t,
    current_vpid: libc::pid_t,
) -> i32 {
    use crate::criu::util::{open_pid_proc, PROC_SELF};

    if open_pid_proc(sfd_state, open_proc_self_pid, open_proc_pid, current_vpid) < 0 {
        log::error!("Can't open /proc/{}", current_vpid);
        return -1;
    }
    if open_pid_proc(sfd_state, open_proc_self_pid, open_proc_pid, PROC_SELF) < 0 {
        log::error!("Can't open PROC_SELF");
        return -1;
    }
    0
}

/// Determines if a child should be restored before setsid (shared version).
/// In CRIU, this checks if the child was born in the current session
/// before the parent did setsid (born_sid != -1 and born_sid == sid).
fn restore_before_setsid_shared(
    store: &SharedPstreeStore,
    child_idx: i32,
) -> bool {
    use std::sync::atomic::Ordering;
    if let Some(child) = store.get_item(child_idx) {
        let born_sid = child.born_sid.load(Ordering::SeqCst);
        if born_sid == -1 {
            return false;
        }
        let current_sid = unsafe { libc::getsid(0) };
        born_sid == current_sid
    } else {
        false
    }
}

/// Create children and restore session using shared pstree.
/// This function forks all children of the current task.
fn create_children_and_session_shared(
    dfd: RawFd,
    sfd_state: &ServiceFdState,
) -> i32 {
    use std::sync::atomic::Ordering;

    let store = match shared_store_mut() {
        Some(s) => s,
        None => {
            log::error!("create_children_and_session: no shared store");
            return -1;
        }
    };

    let current = match current_shared() {
        Some(c) => c,
        None => {
            log::error!("create_children_and_session: no current item");
            return -1;
        }
    };

    let nr_children = current.nr_children.load(Ordering::SeqCst) as usize;
    let is_root = current.parent_idx.load(Ordering::SeqCst) < 0;

    log::info!("Restoring children in alien sessions:");

    // First pass: fork children that need to be restored before setsid
    for i in 0..nr_children {
        let child_idx = match current.get_child(i) {
            Some(idx) => idx,
            None => continue,
        };

        if !restore_before_setsid_shared(store, child_idx) {
            continue;
        }

        // Verify born_sid matches current session
        if let Some(child) = store.get_item(child_idx) {
            let born_sid = child.born_sid.load(Ordering::SeqCst);
            let current_sid = unsafe { libc::getsid(0) };
            if born_sid != -1 && current_sid != born_sid {
                log::error!(
                    "BUG: born_sid {} != current_sid {}",
                    born_sid,
                    current_sid
                );
                return -1;
            }
        }

        let ret = fork_with_pid_shared(store, child_idx, dfd, sfd_state);
        if ret < 0 {
            return ret;
        }
    }

    // For non-root tasks, call restore_sid
    if !is_root {
        restore_sid_shared();
    }

    log::info!("Restoring children in our session:");

    // Second pass: fork children that are restored after setsid
    for i in 0..nr_children {
        let child_idx = match current.get_child(i) {
            Some(idx) => idx,
            None => continue,
        };

        if restore_before_setsid_shared(store, child_idx) {
            continue;
        }

        let ret = fork_with_pid_shared(store, child_idx, dfd, sfd_state);
        if ret < 0 {
            return ret;
        }
    }

    0
}

/// Fork a child using the shared pstree.
/// This is similar to fork_with_pid but uses SharedPstreeItem instead of PidStore.
fn fork_with_pid_shared(
    store: &mut SharedPstreeStore,
    item_idx: i32,
    dfd: RawFd,
    sfd_state: &ServiceFdState,
) -> i32 {
    use std::sync::atomic::Ordering;

    let shared_item = match store.get_item_mut(item_idx) {
        Some(i) => i as *mut SharedPstreeItem,
        None => return -1,
    };

    let (pid, state, clone_flags, parent_idx) = {
        let item = unsafe { &*shared_item };
        let pid = item.vpid();
        let state = item.pid.get_state();
        let clone_flags = item.rst.clone_flags.load(Ordering::SeqCst);
        let parent_idx = item.parent_idx.load(Ordering::SeqCst);
        (pid, state, clone_flags, parent_idx)
    };

    let is_helper = state == TaskState::Helper;

    // For now, skip opening core for helpers
    let core = if !is_helper {
        match open_core(pid, dfd) {
            Ok(c) => Some(c),
            Err(_) => return -1,
        }
    } else {
        None
    };

    // Update shared item state from core
    if let Some(ref c) = core {
        let item = unsafe { &mut *shared_item };
        if let Some(tc) = &c.tc {
            item.pid.set_state(TaskState::from(tc.task_state as i32));
            if tc.stop_signo.is_some() {
                item.pid.stop_signo.store(tc.stop_signo.unwrap() as i32, Ordering::SeqCst);
            }
        }
    }

    let cg_set = unsafe { (*shared_item).rst.cg_set.load(Ordering::SeqCst) };
    let parent_cg_set = if parent_idx >= 0 {
        store.get_item(parent_idx).map(|p| p.rst.cg_set.load(Ordering::SeqCst))
    } else {
        None
    };

    let parent_has_fdt = false; // TODO: implement FDT checking

    // Copy service fd state for child
    let mut sfd_arr = [-1i32; 16];
    for i in 0..16 {
        let sfd_type = unsafe { std::mem::transmute::<i32, SfdType>(i) };
        sfd_arr[i as usize] = sfd_state.get_service_fd(sfd_type);
    }

    let service_fd_id = unsafe { (*shared_item).rst.service_fd_id.load(Ordering::SeqCst) };

    let ca = CrCloneArg {
        item_idx: item_idx as usize,
        clone_flags,
        core,
        sfd_map: 0,
        sfd_arr,
        service_fd_base: sfd_state.get_service_fd_base(),
        service_fd_id,
        manage_cgroups: opts().manage_cgroups,
        cg_set,
        parent_cg_set,
        has_parent: parent_idx >= 0,
        parent_has_fdt,
        max_fd: 0,
        fdt_nr: 1,
        dfd,
        shared_item,
        shared_store: store as *mut SharedPstreeStore,
    };

    assert!(
        (clone_flags & libc::CLONE_VM as u64) == 0,
        "BUG: CLONE_VM set"
    );

    log::info!(
        "Forking task with {} pid (flags 0x{:x})",
        pid,
        clone_flags
    );

    let ret: libc::pid_t;
    let ca_ptr = Box::into_raw(Box::new(ca));

    let clone_flags_int =
        clone_flags as i32 & !(libc::CLONE_NEWNET | libc::CLONE_NEWCGROUP | 0x00000080);

    if (clone_flags & libc::CLONE_NEWPID as u64) == 0 {
        lock_last_pid();

        if !kdat().has_clone3_set_tid {
            let set_pid_result = set_next_pid(pid);

            if set_pid_result.is_err() {
                log::error!("Setting PID failed");
                unlock_last_pid();
                let _ = unsafe { Box::from_raw(ca_ptr) };
                return -1;
            }
        }
    } else if pid != INIT_PID {
        log::error!(
            "First PID in a PID namespace needs to be {} and not {}",
            INIT_PID,
            pid
        );
        let _ = unsafe { Box::from_raw(ca_ptr) };
        return -1;
    }

    if kdat().has_clone3_set_tid {
        ret = clone3_with_pid_noasan(
            __restore_task_with_children,
            ca_ptr as *mut c_void,
            clone_flags_int,
            libc::SIGCHLD,
            pid,
        );
    } else {
        let flags = clone_flags_int | libc::SIGCHLD;
        ret = clone_noasan(__restore_task_with_children, flags, ca_ptr as *mut c_void);
    }

    let _ca_box = unsafe { Box::from_raw(ca_ptr) };

    if ret < 0 {
        log::error!("Can't fork for {}", pid);
        let errno = unsafe { *libc::__errno_location() };
        if errno == libc::EEXIST {
            set_cr_errno(libc::EEXIST);
        }
        if (clone_flags & libc::CLONE_NEWPID as u64) == 0 {
            unlock_last_pid();
        }
        return ret;
    }

    // Root task's real PID is set by fork_with_pid, not here
    // Child tasks will set their own real PID in __restore_task_with_children

    if (clone_flags & libc::CLONE_NEWPID as u64) == 0 {
        unlock_last_pid();
    }

    ret
}

pub fn setup_newborn_fds(
    sfd_state: &mut ServiceFdState,
    has_parent: bool,
    parent_has_fdt: bool,
    clone_flags: u64,
    service_fd_id: i32,
    max_fd: i32,
    fdt_nr: i32,
) -> i32 {
    use crate::criu::files::close_old_fds;
    use crate::criu::servicefd::clone_service_fd;

    if clone_service_fd(sfd_state, service_fd_id, max_fd, fdt_nr, clone_flags) != 0 {
        return -1;
    }

    if !has_parent || (parent_has_fdt && (clone_flags & libc::CLONE_FILES as u64) == 0) {
        // When our parent has shared fd table, some of the table owners
        // may be already created. Files they open will be inherited
        // by current process, and here we close them. Also, service fds
        // of parent are closed here. And root_item closes the files,
        // that were inherited from criu process.
        if close_old_fds(sfd_state) != 0 {
            return -1;
        }
    }

    0
}

fn goto_err() {
    use crate::criu::task_entries::task_entries;
    let te = task_entries();
    te.nr_in_progress.abort_and_wake();
    unsafe { libc::exit(1) };
}

pub fn attach_to_tasks(store: &mut PidStore, root_seized: bool, root_item_idx: usize) -> i32 {
    use crate::compel::ptrace::ptrace_suspend_seccomp;
    use crate::criu::proc_parse::parse_threads;
    use crate::criu::util::arch_ptrace_restore;

    let item_count = store.items_count();
    for item_idx in 0..item_count {
        let item = match store.get_item(item_idx) {
            Some(i) => i,
            None => continue,
        };

        if !task_alive(item) {
            continue;
        }

        let nr_threads = item.nr_threads;
        let pid_real = item.pid.real;

        if nr_threads == 1 {
            if let Some(item) = store.get_item_mut(item_idx) {
                if !item.threads.is_empty() {
                    item.threads[0].real = pid_real;
                }
            }
        } else {
            match parse_threads(pid_real) {
                Ok(threads) => {
                    if let Some(item) = store.get_item_mut(item_idx) {
                        let len = threads.len();
                        item.threads = threads.into_iter().map(|t| {
                            let mut p = Pid::default();
                            p.real = t.real;
                            p.ns[0].virt = t.virt;
                            p
                        }).collect();
                        item.nr_threads = len as i32;
                    }
                }
                Err(_) => return -1,
            }
        }

        let item = match store.get_item(item_idx) {
            Some(i) => i,
            None => continue,
        };

        let nr_threads = item.nr_threads as usize;
        let has_seccomp = rsti(item).map(|r| r.has_seccomp).unwrap_or(false);

        for i in 0..nr_threads {
            let pid = item.threads.get(i).map(|t| t.real).unwrap_or(-1);
            if pid < 0 {
                continue;
            }

            if item_idx != root_item_idx || !root_seized || i != 0 {
                if unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, 0, 0) } != 0 {
                    log::error!("Can't attach to {}", pid);
                    return -1;
                }
            }

            if unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, pid, 0, 0) } != 0 {
                log::error!("Can't interrupt the {} task", pid);
                return -1;
            }

            let mut status: libc::c_int = 0;
            if unsafe { libc::wait4(pid, &mut status, libc::__WALL, std::ptr::null_mut()) } != pid {
                log::error!("waitpid({}) failed", pid);
                return -1;
            }

            if unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, std::ptr::null::<libc::c_void>(), libc::PTRACE_O_TRACESYSGOOD) } != 0 {
                log::error!("Unable to set PTRACE_O_TRACESYSGOOD for {}", pid);
                return -1;
            }

            if arch_ptrace_restore(pid, item_idx) != 0 {
                return -1;
            }

            /*
             * Suspend seccomp if necessary. We need to do this because
             * although seccomp is restored at the very end of the
             * restorer blob (and the final sigreturn is ok), here we're
             * doing an munmap in the process, which may be blocked by
             * seccomp and cause the task to be killed.
             */
            if has_seccomp {
                if ptrace_suspend_seccomp(pid).is_err() {
                    log::error!("failed to suspend seccomp, restore will probably fail...");
                }
            }

            if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, std::ptr::null::<libc::c_void>(), std::ptr::null::<libc::c_void>()) } != 0 {
                log::error!("Unable to resume {}", pid);
                return -1;
            }
        }
    }

    0
}

pub fn catch_tasks(store: &mut PidStore, _root_seized: bool) -> i32 {
    use crate::compel::infect::compel_stop_pie;
    use crate::criu::proc_parse::parse_threads;
    use crate::criu::util::{fault_injected, Faults};

    let nobp = fault_injected(Faults::NoBreakpoints) || !kdat().has_breakpoints;

    let item_count = store.items_count();
    for item_idx in 0..item_count {
        let item = match store.get_item(item_idx) {
            Some(i) => i,
            None => continue,
        };

        if !task_alive(item) {
            continue;
        }

        let nr_threads = item.nr_threads;
        let pid_real = item.pid.real;

        if nr_threads == 1 {
            if let Some(item) = store.get_item_mut(item_idx) {
                if !item.threads.is_empty() {
                    item.threads[0].real = pid_real;
                }
            }
        } else {
            match parse_threads(pid_real) {
                Ok(threads) => {
                    if let Some(item) = store.get_item_mut(item_idx) {
                        let len = threads.len();
                        item.threads = threads
                            .into_iter()
                            .map(|t| {
                                let mut p = Pid::default();
                                p.real = t.real;
                                p.ns[0].virt = t.virt;
                                p
                            })
                            .collect();
                        item.nr_threads = len as i32;
                    }
                }
                Err(_) => return -1,
            }
        }

        let item = match store.get_item(item_idx) {
            Some(i) => i,
            None => continue,
        };

        let breakpoint = rsti(item).map(|r| r.breakpoint).unwrap_or(0);
        let nr_threads = item.nr_threads as usize;

        for i in 0..nr_threads {
            let pid = match item.threads.get(i) {
                Some(t) => t.real,
                None => continue,
            };

            if unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, pid, 0, 0) } != 0 {
                log::error!("Can't interrupt the {} task", pid);
                return -1;
            }

            let mut status: libc::c_int = 0;
            if unsafe { libc::wait4(pid, &mut status, libc::__WALL, std::ptr::null_mut()) } != pid {
                log::error!("waitpid({}) failed", pid);
                return -1;
            }

            let bp_addr = breakpoint as *mut c_void;
            if let Err(_) = compel_stop_pie(pid, bp_addr, nobp) {
                return -1;
            }
        }
    }

    0
}

pub fn finalize_restore(store: &PidStore) {
    use crate::compel::infect::{compel_prepare_noctx, compel_unmap};

    let item_count = store.items_count();
    for item_idx in 0..item_count {
        let item = match store.get_item(item_idx) {
            Some(i) => i,
            None => continue,
        };

        if !task_alive(item) {
            continue;
        }

        let pid = item.pid.real;
        let munmap_restorer = rsti(item).map(|r| r.munmap_restorer).unwrap_or(0);
        let stop_signo = item.pid.stop_signo;
        let item_state = item.pid.state;

        // Unmap the restorer blob
        let ctl = match compel_prepare_noctx(pid) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut ctl = ctl;
        if compel_unmap(&mut ctl, munmap_restorer).is_err() {
            log::error!("Failed to unmap restorer from {}", pid);
        }

        if opts().final_state == TaskState::Stopped as i32 {
            unsafe { libc::kill(pid, libc::SIGSTOP) };
        } else if item_state == TaskState::Stopped {
            if stop_signo > 0 {
                unsafe { libc::kill(pid, stop_signo) };
            } else {
                unsafe { libc::kill(pid, libc::SIGSTOP) };
            }
        }
    }
}

pub fn arch_set_thread_regs_nosigrt(_thread: &Pid) -> i32 {
    0
}

/// Offset of rseq_cs field in struct criu_rseq
/// Layout: cpu_id_start (u32) + cpu_id (u32) = 8 bytes before rseq_cs
const RSEQ_CS_OFFSET: u64 = 8;

pub fn restore_rseq_cs(store: &mut PidStore) -> i32 {
    use crate::compel::ptrace::ptrace_poke_area;
    use crate::criu::proc_parse::parse_threads;
    use std::ffi::c_void;

    let item_count = store.items_count();
    for item_idx in 0..item_count {
        let item = match store.get_item(item_idx) {
            Some(i) => i,
            None => continue,
        };

        if !task_alive(item) {
            continue;
        }

        let nr_threads = item.nr_threads;
        let pid_real = item.pid.real;

        if nr_threads == 1 {
            if let Some(item) = store.get_item_mut(item_idx) {
                if !item.threads.is_empty() {
                    item.threads[0].real = pid_real;
                }
            }
        } else {
            match parse_threads(pid_real) {
                Ok(threads) => {
                    if let Some(item) = store.get_item_mut(item_idx) {
                        let len = threads.len();
                        item.threads = threads
                            .into_iter()
                            .map(|t| {
                                let mut p = Pid::default();
                                p.real = t.real;
                                p.ns[0].virt = t.virt;
                                p
                            })
                            .collect();
                        item.nr_threads = len as i32;
                    }
                }
                Err(_) => {
                    log::error!("restore_rseq_cs: parse_threads failed");
                    return -1;
                }
            }
        }

        let item = match store.get_item(item_idx) {
            Some(i) => i,
            None => continue,
        };

        let nr_threads = item.nr_threads as usize;

        // Get pointer to rseqe array base
        let rseqe_base = match rsti(item) {
            Some(rst) => match &rst.rseqe {
                Some(boxed) => boxed.as_ref() as *const super::pstree::RstRseq,
                None => {
                    log::error!("restore_rseq_cs: rsti(item)->rseqe is NULL");
                    return -1;
                }
            },
            None => {
                log::error!("restore_rseq_cs: rsti(item) is NULL");
                return -1;
            }
        };

        for i in 0..nr_threads {
            let pid = match item.threads.get(i) {
                Some(t) => t.real,
                None => continue,
            };

            // Access rseqe[i] via pointer arithmetic
            let rseqe = unsafe { &*rseqe_base.add(i) };

            if rseqe.rseq_cs_pointer == 0 || rseqe.rseq_abi_pointer == 0 {
                continue;
            }

            // decode_pointer: just cast u64 to *mut c_void
            let dest_addr = (rseqe.rseq_abi_pointer + RSEQ_CS_OFFSET) as *mut c_void;
            let src = &rseqe.rseq_cs_pointer as *const u64 as *const c_void;

            if ptrace_poke_area(pid, src, dest_addr, std::mem::size_of::<u64>()).is_err() {
                log::error!("Can't restore rseq_cs pointer (pid: {})", pid);
                return -1;
            }
        }
    }

    0
}

pub fn finalize_restore_detach(store: &PidStore) -> i32 {
    let item_count = store.items_count();
    for item_idx in 0..item_count {
        let item = match store.get_item(item_idx) {
            Some(i) => i,
            None => continue,
        };

        if !task_alive(item) {
            continue;
        }

        let nr_threads = item.nr_threads as usize;

        for i in 0..nr_threads {
            let thread = match item.threads.get(i) {
                Some(t) => t,
                None => continue,
            };

            let pid = thread.real;
            if pid < 0 {
                log::error!("pstree item has invalid pid {}", pid);
                continue;
            }

            if arch_set_thread_regs_nosigrt(thread) != 0 {
                log::error!("Restoring regs for {} failed", pid);
                return -1;
            }

            if unsafe {
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    pid,
                    std::ptr::null::<c_void>(),
                    0,
                )
            } != 0
            {
                log::error!("Unable to detach {}", pid);
                return -1;
            }
        }
    }

    0
}

/// Main restore orchestration function.
/// This is the entry point for the restore process after pstree is prepared.
///
/// Note: This is a partial implementation. Full implementation requires
/// additional infrastructure for namespace preparation and process forking.
pub fn restore_root_task(
    store: &mut PidStore,
    root_item_idx: usize,
    sfd_state: &mut ServiceFdState,
    fdstore_desc: &mut FdstoreDesc,
    dfd: RawFd,
) -> i32 {
    let mnt_ns_fd: RawFd = -1;

    let init = match store.get_item(root_item_idx) {
        Some(item) => item,
        None => {
            log::error!("Root item not found");
            return -1;
        }
    };

    let ret = run_scripts(ScriptAction::PreRestore);
    if ret != 0 {
        log::error!(
            "Aborting restore due to pre-restore script ret code {}",
            ret
        );
        return -1;
    }

    let fd = unsafe { libc::open(b"/proc\0".as_ptr() as *const i8, libc::O_DIRECTORY | libc::O_RDONLY) };
    if fd < 0 {
        log::error!("Unable to open /proc");
        return -1;
    }

    let ret = sfd_state.install_service_fd(SfdType::CrProcFdOff, fd);
    if ret < 0 {
        return -1;
    }

    if prepare_userns_hook() != 0 {
        return -1;
    }

    // Full namespace preparation would happen here via prepare_namespace_before_tasks
    // which requires mount_store, ns_ids, and externals parameters

    let init_vpid = vpid(init);
    let ns_mask = root_ns_mask();

    if init_vpid == INIT_PID {
        if (ns_mask & libc::CLONE_NEWPID as u64) == 0 {
            log::error!(
                "This process tree can only be restored in a new pid namespace.\n\
                 criu should be re-executed with the \"--namespace pid\" option."
            );
            return -1;
        }
    } else if (ns_mask & libc::CLONE_NEWPID as u64) != 0 {
        let ids = match init.ids {
            Some(ref ids) => ids,
            None => {
                log::error!("Root item missing ids");
                return -1;
            }
        };
        let pid_ns_id = ids.pid_ns_id.unwrap_or(0);
        let ns = lookup_ns_by_id_ptr(pid_ns_id, &ns_desc::PID);
        if ns.is_null() {
            log::error!("Can't restore pid namespace without the process init");
            return -1;
        }
        let ns_ref = unsafe { &*ns };
        if ns_ref.ext_key.is_none() {
            log::error!("Can't restore pid namespace without the process init");
            return -1;
        }
    }

    __restore_switch_stage_nw(CrState::RootTask);

    // Fork the root task with restore_task_with_children callback
    let ret = fork_with_pid(store, root_item_idx, dfd, sfd_state, restore_task_with_children);
    if ret < 0 {
        log::error!("Failed to fork root task");
        return goto_out_kill(store, root_item_idx, mnt_ns_fd);
    }

    // Update real pid in store
    if let Some(item) = store.get_item_mut(root_item_idx) {
        item.pid.real = ret;
    }

    restore_origin_ns_hook();

    // Continue with finish_restore when full implementation is complete
    finish_restore_stub(store, root_item_idx, sfd_state, fdstore_desc, dfd, mnt_ns_fd)
}

fn finish_restore_stub(
    store: &mut PidStore,
    root_item_idx: usize,
    sfd_state: &mut ServiceFdState,
    fdstore_desc: &FdstoreDesc,
    dfd: RawFd,
    mnt_ns_fd: RawFd,
) -> i32 {
    let _ = (store, root_item_idx, sfd_state, fdstore_desc, dfd, mnt_ns_fd);

    // This stub represents the post-fork restore stages
    // Full implementation would include:
    // - run_plugins(PostForking)
    // - restore_wait_inprogress_tasks
    // - apply_memfd_seals
    // - Handle zombie processes
    // - restore_switch_stage(RestoreSigchld)
    // - stop_usernsd, stop_cgroupd
    // - move_veth_to_bridge
    // - prepare_cgroup_properties
    // - depopulate_roots_yard
    // - network_unlock
    // - attach_to_tasks, catch_tasks
    // - lazy_pages_finish_restore
    // - compel_stop_on_syscall
    // - finalize_restore
    // - restore_rseq_cs
    // - finalize_restore_detach

    log::warn!("finish_restore_stub: placeholder - full implementation pending");
    0
}

fn goto_out_kill(store: &PidStore, root_item_idx: usize, _mnt_ns_fd: RawFd) -> i32 {
    kill_restore_tasks(store, root_item_idx);
    // depopulate_roots_yard and stop_usernsd require additional parameters
    // that are not available in this simplified error path
    __restore_switch_stage_nw(CrState::Fail);
    log::error!("Restoring FAILED.");
    -1
}

fn kill_restore_tasks(store: &PidStore, root_item_idx: usize) {
    let init = match store.get_item(root_item_idx) {
        Some(item) => item,
        None => return,
    };

    if vpid(init) == INIT_PID {
        if init.pid.real > 0 {
            unsafe { libc::kill(init.pid.real, libc::SIGKILL) };
        }
        let mut status: i32 = 0;
        if unsafe { libc::waitpid(init.pid.real, &mut status, 0) } < 0 {
            log::warn!("Unable to wait {}", init.pid.real);
        }
    } else {
        let item_count = store.items_count();
        for item_idx in 0..item_count {
            if let Some(item) = store.get_item(item_idx) {
                if item.pid.real > 0 {
                    unsafe { libc::kill(item.pid.real, libc::SIGKILL) };
                }
            }
        }
    }
}

pub fn crtools_prepare_shared(
    dfd: RawFd,
    sfd_state: &ServiceFdState,
    fdstore_desc: &mut FdstoreDesc,
) -> i32 {
    if prepare_memfd_inodes(dfd) != 0 {
        return -1;
    }

    if prepare_files(dfd) != 0 {
        return -1;
    }

    /* We might want to remove ghost files on failed restore */
    if collect_remaps_and_regfiles(dfd) != 0 {
        return -1;
    }

    /* Connections are unlocked from criu */
    if !files_collected() {
        // TODO: collect_image(&inet_sk_cinfo)
    }

    // TODO: collect_binfmt_misc()

    if tty_prep_fds(sfd_state, fdstore_desc) != 0 {
        return -1;
    }

    // TODO: prepare_apparmor_namespaces()

    0
}

static mut RESTORER: *mut libc::c_void = std::ptr::null_mut();
static mut RESTORER_LEN: usize = 0;

fn prepare_restorer_blob() -> i32 {
    /*
     * We map anonymous mapping, not mremap the restorer itself later.
     * Otherwise the restorer vma would be tied to criu binary which
     * in turn will lead to set-exe-file prctl to fail with EBUSY.
     */

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let restorer_len = page_size;

    let restorer = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            restorer_len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            0,
            0,
        )
    };

    if restorer == libc::MAP_FAILED {
        log::error!("Can't map restorer code");
        return -1;
    }

    unsafe {
        RESTORER = restorer;
        RESTORER_LEN = restorer_len;
    }

    0
}

fn prepare_cow_vmas(_store: &PidStore) {
    // TODO: implement COW VMA preparation
}

fn run_post_prepare() -> i32 {
    // TODO: run post-prepare hooks
    0
}

pub fn root_prepare_shared(
    store: &mut PidStore,
    dfd: RawFd,
    _sfd_state: &ServiceFdState,
) -> i32 {
    use crate::criu::files::{prepare_fd_pid, prepare_fs_pid};
    use crate::criu::files_reg::prepare_remaps;
    use crate::criu::mem::prepare_mm_pid;
    use crate::criu::seccomp::seccomp_read_image;

    log::info!("Preparing info about shared resources");

    if prepare_remaps() != 0 {
        return -1;
    }

    if seccomp_read_image(dfd) != 0 {
        return -1;
    }

    // TODO: collect_images(cinfos, ...)
    // TODO: if !files_collected() && collect_images(cinfos_files, ...)

    let item_count = store.items_count();
    for item_idx in 0..item_count {
        let is_helper = match store.get_item(item_idx) {
            Some(item) => item.pid.state == TaskState::Helper,
            None => continue,
        };

        if is_helper {
            continue;
        }

        if prepare_mm_pid(store, item_idx, dfd) != 0 {
            return -1;
        }

        if prepare_fd_pid(store, item_idx, dfd) != 0 {
            return -1;
        }

        if prepare_fs_pid(store, item_idx, dfd) != 0 {
            return -1;
        }
    }

    prepare_cow_vmas(store);

    if prepare_restorer_blob() != 0 {
        return -1;
    }

    // TODO: add_fake_unix_queuers()
    // TODO: prepare_scms()

    if run_post_prepare() != 0 {
        return -1;
    }

    // TODO: unix_prepare_root_shared()

    // show_saved_files() - debug logging, skip for now

    0
}

pub fn cr_restore_tasks(dfd: RawFd) -> i32 {
    let mut ret: i32 = -1;

    let mut sfd_state = ServiceFdState::new();
    if init_service_fd() != 0 {
        return 1;
    }

    if check_img_inventory(dfd, true) < 0 {
        return -1;
    }

    if init_stats(RESTORE_STATS) != 0 {
        return -1;
    }

    if lsm_check_opts().is_err() {
        return -1;
    }

    timing_start(RestoreTime::Restore as usize);

    if cpu_init() < 0 {
        return -1;
    }

    if vdso_init_restore().is_err() {
        return -1;
    }

    if tty_init_restore() != 0 {
        return -1;
    }

    if (opts().cpu_cap & 0x1) != 0 {
        if cpu_validate_cpuinfo() != 0 {
            return -1;
        }
    }

    if prepare_task_entries() < 0 {
        return -1;
    }

    let mut store = PidStore::new();
    if prepare_pstree(&mut store, dfd) < 0 {
        return -1;
    }

    let fdstore_desc_ptr = match fdstore_init(&mut sfd_state, "") {
        Ok(desc) => desc,
        Err(_) => return -1,
    };
    let fdstore_desc = unsafe { &mut *fdstore_desc_ptr };

    if cr_plugin_init(CrPluginStage::Restore) != 0 {
        return -1;
    }

    if inherit_fd_move_to_fdstore(&sfd_state, fdstore_desc) != 0 {
        cr_plugin_fini(CrPluginStage::Restore, ret);
        return ret;
    }

    if crtools_prepare_shared(dfd, &sfd_state, fdstore_desc) < 0 {
        cr_plugin_fini(CrPluginStage::Restore, ret);
        return ret;
    }

    let manage_cgroups = opts().manage_cgroups;
    let cgroup_yard = opts().cgroup_yard.as_deref();
    if prepare_cgroup(&mut sfd_state, manage_cgroups, cgroup_yard).is_err() {
        fini_cgroup(&mut sfd_state, cgroup_yard);
        cr_plugin_fini(CrPluginStage::Restore, ret);
        return ret;
    }

    if criu_signals_setup() < 0 {
        fini_cgroup(&mut sfd_state, cgroup_yard);
        cr_plugin_fini(CrPluginStage::Restore, ret);
        return ret;
    }

    if prepare_lazy_pages_socket(&sfd_state, fdstore_desc) < 0 {
        fini_cgroup(&mut sfd_state, cgroup_yard);
        cr_plugin_fini(CrPluginStage::Restore, ret);
        return ret;
    }

    let root_idx = root_item_idx();
    ret = restore_root_task(&mut store, root_idx, &mut sfd_state, fdstore_desc, dfd);

    fini_cgroup(&mut sfd_state, cgroup_yard);
    cr_plugin_fini(CrPluginStage::Restore, ret);
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::TaskCoreEntry;

    #[test]
    fn test_check_core_march_mismatch() {
        let mut core = CoreEntry {
            mtype: 999, // Invalid march
            thread_info: None,
            ti_arm: None,
            ti_aarch64: None,
            ti_ppc64: None,
            ti_s390: None,
            ti_mips: None,
            ti_loongarch64: None,
            ti_riscv64: None,
            tc: None,
            ids: None,
            thread_core: None,
        };
        let mut me = crate::criu::pstree::alloc_pstree_item(true);

        let ret = check_core(&mut core, &mut me);
        assert_eq!(ret, -1);
    }

    #[test]
    fn test_check_core_missing_tc() {
        let mut core = CoreEntry {
            mtype: CORE_ENTRY_MARCH,
            thread_info: None,
            ti_arm: None,
            ti_aarch64: None,
            ti_ppc64: None,
            ti_s390: None,
            ti_mips: None,
            ti_loongarch64: None,
            ti_riscv64: None,
            tc: None,
            ids: None,
            thread_core: None,
        };
        let mut me = crate::criu::pstree::alloc_pstree_item(true);

        let ret = check_core(&mut core, &mut me);
        assert_eq!(ret, -1);
    }

    #[test]
    fn test_check_core_dead_task() {
        let mut core = CoreEntry {
            mtype: CORE_ENTRY_MARCH,
            thread_info: None,
            ti_arm: None,
            ti_aarch64: None,
            ti_ppc64: None,
            ti_s390: None,
            ti_mips: None,
            ti_loongarch64: None,
            ti_riscv64: None,
            tc: Some(TaskCoreEntry {
                task_state: TaskState::Dead as u32,
                exit_code: 0,
                personality: 0,
                flags: 0,
                blk_sigset: 0,
                comm: String::new(),
                timers: None,
                rlimits: None,
                cg_set: None,
                signals_s: None,
                old_seccomp_mode: None,
                old_seccomp_filter: None,
                loginuid: None,
                oom_score_adj: None,
                sigactions: vec![],
                child_subreaper: None,
                blk_sigset_extended: None,
                stop_signo: None,
                membarrier_registration_mask: None,
            }),
            ids: None,
            thread_core: None,
        };
        let mut me = crate::criu::pstree::alloc_pstree_item(true);

        // Dead task should pass validation even without arch info
        let ret = check_core(&mut core, &mut me);
        assert_eq!(ret, 0);
    }
}
