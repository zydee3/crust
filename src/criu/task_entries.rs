use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::OnceLock;

use crate::criu::lock::{Futex, Mutex};

static CR_ERRNO: AtomicI32 = AtomicI32::new(0);

pub fn set_cr_errno(new_err: i32) {
    let _ = CR_ERRNO.compare_exchange(0, new_err, Ordering::SeqCst, Ordering::SeqCst);
}

pub fn get_cr_errno() -> i32 {
    CR_ERRNO.load(Ordering::SeqCst)
}

#[inline]
pub fn get_task_cr_err() -> i32 {
    task_entries().cr_err.load(Ordering::SeqCst)
}
use crate::criu::rst_malloc::{rst_mem_align_cpos, rst_mem_alloc, RstMemType};

struct TaskEntriesPtr(*mut TaskEntries);
unsafe impl Send for TaskEntriesPtr {}
unsafe impl Sync for TaskEntriesPtr {}

/*
 * The first staged stage is CR_STATE_ROOT_TASK which is started
 * upon the first SIGCHLD received.
 */
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrState {
    Fail = -1,
    /*
     * The root task creation stage. It's set at the exit
     * from the forking stage (once) and is being constantly
     * tested as the first in the order.
     */
    RootTask = 0,
    /*
     * At this stage tasks should prepare namespaces and
     * other stuff that's required to properly call
     * fork_with_pid
     */
    PrepareNamespaces,
    /*
     * The forking stage. The forking start is the most heavy
     * one because we fork and join a lot. The last forking
     * finished is CR_STATE_RESTORE. The forking stage is
     * over once the nr of tasks in progress becomes equal
     * to nr of total tasks.
     *
     * Individual forks are controlled via task_st field
     * in the pstree.
     */
    Forking,
    /*
     * The restore stage. The last waited stage is CR_STATE_RESTORE.
     * The restore stage is over once the nr of tasks in progress
     * becomes equal to nr of total threads.
     */
    Restore,
    /*
     * The sigchld restore stage. The first waited stage is
     * CR_STATE_RESTORE_SIGCHLD.
     */
    RestoreSigchld,
    /*
     * Restore creds stage. In order to properly function, all
     * tasks at this stage must share non-privileged creds.
     */
    RestoreCreds,
    Complete,
}

impl From<i32> for CrState {
    fn from(v: i32) -> Self {
        match v {
            -1 => CrState::Fail,
            0 => CrState::RootTask,
            1 => CrState::PrepareNamespaces,
            2 => CrState::Forking,
            3 => CrState::Restore,
            4 => CrState::RestoreSigchld,
            5 => CrState::RestoreCreds,
            6 => CrState::Complete,
            _ => CrState::Fail,
        }
    }
}

#[repr(C)]
pub struct TaskEntries {
    pub nr_threads: i32,
    pub nr_tasks: i32,
    pub nr_helpers: i32,
    pub nr_in_progress: Futex,
    pub start: Futex,
    pub cr_err: AtomicI32,
    pub userns_sync_lock: Mutex,
    pub cgroupd_sync_lock: Mutex,
    pub last_pid_mutex: Mutex,
}

impl TaskEntries {
    pub fn new() -> Self {
        Self {
            nr_threads: 0,
            nr_tasks: 0,
            nr_helpers: 0,
            nr_in_progress: Futex::new(),
            start: Futex::new(),
            cr_err: AtomicI32::new(0),
            userns_sync_lock: Mutex::new(),
            cgroupd_sync_lock: Mutex::new(),
            last_pid_mutex: Mutex::new(),
        }
    }

    pub fn init(&mut self) {
        self.nr_threads = 0;
        self.nr_tasks = 0;
        self.nr_helpers = 0;
        self.start.set(CrState::Fail as u32);
        self.userns_sync_lock.init();
        self.cgroupd_sync_lock.init();
        self.last_pid_mutex.init();
    }
}

impl Default for TaskEntries {
    fn default() -> Self {
        Self::new()
    }
}

static TASK_ENTRIES: OnceLock<TaskEntriesPtr> = OnceLock::new();
static TASK_ENTRIES_POS: OnceLock<usize> = OnceLock::new();

pub fn prepare_task_entries() -> i32 {
    let pos = rst_mem_align_cpos(RstMemType::Shremap);

    let ptr = rst_mem_alloc(std::mem::size_of::<TaskEntries>(), RstMemType::Shremap);
    if ptr.is_null() {
        log::error!("Can't map shmem for task_entries");
        return -1;
    }

    let te = ptr as *mut TaskEntries;
    unsafe {
        (*te).nr_threads = 0;
        (*te).nr_tasks = 0;
        (*te).nr_helpers = 0;
        (*te).start.set(CrState::Fail as u32);
        (*te).userns_sync_lock.init();
        (*te).cgroupd_sync_lock.init();
        (*te).last_pid_mutex.init();
    }

    let _ = TASK_ENTRIES_POS.set(pos);
    let _ = TASK_ENTRIES.set(TaskEntriesPtr(te));

    0
}

pub fn task_entries() -> &'static TaskEntries {
    unsafe {
        &*TASK_ENTRIES.get().expect("task_entries not initialized").0
    }
}

pub fn task_entries_mut() -> &'static mut TaskEntries {
    unsafe {
        &mut *TASK_ENTRIES.get().expect("task_entries not initialized").0
    }
}

pub fn task_entries_try() -> Option<&'static TaskEntries> {
    TASK_ENTRIES.get().map(|p| unsafe { &*p.0 })
}

pub fn task_entries_ptr() -> *mut TaskEntries {
    TASK_ENTRIES.get().map_or(std::ptr::null_mut(), |p| p.0)
}

pub fn task_entries_pos() -> usize {
    *TASK_ENTRIES_POS.get().unwrap_or(&0)
}

#[inline]
pub fn stage_participants(next_stage: CrState) -> i32 {
    match next_stage {
        CrState::Fail => 0,
        CrState::RootTask | CrState::PrepareNamespaces => 1,
        CrState::Forking => {
            let te = task_entries();
            te.nr_tasks + te.nr_helpers
        }
        CrState::Restore => {
            let te = task_entries();
            te.nr_threads + te.nr_helpers
        }
        CrState::RestoreSigchld | CrState::RestoreCreds => {
            task_entries().nr_threads
        }
        CrState::Complete => {
            panic!("BUG: stage_participants called with Complete");
        }
    }
}

fn __restore_wait_inprogress_tasks(participants: i32) -> i32 {
    let np = &task_entries().nr_in_progress;

    np.wait_while_gt(participants as u32);
    let ret = np.get() as i32;
    if ret < 0 {
        set_cr_errno(get_task_cr_err());
        return ret;
    }

    0
}

pub fn restore_wait_inprogress_tasks() -> i32 {
    __restore_wait_inprogress_tasks(0)
}

#[inline]
fn __restore_switch_stage_nw(next_stage: CrState) {
    let te = task_entries();
    te.nr_in_progress.set(stage_participants(next_stage) as u32);
    te.start.set(next_stage as i32 as u32);
}

#[inline]
fn __restore_switch_stage(next_stage: CrState) {
    let te = task_entries();
    if next_stage != CrState::Complete {
        te.nr_in_progress.set(stage_participants(next_stage) as u32);
    }
    te.start.set_and_wake(next_stage as i32 as u32);
}

pub fn restore_switch_stage(next_stage: CrState) -> i32 {
    __restore_switch_stage(next_stage);
    restore_wait_inprogress_tasks()
}

pub fn restore_finish_stage(stage: CrState) -> i32 {
    let te = task_entries();
    te.nr_in_progress.dec_and_wake();
    te.start.wait_while_eq(stage as u32);
    te.start.get() as i32
}

#[inline]
pub fn lock_last_pid() {
    task_entries().last_pid_mutex.lock();
}

#[inline]
pub fn unlock_last_pid() {
    task_entries().last_pid_mutex.unlock();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cr_state_values() {
        assert_eq!(CrState::Fail as i32, -1);
        assert_eq!(CrState::RootTask as i32, 0);
        assert_eq!(CrState::PrepareNamespaces as i32, 1);
        assert_eq!(CrState::Forking as i32, 2);
        assert_eq!(CrState::Restore as i32, 3);
        assert_eq!(CrState::RestoreSigchld as i32, 4);
        assert_eq!(CrState::RestoreCreds as i32, 5);
        assert_eq!(CrState::Complete as i32, 6);
    }

    #[test]
    fn test_cr_state_from_i32() {
        assert_eq!(CrState::from(-1), CrState::Fail);
        assert_eq!(CrState::from(0), CrState::RootTask);
        assert_eq!(CrState::from(3), CrState::Restore);
        assert_eq!(CrState::from(100), CrState::Fail); // Invalid maps to Fail
    }

    #[test]
    fn test_task_entries_new() {
        let te = TaskEntries::new();
        assert_eq!(te.nr_threads, 0);
        assert_eq!(te.nr_tasks, 0);
        assert_eq!(te.nr_helpers, 0);
    }

    #[test]
    fn test_task_entries_size() {
        // Ensure the struct is properly sized for shared memory
        let size = std::mem::size_of::<TaskEntries>();
        assert!(size > 0);
        // It should be at least big enough for the fields
        assert!(size >= 3 * std::mem::size_of::<i32>() + 2 * std::mem::size_of::<Futex>() + std::mem::size_of::<AtomicI32>() + 3 * std::mem::size_of::<Mutex>());
    }
}
