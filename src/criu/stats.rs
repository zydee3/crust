use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use crate::criu::image::{close_image, open_image_at, O_DUMP};
use crate::criu::image_desc::magic::STATS_MAGIC;
use crate::criu::image_desc::CrFdType;
use crate::criu::options::opts;
use crate::criu::protobuf::pb_write_one;
use crate::criu::rst_malloc::shmalloc;
use crate::proto::{DumpStatsEntry, RestoreStatsEntry, StatsEntry};

const USEC_PER_SEC: i64 = 1_000_000;

pub const DUMP_STATS: i32 = 1;
pub const RESTORE_STATS: i32 = 2;

#[repr(usize)]
#[derive(Clone, Copy)]
pub enum DumpTime {
    Freezing = 0,
    Frozen,
    Memdump,
    Memwrite,
    IrmapResolve,
}

pub const DUMP_TIME_NR_STATS: usize = 5;

#[repr(usize)]
#[derive(Clone, Copy)]
pub enum RestoreTime {
    Fork = 0,
    Restore,
}

pub const RESTORE_TIME_NR_STATS: usize = 2;

#[repr(usize)]
#[derive(Clone, Copy)]
pub enum DumpCnt {
    PagesScanned = 0,
    PagesSkippedParent,
    PagesWritten,
    PagesLazy,
    PagePipes,
    PagePipeBufs,
    ShpagesScanned,
    ShpagesSkippedParent,
    ShpagesWritten,
}

pub const DUMP_CNT_NR_STATS: usize = 9;

#[repr(usize)]
#[derive(Clone, Copy)]
pub enum RestoreCnt {
    PagesCompared = 0,
    PagesSkippedCow,
    PagesRestored,
}

pub const RESTORE_CNT_NR_STATS: usize = 3;

#[derive(Clone, Copy, Default)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[derive(Clone, Copy, Default)]
pub struct Timing {
    pub start: Timeval,
    pub total: Timeval,
}

#[repr(C)]
pub struct DumpStats {
    pub timings: [Timing; DUMP_TIME_NR_STATS],
    pub counts: [u64; DUMP_CNT_NR_STATS],
}

impl Default for DumpStats {
    fn default() -> Self {
        Self {
            timings: [Timing::default(); DUMP_TIME_NR_STATS],
            counts: [0; DUMP_CNT_NR_STATS],
        }
    }
}

#[repr(C)]
pub struct RestoreStats {
    pub timings: [Timing; RESTORE_TIME_NR_STATS],
    pub counts: [AtomicU64; RESTORE_CNT_NR_STATS],
}

impl Default for RestoreStats {
    fn default() -> Self {
        Self {
            timings: [Timing::default(); RESTORE_TIME_NR_STATS],
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

struct DumpStatsPtr(*mut DumpStats);
unsafe impl Send for DumpStatsPtr {}
unsafe impl Sync for DumpStatsPtr {}

struct RestoreStatsPtr(*mut RestoreStats);
unsafe impl Send for RestoreStatsPtr {}
unsafe impl Sync for RestoreStatsPtr {}

static DSTATS: OnceLock<DumpStatsPtr> = OnceLock::new();
static RSTATS: OnceLock<RestoreStatsPtr> = OnceLock::new();

impl Timeval {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_duration(d: Duration) -> Self {
        Self {
            tv_sec: d.as_secs() as i64,
            tv_usec: d.subsec_micros() as i64,
        }
    }
}

pub fn timeval_accumulate(from: &Timeval, to: &Timeval, res: &mut Timeval) {
    res.tv_sec += to.tv_sec - from.tv_sec;
    let mut usec = to.tv_usec;

    if usec < from.tv_usec {
        usec += USEC_PER_SEC;
        res.tv_sec -= 1;
    }

    res.tv_usec += usec - from.tv_usec;

    if res.tv_usec > USEC_PER_SEC {
        res.tv_usec -= USEC_PER_SEC;
        res.tv_sec += 1;
    }
}

fn dstats() -> Option<&'static mut DumpStats> {
    DSTATS.get().map(|p| unsafe { &mut *p.0 })
}

fn rstats() -> Option<&'static mut RestoreStats> {
    RSTATS.get().map(|p| unsafe { &mut *p.0 })
}

pub fn set_dstats(ptr: *mut DumpStats) {
    let _ = DSTATS.set(DumpStatsPtr(ptr));
}

pub fn set_rstats(ptr: *mut RestoreStats) {
    let _ = RSTATS.set(RestoreStatsPtr(ptr));
}

fn get_timing(t: usize) -> Option<&'static mut Timing> {
    if let Some(ds) = dstats() {
        if t >= DUMP_TIME_NR_STATS {
            panic!("BUG: timing index {} >= DUMP_TIME_NR_STATS", t);
        }
        return Some(&mut ds.timings[t]);
    }
    if let Some(rs) = rstats() {
        // FIXME -- this does _NOT_ work when called
        // from different tasks.
        if t >= RESTORE_TIME_NR_STATS {
            panic!("BUG: timing index {} >= RESTORE_TIME_NR_STATS", t);
        }
        return Some(&mut rs.timings[t]);
    }
    panic!("BUG: get_timing called with no stats");
}

fn gettimeofday() -> Timeval {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    unsafe {
        libc::gettimeofday(&mut tv, std::ptr::null_mut());
    }
    Timeval {
        tv_sec: tv.tv_sec,
        tv_usec: tv.tv_usec,
    }
}

pub fn timing_start(t: usize) {
    if let Some(tm) = get_timing(t) {
        tm.start = gettimeofday();
    }
}

pub fn timing_stop(t: usize) {
    if dstats().is_none() && rstats().is_none() {
        return;
    }

    if let Some(tm) = get_timing(t) {
        let now = gettimeofday();
        timeval_accumulate(&tm.start, &now, &mut tm.total);
    }
}

pub fn cnt_add(c: usize, val: u64) {
    if let Some(ds) = dstats() {
        if c < DUMP_CNT_NR_STATS {
            ds.counts[c] += val;
        }
    } else if let Some(rs) = rstats() {
        if c < RESTORE_CNT_NR_STATS {
            rs.counts[c].fetch_add(val, Ordering::SeqCst);
        }
    }
}

pub fn cnt_sub(c: usize, val: u64) {
    if let Some(ds) = dstats() {
        if c < DUMP_CNT_NR_STATS {
            ds.counts[c] -= val;
        }
    } else if let Some(rs) = rstats() {
        if c < RESTORE_CNT_NR_STATS {
            rs.counts[c].fetch_sub(val, Ordering::SeqCst);
        }
    }
}

fn encode_time(t: usize) -> u32 {
    if let Some(tm) = get_timing(t) {
        (tm.total.tv_sec * USEC_PER_SEC + tm.total.tv_usec) as u32
    } else {
        0
    }
}

fn display_stats(what: i32, stats: &StatsEntry) {
    if what == DUMP_STATS {
        if let Some(dump) = &stats.dump {
            println!("Displaying dump stats:");
            println!("Freezing time: {} us", dump.freezing_time);
            println!("Frozen time: {} us", dump.frozen_time);
            println!("Memory dump time: {} us", dump.memdump_time);
            println!("Memory write time: {} us", dump.memwrite_time);
            if let Some(irmap) = dump.irmap_resolve {
                println!("IRMAP resolve time: {} us", irmap);
            }
            println!(
                "Memory pages scanned: {} (0x{:x})",
                dump.pages_scanned, dump.pages_scanned
            );
            println!(
                "Memory pages skipped from parent: {} (0x{:x})",
                dump.pages_skipped_parent, dump.pages_skipped_parent
            );
            println!(
                "Memory pages written: {} (0x{:x})",
                dump.pages_written, dump.pages_written
            );
            println!(
                "Lazy memory pages: {} (0x{:x})",
                dump.pages_lazy, dump.pages_lazy
            );
        }
    } else if what == RESTORE_STATS {
        if let Some(restore) = &stats.restore {
            println!("Displaying restore stats:");
            println!(
                "Pages compared: {} (0x{:x})",
                restore.pages_compared, restore.pages_compared
            );
            println!(
                "Pages skipped COW: {} (0x{:x})",
                restore.pages_skipped_cow, restore.pages_skipped_cow
            );
            if let Some(pages_restored) = restore.pages_restored {
                println!(
                    "Pages restored: {} (0x{:x})",
                    pages_restored, pages_restored
                );
            }
            println!("Restore time: {} us", restore.restore_time);
            println!("Forking time: {} us", restore.forking_time);
        }
    }
}

pub fn write_stats(what: i32) {
    println!("Writing stats");

    let stats: StatsEntry;
    let name: &str;

    if what == DUMP_STATS {
        let ds = match dstats() {
            Some(d) => d,
            None => return,
        };

        let ds_entry = DumpStatsEntry {
            freezing_time: encode_time(DumpTime::Freezing as usize),
            frozen_time: encode_time(DumpTime::Frozen as usize),
            memdump_time: encode_time(DumpTime::Memdump as usize),
            memwrite_time: encode_time(DumpTime::Memwrite as usize),
            irmap_resolve: Some(encode_time(DumpTime::IrmapResolve as usize)),
            pages_scanned: ds.counts[DumpCnt::PagesScanned as usize],
            pages_skipped_parent: ds.counts[DumpCnt::PagesSkippedParent as usize],
            pages_written: ds.counts[DumpCnt::PagesWritten as usize],
            pages_lazy: ds.counts[DumpCnt::PagesLazy as usize],
            page_pipes: Some(ds.counts[DumpCnt::PagePipes as usize]),
            page_pipe_bufs: Some(ds.counts[DumpCnt::PagePipeBufs as usize]),
            shpages_scanned: Some(ds.counts[DumpCnt::ShpagesScanned as usize]),
            shpages_skipped_parent: Some(ds.counts[DumpCnt::ShpagesSkippedParent as usize]),
            shpages_written: Some(ds.counts[DumpCnt::ShpagesWritten as usize]),
        };

        stats = StatsEntry {
            dump: Some(ds_entry),
            restore: None,
        };
        name = "dump";
    } else if what == RESTORE_STATS {
        let rs = match rstats() {
            Some(r) => r,
            None => return,
        };

        let rs_entry = RestoreStatsEntry {
            pages_compared: rs.counts[RestoreCnt::PagesCompared as usize].load(Ordering::SeqCst),
            pages_skipped_cow: rs.counts[RestoreCnt::PagesSkippedCow as usize]
                .load(Ordering::SeqCst),
            pages_restored: Some(
                rs.counts[RestoreCnt::PagesRestored as usize].load(Ordering::SeqCst),
            ),
            forking_time: encode_time(RestoreTime::Fork as usize),
            restore_time: encode_time(RestoreTime::Restore as usize),
        };

        stats = StatsEntry {
            dump: None,
            restore: Some(rs_entry),
        };
        name = "restore";
    } else {
        return;
    }

    if let Ok(mut img) = open_image_at(libc::AT_FDCWD, CrFdType::Stats, O_DUMP as u32, name) {
        let _ = pb_write_one(&mut img, &stats, libc::AT_FDCWD, STATS_MAGIC);
        close_image(&mut img);
    }

    if opts().display_stats != 0 {
        display_stats(what, &stats);
    }
}

pub fn init_stats(what: i32) -> i32 {
    if what == DUMP_STATS {
        // Dumping happens via one process most of the time,
        // so we are typically OK with the plain malloc, but
        // when dumping namespaces we fork() a separate process
        // for it and when it goes and dumps shmem segments
        // it will alter the CNT_SHPAGES_ counters, so we need
        // to have them in shmem.
        let ptr = shmalloc(std::mem::size_of::<DumpStats>()) as *mut DumpStats;
        if ptr.is_null() {
            return -1;
        }
        unsafe {
            std::ptr::write(ptr, DumpStats::default());
        }
        set_dstats(ptr);
        return 0;
    }

    let ptr = shmalloc(std::mem::size_of::<RestoreStats>()) as *mut RestoreStats;
    if ptr.is_null() {
        return -1;
    }
    unsafe {
        std::ptr::write(ptr, RestoreStats::default());
    }
    set_rstats(ptr);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeval_accumulate_simple() {
        let from = Timeval { tv_sec: 0, tv_usec: 0 };
        let to = Timeval { tv_sec: 1, tv_usec: 500_000 };
        let mut res = Timeval::new();

        timeval_accumulate(&from, &to, &mut res);

        assert_eq!(res.tv_sec, 1);
        assert_eq!(res.tv_usec, 500_000);
    }

    #[test]
    fn test_timeval_accumulate_multiple() {
        let mut res = Timeval::new();

        // First accumulation: 0.5 seconds
        let from1 = Timeval { tv_sec: 0, tv_usec: 0 };
        let to1 = Timeval { tv_sec: 0, tv_usec: 500_000 };
        timeval_accumulate(&from1, &to1, &mut res);
        assert_eq!(res.tv_sec, 0);
        assert_eq!(res.tv_usec, 500_000);

        // Second accumulation: 0.7 seconds (total should be 1.2 seconds)
        let from2 = Timeval { tv_sec: 10, tv_usec: 0 };
        let to2 = Timeval { tv_sec: 10, tv_usec: 700_000 };
        timeval_accumulate(&from2, &to2, &mut res);
        assert_eq!(res.tv_sec, 1);
        assert_eq!(res.tv_usec, 200_000);
    }

    #[test]
    fn test_timeval_accumulate_carry() {
        // Test when 'to' usec is less than 'from' usec
        let from = Timeval { tv_sec: 0, tv_usec: 800_000 };
        let to = Timeval { tv_sec: 1, tv_usec: 200_000 };
        let mut res = Timeval::new();

        timeval_accumulate(&from, &to, &mut res);

        // Should be 0.4 seconds
        assert_eq!(res.tv_sec, 0);
        assert_eq!(res.tv_usec, 400_000);
    }

    #[test]
    fn test_timeval_new() {
        let tv = Timeval::new();
        assert_eq!(tv.tv_sec, 0);
        assert_eq!(tv.tv_usec, 0);
    }
}
