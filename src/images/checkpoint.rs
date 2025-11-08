// CRIU checkpoint data structures
use crate::error::Result;
use crate::proto::{
    CoreEntry, FileEntry, FsEntry, MmEntry, PagemapEntry, PstreeEntry, SeccompEntry,
    TaskKobjIdsEntry, TimensEntry, TtyInfoEntry,
};

pub struct Pagemap {
    pub pages_id: u32,
    pub entries: Vec<PagemapEntry>,
}

/// CRIU checkpoint
pub struct CriuCheckpoint {
    pub pstree: PstreeEntry,
    pub core: CoreEntry,
    pub mm: MmEntry,
    pub pagemap: Pagemap,
    pub pages_data: Vec<u8>,
    pub files: Option<Vec<FileEntry>>,
    pub fs: Option<FsEntry>,
    pub ids: Option<TaskKobjIdsEntry>,
    pub seccomp: Option<SeccompEntry>,
    pub timens: Option<TimensEntry>,
    pub tty_info: Option<Vec<TtyInfoEntry>>,
}

impl CriuCheckpoint {
    /// Display checkpoint information for debugging
    pub fn display(&self) -> Result<()> {
        log::debug!("CRIU Checkpoint Metadata");

        self.display_pstree();
        self.display_core_state();
        self.display_cpu_registers();
        self.display_memory_map();
        self.display_pagemap();
        self.display_filesystem();
        self.display_namespaces();
        self.display_files();
        self.display_seccomp();
        self.display_timens();
        self.display_tty();

        Ok(())
    }

    fn display_pstree(&self) {
        log::debug!("Process Tree (pstree.img)");
        log::debug!("  PID: {}", self.pstree.pid);
        log::debug!("  PPID: {}", self.pstree.ppid);
        log::debug!("  PGID: {}", self.pstree.pgid);
        log::debug!("  SID: {}", self.pstree.sid);
        log::debug!("  Threads: {}", self.pstree.threads.len());
    }

    fn display_core_state(&self) {
        log::debug!("Core State (core-{}.img)", self.pstree.pid);
        log::debug!(
            "  Task state: {}",
            self.core.tc.as_ref().map(|tc| tc.task_state).unwrap_or(0)
        );
        log::debug!(
            "  Exit code: {}",
            self.core.tc.as_ref().map(|tc| tc.exit_code).unwrap_or(0)
        );
        log::debug!(
            "  Personality: 0x{:x}",
            self.core.tc.as_ref().map(|tc| tc.personality).unwrap_or(0)
        );
        log::debug!(
            "  Flags: 0x{:x}",
            self.core.tc.as_ref().map(|tc| tc.flags).unwrap_or(0)
        );
        if let Some(tc) = &self.core.tc {
            log::debug!("  Comm: {}", tc.comm);
        }
    }

    fn display_cpu_registers(&self) {
        if let Some(thread_info) = &self.core.thread_info {
            let gpregs = &thread_info.gpregs;
            log::debug!("CPU Registers (x86_64):");
            log::debug!("  RIP: 0x{:016x}", gpregs.ip);
            log::debug!("  RSP: 0x{:016x}", gpregs.sp);
            log::debug!("  RBP: 0x{:016x}", gpregs.bp);
            log::debug!("  RAX: 0x{:016x}", gpregs.ax);
            log::debug!("  RBX: 0x{:016x}", gpregs.bx);
            log::debug!("  RCX: 0x{:016x}", gpregs.cx);
            log::debug!("  RDX: 0x{:016x}", gpregs.dx);
            log::debug!("  RSI: 0x{:016x}", gpregs.si);
            log::debug!("  RDI: 0x{:016x}", gpregs.di);
            log::debug!("  R8:  0x{:016x}", gpregs.r8);
            log::debug!("  R9:  0x{:016x}", gpregs.r9);
            log::debug!("  R10: 0x{:016x}", gpregs.r10);
            log::debug!("  R11: 0x{:016x}", gpregs.r11);
            log::debug!("  R12: 0x{:016x}", gpregs.r12);
            log::debug!("  R13: 0x{:016x}", gpregs.r13);
            log::debug!("  R14: 0x{:016x}", gpregs.r14);
            log::debug!("  R15: 0x{:016x}", gpregs.r15);
            log::debug!("  CS:  0x{:04x}", gpregs.cs);
            log::debug!("  SS:  0x{:04x}", gpregs.ss);
            log::debug!("  EFLAGS: 0x{:016x}", gpregs.flags);
        }
    }

    fn display_memory_map(&self) {
        log::debug!("Memory Map (mm-{}.img)", self.pstree.pid);
        log::debug!("  VMAs: {}", self.mm.vmas.len());
        log::debug!("  MM start code: 0x{:x}", self.mm.mm_start_code);
        log::debug!("  MM end code: 0x{:x}", self.mm.mm_end_code);
        log::debug!("  MM start data: 0x{:x}", self.mm.mm_start_data);
        log::debug!("  MM end data: 0x{:x}", self.mm.mm_end_data);
        log::debug!("  MM start stack: 0x{:x}", self.mm.mm_start_stack);
        log::debug!("  MM start brk: 0x{:x}", self.mm.mm_start_brk);
        log::debug!("  MM brk: 0x{:x}", self.mm.mm_brk);
        log::debug!("  MM arg start: 0x{:x}", self.mm.mm_arg_start);
        log::debug!("  MM arg end: 0x{:x}", self.mm.mm_arg_end);
        log::debug!("  MM env start: 0x{:x}", self.mm.mm_env_start);
        log::debug!("  MM env end: 0x{:x}", self.mm.mm_env_end);

        log::debug!("Memory Regions ({} VMAs):", self.mm.vmas.len());

        for (i, vma) in self.mm.vmas.iter().enumerate() {
            self.display_vma(i, vma);
        }
    }

    fn display_vma(&self, index: usize, vma: &crate::proto::VmaEntry) {
        let size = vma.end - vma.start;
        let prot_str = format!(
            "{}{}{}",
            if vma.prot & 1 != 0 { "r" } else { "-" },
            if vma.prot & 2 != 0 { "w" } else { "-" },
            if vma.prot & 4 != 0 { "x" } else { "-" }
        );
        let flags_str = format!(
            "{}{}",
            if vma.flags & 0x01 != 0 { "s" } else { "p" },
            if vma.flags & 0x20 != 0 { " anon" } else { "" }
        );
        log::debug!(
            "  [{:2}] 0x{:016x}-0x{:016x} ({:8} bytes) {} flags=0x{:x}{} fd={}{}",
            index,
            vma.start,
            vma.end,
            size,
            prot_str,
            vma.flags,
            flags_str,
            vma.fd,
            vma.fdflags
                .map(|f| format!(" fdflags=0x{:x}", f))
                .unwrap_or_default()
        );
    }

    fn display_pagemap(&self) {
        const PAGE_SIZE: usize = 4096;
        let total_pages: u64 = self
            .pagemap
            .entries
            .iter()
            .map(|e| e.nr_pages.unwrap_or(e.compat_nr_pages as u64))
            .sum();
        let total_bytes = total_pages as usize * PAGE_SIZE;

        log::debug!(
            "Pagemap (pagemap-{}.img, pages-{}.img)",
            self.pstree.pid,
            self.pagemap.pages_id
        );
        log::debug!("Pages ID: {}", self.pagemap.pages_id);
        log::debug!("Pagemap entries: {}", self.pagemap.entries.len());
        log::debug!("Total pages: {}", total_pages);
        log::debug!(
            "Total memory data: {} bytes ({:.2} KB, {:.2} MB)",
            total_bytes,
            total_bytes as f64 / 1024.0,
            total_bytes as f64 / 1024.0 / 1024.0
        );
        log::debug!("Pages data buffer size: {} bytes", self.pages_data.len());

        for (i, entry) in self.pagemap.entries.iter().enumerate().take(5) {
            let nr_pages = entry.nr_pages.unwrap_or(entry.compat_nr_pages as u64);
            log::debug!(
                "  Entry[{}]: vaddr=0x{:x} pages={} flags=0x{:x}",
                i,
                entry.vaddr,
                nr_pages,
                entry.flags.unwrap_or(0)
            );
        }
        if self.pagemap.entries.len() > 5 {
            log::debug!("  ... ({} more entries)", self.pagemap.entries.len() - 5);
        }
    }

    fn display_filesystem(&self) {
        log::debug!("Filesystem Context (fs-{}.img)", self.pstree.pid);
        if let Some(ref fs) = self.fs {
            log::debug!("  CWD file ID: {}", fs.cwd_id);
            log::debug!("  Root file ID: {}", fs.root_id);
            if let Some(umask) = fs.umask {
                log::debug!("  Umask: 0{:o}", umask);
            }
        } else {
            log::debug!("  (Not present)");
        }
    }

    fn display_namespaces(&self) {
        log::debug!("Namespace IDs (ids-{}.img)", self.pstree.pid);
        if let Some(ref ids) = self.ids {
            if let Some(pid_ns_id) = ids.pid_ns_id {
                log::debug!("  PID namespace: {}", pid_ns_id);
            }
            if let Some(net_ns_id) = ids.net_ns_id {
                log::debug!("  Net namespace: {}", net_ns_id);
            }
            if let Some(ipc_ns_id) = ids.ipc_ns_id {
                log::debug!("  IPC namespace: {}", ipc_ns_id);
            }
            if let Some(uts_ns_id) = ids.uts_ns_id {
                log::debug!("  UTS namespace: {}", uts_ns_id);
            }
            if let Some(mnt_ns_id) = ids.mnt_ns_id {
                log::debug!("  MNT namespace: {}", mnt_ns_id);
            }
        } else {
            log::debug!("  (Not present)");
        }
    }

    fn display_files(&self) {
        log::debug!("File Table (files.img)");
        if let Some(ref files) = self.files {
            log::debug!("  File entries: {}", files.len());
            for (i, file) in files.iter().enumerate().take(3) {
                log::debug!("    File[{}]: id={} type={:?}", i, file.id, file.r#type);
            }
            if files.len() > 3 {
                log::debug!("    ... ({} more files)", files.len() - 3);
            }
        } else {
            log::debug!("  (Failed to parse or not present)");
        }
    }

    fn display_seccomp(&self) {
        log::debug!("Seccomp Filters (seccomp.img)");
        if let Some(ref seccomp) = self.seccomp {
            log::debug!("  Filter entries: {}", seccomp.seccomp_filters.len());
        } else {
            log::debug!("  (Not present)");
        }
    }

    fn display_timens(&self) {
        log::debug!("Time Namespace (timens-0.img)");
        if let Some(ref timens) = self.timens {
            log::debug!("  Monotonic offset: {:?}", timens.monotonic);
            log::debug!("  Boottime offset: {:?}", timens.boottime);
        } else {
            log::debug!("  (Not present)");
        }
    }

    fn display_tty(&self) {
        log::debug!("TTY Info (tty-info.img)");
        if let Some(ref tty_info) = self.tty_info {
            log::debug!("  TTY entries: {}", tty_info.len());
        } else {
            log::debug!("  (Failed to parse or not present)");
        }
    }
}
