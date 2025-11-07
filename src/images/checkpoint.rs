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
        log::info!("=== CRIU Checkpoint Metadata ===");
        log::info!("");

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
        log::info!("--- Process Tree (pstree.img) ---");
        log::info!("PID: {}", self.pstree.pid);
        log::info!("PPID: {}", self.pstree.ppid);
        log::info!("PGID: {}", self.pstree.pgid);
        log::info!("SID: {}", self.pstree.sid);
        log::info!("Threads: {}", self.pstree.threads.len());
        log::info!("");
    }

    fn display_core_state(&self) {
        log::info!("--- Core State (core-{}.img) ---", self.pstree.pid);
        log::info!(
            "Task state: {}",
            self.core.tc.as_ref().map(|tc| tc.task_state).unwrap_or(0)
        );
        log::info!(
            "Exit code: {}",
            self.core.tc.as_ref().map(|tc| tc.exit_code).unwrap_or(0)
        );
        log::info!(
            "Personality: 0x{:x}",
            self.core.tc.as_ref().map(|tc| tc.personality).unwrap_or(0)
        );
        log::info!(
            "Flags: 0x{:x}",
            self.core.tc.as_ref().map(|tc| tc.flags).unwrap_or(0)
        );
        if let Some(tc) = &self.core.tc {
            log::info!("Comm: {}", tc.comm);
        }
    }

    fn display_cpu_registers(&self) {
        if let Some(thread_info) = &self.core.thread_info {
            let gpregs = &thread_info.gpregs;
            log::info!("");
            log::info!("CPU Registers (x86_64):");
            log::info!("  RIP: 0x{:016x}", gpregs.ip);
            log::info!("  RSP: 0x{:016x}", gpregs.sp);
            log::info!("  RBP: 0x{:016x}", gpregs.bp);
            log::info!("  RAX: 0x{:016x}", gpregs.ax);
            log::info!("  RBX: 0x{:016x}", gpregs.bx);
            log::info!("  RCX: 0x{:016x}", gpregs.cx);
            log::info!("  RDX: 0x{:016x}", gpregs.dx);
            log::info!("  RSI: 0x{:016x}", gpregs.si);
            log::info!("  RDI: 0x{:016x}", gpregs.di);
            log::info!("  R8:  0x{:016x}", gpregs.r8);
            log::info!("  R9:  0x{:016x}", gpregs.r9);
            log::info!("  R10: 0x{:016x}", gpregs.r10);
            log::info!("  R11: 0x{:016x}", gpregs.r11);
            log::info!("  R12: 0x{:016x}", gpregs.r12);
            log::info!("  R13: 0x{:016x}", gpregs.r13);
            log::info!("  R14: 0x{:016x}", gpregs.r14);
            log::info!("  R15: 0x{:016x}", gpregs.r15);
            log::info!("  CS:  0x{:04x}", gpregs.cs);
            log::info!("  SS:  0x{:04x}", gpregs.ss);
            log::info!("  EFLAGS: 0x{:016x}", gpregs.flags);
        }
        log::info!("");
    }

    fn display_memory_map(&self) {
        log::info!("--- Memory Map (mm-{}.img) ---", self.pstree.pid);
        log::info!("VMAs: {}", self.mm.vmas.len());
        log::info!("MM start code: 0x{:x}", self.mm.mm_start_code);
        log::info!("MM end code: 0x{:x}", self.mm.mm_end_code);
        log::info!("MM start data: 0x{:x}", self.mm.mm_start_data);
        log::info!("MM end data: 0x{:x}", self.mm.mm_end_data);
        log::info!("MM start stack: 0x{:x}", self.mm.mm_start_stack);
        log::info!("MM start brk: 0x{:x}", self.mm.mm_start_brk);
        log::info!("MM brk: 0x{:x}", self.mm.mm_brk);
        log::info!("MM arg start: 0x{:x}", self.mm.mm_arg_start);
        log::info!("MM arg end: 0x{:x}", self.mm.mm_arg_end);
        log::info!("MM env start: 0x{:x}", self.mm.mm_env_start);
        log::info!("MM env end: 0x{:x}", self.mm.mm_env_end);
        log::info!("");
        log::info!("Memory Regions ({} VMAs):", self.mm.vmas.len());

        for (i, vma) in self.mm.vmas.iter().enumerate() {
            self.display_vma(i, vma);
        }

        log::info!("");
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
        log::info!(
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

        log::info!(
            "--- Pagemap (pagemap-{}.img, pages-{}.img) ---",
            self.pstree.pid,
            self.pagemap.pages_id
        );
        log::info!("Pages ID: {}", self.pagemap.pages_id);
        log::info!("Pagemap entries: {}", self.pagemap.entries.len());
        log::info!("Total pages: {}", total_pages);
        log::info!(
            "Total memory data: {} bytes ({:.2} KB, {:.2} MB)",
            total_bytes,
            total_bytes as f64 / 1024.0,
            total_bytes as f64 / 1024.0 / 1024.0
        );
        log::info!("Pages data buffer size: {} bytes", self.pages_data.len());

        for (i, entry) in self.pagemap.entries.iter().enumerate().take(5) {
            let nr_pages = entry.nr_pages.unwrap_or(entry.compat_nr_pages as u64);
            log::info!(
                "  Entry[{}]: vaddr=0x{:x} pages={} flags=0x{:x}",
                i,
                entry.vaddr,
                nr_pages,
                entry.flags.unwrap_or(0)
            );
        }
        if self.pagemap.entries.len() > 5 {
            log::info!("  ... ({} more entries)", self.pagemap.entries.len() - 5);
        }

        log::info!("");
    }

    fn display_filesystem(&self) {
        log::info!("--- Filesystem Context (fs-{}.img) ---", self.pstree.pid);
        if let Some(ref fs) = self.fs {
            log::info!("CWD file ID: {}", fs.cwd_id);
            log::info!("Root file ID: {}", fs.root_id);
            if let Some(umask) = fs.umask {
                log::info!("Umask: 0{:o}", umask);
            }
        } else {
            log::info!("(Not present)");
        }
        log::info!("");
    }

    fn display_namespaces(&self) {
        log::info!("--- Namespace IDs (ids-{}.img) ---", self.pstree.pid);
        if let Some(ref ids) = self.ids {
            if let Some(pid_ns_id) = ids.pid_ns_id {
                log::info!("PID namespace: {}", pid_ns_id);
            }
            if let Some(net_ns_id) = ids.net_ns_id {
                log::info!("Net namespace: {}", net_ns_id);
            }
            if let Some(ipc_ns_id) = ids.ipc_ns_id {
                log::info!("IPC namespace: {}", ipc_ns_id);
            }
            if let Some(uts_ns_id) = ids.uts_ns_id {
                log::info!("UTS namespace: {}", uts_ns_id);
            }
            if let Some(mnt_ns_id) = ids.mnt_ns_id {
                log::info!("MNT namespace: {}", mnt_ns_id);
            }
        } else {
            log::info!("(Not present)");
        }
        log::info!("");
    }

    fn display_files(&self) {
        log::info!("--- File Table (files.img) ---");
        if let Some(ref files) = self.files {
            log::info!("File entries: {}", files.len());
            for (i, file) in files.iter().enumerate().take(3) {
                log::info!("  File[{}]: id={} type={:?}", i, file.id, file.r#type);
            }
            if files.len() > 3 {
                log::info!("  ... ({} more files)", files.len() - 3);
            }
        } else {
            log::info!("(Failed to parse or not present)");
        }
        log::info!("");
    }

    fn display_seccomp(&self) {
        log::info!("--- Seccomp Filters (seccomp.img) ---");
        if let Some(ref seccomp) = self.seccomp {
            log::info!("Filter entries: {}", seccomp.seccomp_filters.len());
        } else {
            log::info!("(Not present)");
        }
        log::info!("");
    }

    fn display_timens(&self) {
        log::info!("--- Time Namespace (timens-0.img) ---");
        if let Some(ref timens) = self.timens {
            log::info!("Monotonic offset: {:?}", timens.monotonic);
            log::info!("Boottime offset: {:?}", timens.boottime);
        } else {
            log::info!("(Not present)");
        }
        log::info!("");
    }

    fn display_tty(&self) {
        log::info!("--- TTY Info (tty-info.img) ---");
        if let Some(ref tty_info) = self.tty_info {
            log::info!("TTY entries: {}", tty_info.len());
        } else {
            log::info!("(Failed to parse or not present)");
        }
    }
}
