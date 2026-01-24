//! Kernel data - runtime kernel capability detection.
//!
//! Maps to: criu/include/kerndat.h

use std::sync::OnceLock;

/// Global kernel data instance - probed once at startup, read everywhere.
/// Maps to: extern struct kerndat_s kdat (criu/kerndat.c)
pub static KDAT: OnceLock<KernelData> = OnceLock::new();

/// Initialize the global kernel data.
pub fn kdat_init(kdat: KernelData) -> Result<(), KernelData> {
    KDAT.set(kdat)
}

/// Get reference to global kernel data. Panics if not initialized.
pub fn kdat() -> &'static KernelData {
    KDAT.get().expect("KDAT not initialized")
}

/// Get reference to global kernel data, returning None if not initialized.
pub fn kdat_try() -> Option<&'static KernelData> {
    KDAT.get()
}

/// Login UID functionality level.
/// Maps to: enum loginuid_func (criu/include/kerndat.h:28-32)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum LoginuidFunc {
    #[default]
    None = 0,
    Read,
    Full,
}

/// Pagemap functionality level.
/// Maps to: enum pagemap_func (criu/include/kerndat.h:21-26)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum PagemapFunc {
    #[default]
    Unknown = 0,
    Disabled,
    FlagsOnly,
    Full,
}

/// Maximum number of hugetlb page sizes.
pub const HUGETLB_MAX: usize = 4;

/// vDSO symbol table.
/// Maps to: struct vdso_symtable (criu/include/vdso.h)
#[derive(Debug, Clone, Default)]
pub struct VdsoSymtable {
    pub vdso_size: usize,
    pub vvar_size: usize,
    pub vvar_vclock_size: usize,
    pub vdso_before_vvar: bool,
}

/// ptrace rseq configuration.
/// Maps to: struct __ptrace_rseq_configuration
#[derive(Debug, Clone, Default)]
pub struct PtraceRseqConfiguration {
    pub rseq_abi_pointer: u64,
    pub rseq_abi_size: u32,
    pub signature: u32,
    pub flags: u32,
}

/// Kernel data structure - detected kernel capabilities.
/// Maps to: struct kerndat_s (criu/include/kerndat.h:34-96)
#[derive(Debug, Clone)]
pub struct KernelData {
    pub magic1: u32,
    pub magic2: u32,
    pub shmem_dev: libc::dev_t,
    pub last_cap: i32,
    pub zero_page_pfn: u64,
    pub has_dirty_track: bool,
    pub has_memfd: bool,
    pub has_memfd_hugetlb: bool,
    pub has_fdinfo_lock: bool,
    pub task_size: u64,
    pub ipv6: bool,
    pub luid: LoginuidFunc,
    pub compat_cr: bool,
    pub sk_ns: bool,
    pub sk_unix_file: bool,
    pub tun_ns: bool,
    pub pmap: PagemapFunc,
    pub has_xtlocks: u32,
    pub mmap_min_addr: u64,
    pub has_tcp_half_closed: bool,
    pub stack_guard_gap_hidden: bool,
    pub lsm: i32,
    pub apparmor_ns_dumping_enabled: bool,
    pub has_uffd: bool,
    pub uffd_features: u64,
    pub has_thp_disable: bool,
    pub can_map_vdso: bool,
    pub vdso_hint_reliable: bool,
    pub vdso_sym: VdsoSymtable,
    pub has_nsid: bool,
    pub has_link_nsid: bool,
    pub sysctl_nr_open: u32,
    pub x86_has_ptrace_fpu_xsave_bug: bool,
    pub has_inotify_setnextwd: bool,
    pub has_kcmp_epoll_tfd: bool,
    pub has_fsopen: bool,
    pub has_clone3_set_tid: bool,
    pub has_timens: bool,
    pub has_newifindex: bool,
    pub has_pidfd_open: bool,
    pub has_pidfd_getfd: bool,
    pub has_nspid: bool,
    pub has_nftables_concat: bool,
    pub has_sockopt_buf_lock: bool,
    pub hugetlb_dev: [libc::dev_t; HUGETLB_MAX],
    pub has_move_mount_set_group: bool,
    pub has_openat2: bool,
    pub has_rseq: bool,
    pub has_ptrace_get_rseq_conf: bool,
    pub libc_rseq_conf: PtraceRseqConfiguration,
    pub has_ipv6_freebind: bool,
    pub has_membarrier_get_registrations: bool,
    pub has_pagemap_scan: bool,
    pub has_shstk: bool,
    pub has_close_range: bool,
    pub has_timer_cr_ids: bool,
    pub has_breakpoints: bool,
    pub has_madv_guard: bool,
    pub has_pagemap_scan_guard_pages: bool,
}

impl Default for KernelData {
    fn default() -> Self {
        Self {
            magic1: 0,
            magic2: 0,
            shmem_dev: 0,
            last_cap: 0,
            zero_page_pfn: 0,
            has_dirty_track: false,
            has_memfd: false,
            has_memfd_hugetlb: false,
            has_fdinfo_lock: false,
            task_size: 0,
            ipv6: false,
            luid: LoginuidFunc::None,
            compat_cr: false,
            sk_ns: false,
            sk_unix_file: false,
            tun_ns: false,
            pmap: PagemapFunc::Unknown,
            has_xtlocks: 0,
            mmap_min_addr: 0,
            has_tcp_half_closed: false,
            stack_guard_gap_hidden: false,
            lsm: 0,
            apparmor_ns_dumping_enabled: false,
            has_uffd: false,
            uffd_features: 0,
            has_thp_disable: false,
            can_map_vdso: false,
            vdso_hint_reliable: false,
            vdso_sym: VdsoSymtable::default(),
            has_nsid: false,
            has_link_nsid: false,
            sysctl_nr_open: 1024 * 1024,
            x86_has_ptrace_fpu_xsave_bug: false,
            has_inotify_setnextwd: false,
            has_kcmp_epoll_tfd: false,
            has_fsopen: false,
            has_clone3_set_tid: false,
            has_timens: false,
            has_newifindex: false,
            has_pidfd_open: false,
            has_pidfd_getfd: false,
            has_nspid: false,
            has_nftables_concat: false,
            has_sockopt_buf_lock: false,
            hugetlb_dev: [0; HUGETLB_MAX],
            has_move_mount_set_group: false,
            has_openat2: false,
            has_rseq: false,
            has_ptrace_get_rseq_conf: false,
            libc_rseq_conf: PtraceRseqConfiguration::default(),
            has_ipv6_freebind: false,
            has_membarrier_get_registrations: false,
            has_pagemap_scan: false,
            has_shstk: false,
            has_close_range: false,
            has_timer_cr_ids: false,
            has_breakpoints: false,
            has_madv_guard: false,
            has_pagemap_scan_guard_pages: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_data_default() {
        let kdat = KernelData::default();
        assert_eq!(kdat.luid, LoginuidFunc::None);
        assert_eq!(kdat.pmap, PagemapFunc::Unknown);
        assert!(!kdat.ipv6);
        assert!(!kdat.has_memfd);
    }

    #[test]
    fn test_loginuid_func_values() {
        assert_eq!(LoginuidFunc::None as i32, 0);
        assert_eq!(LoginuidFunc::Read as i32, 1);
        assert_eq!(LoginuidFunc::Full as i32, 2);
    }

    #[test]
    fn test_pagemap_func_values() {
        assert_eq!(PagemapFunc::Unknown as i32, 0);
        assert_eq!(PagemapFunc::Disabled as i32, 1);
        assert_eq!(PagemapFunc::FlagsOnly as i32, 2);
        assert_eq!(PagemapFunc::Full as i32, 3);
    }

    #[test]
    fn test_vdso_symtable_default() {
        let sym = VdsoSymtable::default();
        assert_eq!(sym.vdso_size, 0);
        assert_eq!(sym.vvar_size, 0);
        assert!(!sym.vdso_before_vvar);
    }
}
