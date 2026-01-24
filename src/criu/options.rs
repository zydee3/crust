//! CRIU options - global configuration for dump/restore operations.
//!
//! Maps to: criu/include/cr_options.h

use std::sync::OnceLock;

/// Global options instance - initialized once at startup, read everywhere.
/// Maps to: extern struct cr_options opts (criu/cr-options.c)
pub static OPTS: OnceLock<CriuOpts> = OnceLock::new();

/// Initialize the global options.
pub fn opts_init(opts: CriuOpts) -> Result<(), CriuOpts> {
    OPTS.set(opts)
}

/// Get reference to global options. Panics if not initialized.
pub fn opts() -> &'static CriuOpts {
    OPTS.get().expect("OPTS not initialized")
}

/// Get reference to global options, returning None if not initialized.
pub fn opts_try() -> Option<&'static CriuOpts> {
    OPTS.get()
}

/// CRIU operation mode.
/// Maps to: enum criu_mode (criu/include/cr_options.h:117-132)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum CriuMode {
    #[default]
    Unset = 0,
    Dump,
    PreDump,
    Restore,
    LazyPages,
    Check,
    PageServer,
    Service,
    Swrk,
    Dedup,
    CpuinfoDump,
    CpuinfoCheck,
    ExecDeprecated,
    ShowDeprecated,
}

/// Network locking method.
/// Maps to: enum NETWORK_LOCK_METHOD (criu/include/cr_options.h:67-71)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum NetworkLockMethod {
    #[default]
    Iptables = 0,
    Nftables,
    Skip,
}

/// File validation method.
/// Maps to: enum FILE_VALIDATION_OPTIONS (criu/include/cr_options.h:90-109)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum FileValidationMethod {
    #[default]
    FileSize = 0,
    BuildId,
}

/// Cgroup management mode flags.
pub const CG_MODE_IGNORE: u32 = 0;
pub const CG_MODE_NONE: u32 = 1 << 0;
pub const CG_MODE_PROPS: u32 = 1 << 1;
pub const CG_MODE_SOFT: u32 = 1 << 2;
pub const CG_MODE_FULL: u32 = 1 << 3;
pub const CG_MODE_STRICT: u32 = 1 << 4;
pub const CG_MODE_DEFAULT: u32 = CG_MODE_SOFT;

/// Pre-dump mode.
pub const PRE_DUMP_SPLICE: i32 = 1;
pub const PRE_DUMP_READ: i32 = 2;

/// Linux capability array size.
const LINUX_CAPABILITY_U32S_3: usize = 2;

/// CRIU options structure.
/// Maps to: struct cr_options (criu/include/cr_options.h:134-250)
#[derive(Debug, Clone)]
pub struct CriuOpts {
    pub final_state: i32,
    pub check_extra_features: i32,
    pub check_experimental_features: i32,
    pub restore_detach: i32,
    pub restore_sibling: i32,
    pub ext_unix_sk: bool,
    pub shell_job: i32,
    pub handle_file_locks: i32,
    pub tcp_established_ok: i32,
    pub tcp_close: i32,
    pub evasive_devices: i32,
    pub link_remap_ok: i32,
    pub log_file_per_pid: i32,
    pub pre_dump_mode: i32,
    pub swrk_restore: bool,
    pub output: Option<String>,
    pub root: Option<String>,
    pub pidfile: Option<String>,
    pub freeze_cgroup: Option<String>,
    // ext_mounts, inherit_fds, external, join_ns are lists - use Vec
    pub ext_mounts: Vec<ExtMountEntry>,
    pub inherit_fds: Vec<InheritFdEntry>,
    pub external: Vec<String>,
    pub join_ns: Vec<JoinNsEntry>,
    pub libdir: Option<String>,
    pub use_page_server: i32,
    pub port: u16,
    pub addr: Option<String>,
    pub ps_socket: i32,
    pub track_mem: i32,
    pub img_parent: Option<String>,
    pub auto_dedup: i32,
    pub cpu_cap: u32,
    pub force_irmap: i32,
    pub exec_cmd: Vec<String>,
    pub manage_cgroups: u32,
    pub new_global_cg_root: Option<String>,
    pub cgroup_props: Option<String>,
    pub cgroup_props_file: Option<String>,
    pub new_cgroup_roots: Vec<CgRootEntry>,
    pub cgroup_yard: Option<String>,
    pub autodetect_ext_mounts: bool,
    pub enable_external_sharing: i32,
    pub enable_external_masters: i32,
    pub aufs: bool,
    pub overlayfs: bool,
    pub ghost_fiemap: i32,
    pub has_binfmt_misc: bool,
    pub ghost_limit: usize,
    pub irmap_scan_paths: Vec<String>,
    pub lsm_supplied: bool,
    pub lsm_profile: Option<String>,
    pub lsm_mount_context: Option<String>,
    pub timeout: u32,
    pub empty_ns: u32,
    pub tcp_skip_in_flight: i32,
    pub lazy_pages: bool,
    pub work_dir: Option<String>,
    pub network_lock_method: NetworkLockMethod,
    pub skip_file_rwx_check: i32,
    pub allow_uprobes: i32,
    pub deprecated_ok: i32,
    pub display_stats: i32,
    pub weak_sysctls: i32,
    pub status_fd: i32,
    pub orphan_pts_master: bool,
    pub stream: i32,
    pub tree_id: libc::pid_t,
    pub log_level: i32,
    pub imgs_dir: Option<String>,
    pub tls_cacert: Option<String>,
    pub tls_cacrl: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub tls: i32,
    pub tls_no_cn_verify: i32,
    pub file_validation_method: FileValidationMethod,
    pub mode: CriuMode,
    pub mntns_compat_mode: i32,
    pub argv_0: Option<String>,
    pub uid: libc::uid_t,
    pub cap_eff: [u32; LINUX_CAPABILITY_U32S_3],
    pub unprivileged: i32,
}

/// External mount entry.
#[derive(Debug, Clone, Default)]
pub struct ExtMountEntry {
    pub key: String,
    pub val: String,
}

/// Inherited file descriptor entry.
#[derive(Debug, Clone, Default)]
pub struct InheritFdEntry {
    pub inh_id: String,
    pub inh_fd: i32,
    pub inh_fd_id: i32,
}

/// Join namespace entry.
#[derive(Debug, Clone, Default)]
pub struct JoinNsEntry {
    pub ns_file: String,
    pub ns_type: i32,
    pub extra_opts: Option<String>,
}

/// Cgroup root entry.
#[derive(Debug, Clone, Default)]
pub struct CgRootEntry {
    pub controller: String,
    pub newroot: String,
}

impl Default for CriuOpts {
    fn default() -> Self {
        Self {
            final_state: 0,
            check_extra_features: 0,
            check_experimental_features: 0,
            restore_detach: 0,
            restore_sibling: 0,
            ext_unix_sk: false,
            shell_job: 0,
            handle_file_locks: 0,
            tcp_established_ok: 0,
            tcp_close: 0,
            evasive_devices: 0,
            link_remap_ok: 0,
            log_file_per_pid: 0,
            pre_dump_mode: 0,
            swrk_restore: false,
            output: None,
            root: None,
            pidfile: None,
            freeze_cgroup: None,
            ext_mounts: Vec::new(),
            inherit_fds: Vec::new(),
            external: Vec::new(),
            join_ns: Vec::new(),
            libdir: None,
            use_page_server: 0,
            port: 0,
            addr: None,
            ps_socket: -1,
            track_mem: 0,
            img_parent: None,
            auto_dedup: 0,
            cpu_cap: 0,
            force_irmap: 0,
            exec_cmd: Vec::new(),
            manage_cgroups: CG_MODE_DEFAULT,
            new_global_cg_root: None,
            cgroup_props: None,
            cgroup_props_file: None,
            new_cgroup_roots: Vec::new(),
            cgroup_yard: None,
            autodetect_ext_mounts: false,
            enable_external_sharing: 0,
            enable_external_masters: 0,
            aufs: false,
            overlayfs: false,
            ghost_fiemap: 0,
            has_binfmt_misc: false,
            ghost_limit: 1 << 20, // DEFAULT_GHOST_LIMIT
            irmap_scan_paths: Vec::new(),
            lsm_supplied: false,
            lsm_profile: None,
            lsm_mount_context: None,
            timeout: 10, // DEFAULT_TIMEOUT
            empty_ns: 0,
            tcp_skip_in_flight: 0,
            lazy_pages: false,
            work_dir: None,
            network_lock_method: NetworkLockMethod::Iptables,
            skip_file_rwx_check: 0,
            allow_uprobes: 0,
            deprecated_ok: 0,
            display_stats: 0,
            weak_sysctls: 0,
            status_fd: -1,
            orphan_pts_master: false,
            stream: 0,
            tree_id: 0,
            log_level: 0,
            imgs_dir: None,
            tls_cacert: None,
            tls_cacrl: None,
            tls_cert: None,
            tls_key: None,
            tls: 0,
            tls_no_cn_verify: 0,
            file_validation_method: FileValidationMethod::FileSize,
            mode: CriuMode::Unset,
            mntns_compat_mode: 0,
            argv_0: None,
            uid: 0,
            cap_eff: [0; LINUX_CAPABILITY_U32S_3],
            unprivileged: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criu_opts_default() {
        let opts = CriuOpts::default();
        assert_eq!(opts.mode, CriuMode::Unset);
        assert_eq!(opts.network_lock_method, NetworkLockMethod::Iptables);
        assert!(!opts.lazy_pages);
        assert_eq!(opts.ghost_limit, 1 << 20);
    }

    #[test]
    fn test_network_lock_method_values() {
        assert_eq!(NetworkLockMethod::Iptables as i32, 0);
        assert_eq!(NetworkLockMethod::Nftables as i32, 1);
        assert_eq!(NetworkLockMethod::Skip as i32, 2);
    }

    #[test]
    fn test_criu_mode_values() {
        assert_eq!(CriuMode::Unset as i32, 0);
        assert_eq!(CriuMode::Dump as i32, 1);
        assert_eq!(CriuMode::Restore as i32, 3);
    }
}
