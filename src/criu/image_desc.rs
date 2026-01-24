use crate::criu::image::O_NOBUF;

pub mod magic {
    pub const RAW_IMAGE_MAGIC: u32 = 0x0;
    pub const IMG_COMMON_MAGIC: u32 = 0x54564319;
    pub const IMG_SERVICE_MAGIC: u32 = 0x55105940;

    pub const INVENTORY_MAGIC: u32 = 0x58313116;
    pub const PSTREE_MAGIC: u32 = 0x50273030;
    pub const FDINFO_MAGIC: u32 = 0x56213732;
    pub const PAGEMAP_MAGIC: u32 = 0x56084025;
    pub const SHMEM_PAGEMAP_MAGIC: u32 = PAGEMAP_MAGIC;
    pub const PAGES_MAGIC: u32 = RAW_IMAGE_MAGIC;
    pub const CORE_MAGIC: u32 = 0x55053847;
    pub const IDS_MAGIC: u32 = 0x54432030;
    pub const VMAS_MAGIC: u32 = 0x54123737;
    pub const PIPES_MAGIC: u32 = 0x56513555;
    pub const PIPES_DATA_MAGIC: u32 = 0x56453709;
    pub const FIFO_MAGIC: u32 = 0x58364939;
    pub const FIFO_DATA_MAGIC: u32 = 0x59333054;
    pub const SIGACT_MAGIC: u32 = 0x55344201;
    pub const UNIXSK_MAGIC: u32 = 0x54373943;
    pub const INETSK_MAGIC: u32 = 0x56443851;
    pub const PACKETSK_MAGIC: u32 = 0x60454618;
    pub const ITIMERS_MAGIC: u32 = 0x57464056;
    pub const POSIX_TIMERS_MAGIC: u32 = 0x52603957;
    pub const SK_QUEUES_MAGIC: u32 = 0x56264026;
    pub const UTSNS_MAGIC: u32 = 0x54473203;
    pub const CREDS_MAGIC: u32 = 0x54023547;
    pub const IPC_VAR_MAGIC: u32 = 0x53115007;
    pub const IPCNS_SHM_MAGIC: u32 = 0x46283044;
    pub const IPCNS_MSG_MAGIC: u32 = 0x55453737;
    pub const IPCNS_SEM_MAGIC: u32 = 0x59573019;
    pub const REG_FILES_MAGIC: u32 = 0x50363636;
    pub const EXT_FILES_MAGIC: u32 = 0x59255641;
    pub const FS_MAGIC: u32 = 0x51403912;
    pub const MM_MAGIC: u32 = 0x57492820;
    pub const REMAP_FPATH_MAGIC: u32 = 0x59133954;
    pub const GHOST_FILE_MAGIC: u32 = 0x52583605;
    pub const TCP_STREAM_MAGIC: u32 = 0x51465506;
    pub const EVENTFD_FILE_MAGIC: u32 = 0x44523722;
    pub const EVENTPOLL_FILE_MAGIC: u32 = 0x45023858;
    pub const EVENTPOLL_TFD_MAGIC: u32 = 0x44433746;
    pub const SIGNALFD_MAGIC: u32 = 0x57323820;
    pub const INOTIFY_FILE_MAGIC: u32 = 0x48424431;
    pub const INOTIFY_WD_MAGIC: u32 = 0x54562009;
    pub const MNTS_MAGIC: u32 = 0x55563928;
    pub const NETDEV_MAGIC: u32 = 0x57373951;
    pub const NETNS_MAGIC: u32 = 0x55933752;
    pub const TTY_FILES_MAGIC: u32 = 0x59433025;
    pub const TTY_INFO_MAGIC: u32 = 0x59453036;
    pub const TTY_DATA_MAGIC: u32 = 0x59413026;
    pub const FILE_LOCKS_MAGIC: u32 = 0x54323616;
    pub const RLIMIT_MAGIC: u32 = 0x57113925;
    pub const FANOTIFY_FILE_MAGIC: u32 = 0x55096122;
    pub const FANOTIFY_MARK_MAGIC: u32 = 0x56506035;
    pub const SIGNAL_MAGIC: u32 = 0x59255647;
    pub const PSIGNAL_MAGIC: u32 = SIGNAL_MAGIC;
    pub const NETLINK_SK_MAGIC: u32 = 0x58005614;
    pub const NS_FILES_MAGIC: u32 = 0x61394011;
    pub const TUNFILE_MAGIC: u32 = 0x57143751;
    pub const CGROUP_MAGIC: u32 = 0x59383330;
    pub const TIMERFD_MAGIC: u32 = 0x50493712;
    pub const CPUINFO_MAGIC: u32 = 0x61404013;
    pub const USERNS_MAGIC: u32 = 0x55474906;
    pub const SECCOMP_MAGIC: u32 = 0x64413049;
    pub const BINFMT_MISC_MAGIC: u32 = 0x67343323;
    pub const AUTOFS_MAGIC: u32 = 0x49353943;
    pub const FILES_MAGIC: u32 = 0x56303138;
    pub const MEMFD_INODE_MAGIC: u32 = 0x48453499;
    pub const TIMENS_MAGIC: u32 = 0x43114433;
    pub const PIDNS_MAGIC: u32 = 0x61157326;
    pub const BPFMAP_FILE_MAGIC: u32 = 0x57506142;
    pub const BPFMAP_DATA_MAGIC: u32 = 0x64324033;
    pub const APPARMOR_MAGIC: u32 = 0x59423047;
    pub const PIDFD_MAGIC: u32 = 0x54435556;

    pub const IFADDR_MAGIC: u32 = RAW_IMAGE_MAGIC;
    pub const ROUTE_MAGIC: u32 = RAW_IMAGE_MAGIC;
    pub const ROUTE6_MAGIC: u32 = RAW_IMAGE_MAGIC;
    pub const RULE_MAGIC: u32 = RAW_IMAGE_MAGIC;
    pub const TMPFS_IMG_MAGIC: u32 = RAW_IMAGE_MAGIC;
    pub const TMPFS_DEV_MAGIC: u32 = RAW_IMAGE_MAGIC;
    pub const IPTABLES_MAGIC: u32 = RAW_IMAGE_MAGIC;
    pub const IP6TABLES_MAGIC: u32 = RAW_IMAGE_MAGIC;
    pub const NFTABLES_MAGIC: u32 = RAW_IMAGE_MAGIC;
    pub const NETNF_CT_MAGIC: u32 = RAW_IMAGE_MAGIC;
    pub const NETNF_EXP_MAGIC: u32 = RAW_IMAGE_MAGIC;

    pub const PAGES_OLD_MAGIC: u32 = PAGEMAP_MAGIC;
    pub const SHM_PAGES_OLD_MAGIC: u32 = PAGEMAP_MAGIC;
    pub const BINFMT_MISC_OLD_MAGIC: u32 = BINFMT_MISC_MAGIC;

    pub const STATS_MAGIC: u32 = 0x57093306;
    pub const IRMAP_CACHE_MAGIC: u32 = 0x57004059;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CrFdType {
    Inventory = 0,
    Stats,
    Core,
    Ids,
    Mm,
    Creds,
    Fs,
    Pagemap,
    Utsns,
    Mnts,
    Userns,
    Timens,
    Pidns,
    IpcVar,
    IpcnsShm,
    IpcnsMsg,
    IpcnsSem,
    Netdev,
    Ifaddr,
    Route,
    Route6,
    Rule,
    Iptables,
    Ip6tables,
    Nftables,
    Netns,
    NetnfCt,
    NetnfExp,
    Pstree,
    ShmemPagemap,
    GhostFile,
    TcpStream,
    Fdinfo,
    Files,
    SkQueues,
    PipesData,
    FifoData,
    TtyInfo,
    TtyData,
    RemapFpath,
    Cgroup,
    FileLocks,
    Seccomp,
    Apparmor,
    MemfdInode,
    BpfmapFile,
    BpfmapData,
    TmpfsImg,
    TmpfsDev,
    BinfmtMisc,
    BinfmtMiscOld,
    Pages,
    Sigact,
    Vmas,
    PagesOld,
    ShmPagesOld,
    Rlimit,
    Itimers,
    PosixTimers,
    IrmapCache,
    Cpuinfo,
    Signal,
    Psignal,
    InotifyWd,
    FanotifyMark,
    EventpollTfd,
    RegFiles,
    Inetsk,
    NsFiles,
    Packetsk,
    NetlinkSk,
    EventfdFile,
    EventpollFile,
    Signalfd,
    Tunfile,
    Timerfd,
    InotifyFile,
    FanotifyFile,
    ExtFiles,
    Unixsk,
    Fifo,
    Pipes,
    TtyFiles,
    MemfdFile,
    Pidfd,
    Autofs,
    Max,
}

pub struct CrFdDescTmpl {
    pub fmt: &'static str,
    pub magic: u32,
    pub oflags: i32,
}

pub fn get_imgset_template(fd_type: CrFdType) -> CrFdDescTmpl {
    use magic::*;
    use CrFdType::*;

    match fd_type {
        Inventory => CrFdDescTmpl {
            fmt: "inventory",
            magic: INVENTORY_MAGIC,
            oflags: 0,
        },
        Stats => CrFdDescTmpl {
            fmt: "stats-%s",
            magic: STATS_MAGIC,
            oflags: crate::criu::image::O_SERVICE | crate::criu::image::O_FORCE_LOCAL,
        },
        Core => CrFdDescTmpl {
            fmt: "core-%u",
            magic: CORE_MAGIC,
            oflags: 0,
        },
        Ids => CrFdDescTmpl {
            fmt: "ids-%u",
            magic: IDS_MAGIC,
            oflags: 0,
        },
        Mm => CrFdDescTmpl {
            fmt: "mm-%u",
            magic: MM_MAGIC,
            oflags: 0,
        },
        Creds => CrFdDescTmpl {
            fmt: "creds-%u",
            magic: CREDS_MAGIC,
            oflags: 0,
        },
        Fs => CrFdDescTmpl {
            fmt: "fs-%u",
            magic: FS_MAGIC,
            oflags: 0,
        },
        Pagemap => CrFdDescTmpl {
            fmt: "pagemap-%lu",
            magic: PAGEMAP_MAGIC,
            oflags: 0,
        },
        Pstree => CrFdDescTmpl {
            fmt: "pstree",
            magic: PSTREE_MAGIC,
            oflags: 0,
        },
        Fdinfo => CrFdDescTmpl {
            fmt: "fdinfo-%u",
            magic: FDINFO_MAGIC,
            oflags: 0,
        },
        Vmas => CrFdDescTmpl {
            fmt: "vmas-%u",
            magic: VMAS_MAGIC,
            oflags: 0,
        },
        Pages => CrFdDescTmpl {
            fmt: "pages-%u",
            magic: PAGES_MAGIC,
            oflags: O_NOBUF,
        },
        PagesOld => CrFdDescTmpl {
            fmt: "pages-%d",
            magic: PAGES_OLD_MAGIC,
            oflags: O_NOBUF,
        },
        Sigact => CrFdDescTmpl {
            fmt: "sigacts-%u",
            magic: SIGACT_MAGIC,
            oflags: 0,
        },
        Rlimit => CrFdDescTmpl {
            fmt: "rlimit-%u",
            magic: RLIMIT_MAGIC,
            oflags: 0,
        },
        Itimers => CrFdDescTmpl {
            fmt: "itimers-%u",
            magic: ITIMERS_MAGIC,
            oflags: 0,
        },
        PosixTimers => CrFdDescTmpl {
            fmt: "posix-timers-%u",
            magic: POSIX_TIMERS_MAGIC,
            oflags: 0,
        },
        Unixsk => CrFdDescTmpl {
            fmt: "unixsk",
            magic: UNIXSK_MAGIC,
            oflags: 0,
        },
        Inetsk => CrFdDescTmpl {
            fmt: "inetsk",
            magic: INETSK_MAGIC,
            oflags: 0,
        },
        RegFiles => CrFdDescTmpl {
            fmt: "reg-files",
            magic: REG_FILES_MAGIC,
            oflags: 0,
        },
        ExtFiles => CrFdDescTmpl {
            fmt: "ext-files",
            magic: EXT_FILES_MAGIC,
            oflags: 0,
        },
        NsFiles => CrFdDescTmpl {
            fmt: "ns-files",
            magic: NS_FILES_MAGIC,
            oflags: 0,
        },
        Files => CrFdDescTmpl {
            fmt: "files",
            magic: FILES_MAGIC,
            oflags: 0,
        },
        Pipes => CrFdDescTmpl {
            fmt: "pipes",
            magic: PIPES_MAGIC,
            oflags: 0,
        },
        PipesData => CrFdDescTmpl {
            fmt: "pipes-data",
            magic: PIPES_DATA_MAGIC,
            oflags: O_NOBUF,
        },
        Fifo => CrFdDescTmpl {
            fmt: "fifo",
            magic: FIFO_MAGIC,
            oflags: 0,
        },
        FifoData => CrFdDescTmpl {
            fmt: "fifo-data",
            magic: FIFO_DATA_MAGIC,
            oflags: O_NOBUF,
        },
        EventfdFile => CrFdDescTmpl {
            fmt: "eventfd",
            magic: EVENTFD_FILE_MAGIC,
            oflags: 0,
        },
        EventpollFile => CrFdDescTmpl {
            fmt: "eventpoll",
            magic: EVENTPOLL_FILE_MAGIC,
            oflags: 0,
        },
        EventpollTfd => CrFdDescTmpl {
            fmt: "eventpoll-tfd",
            magic: EVENTPOLL_TFD_MAGIC,
            oflags: 0,
        },
        Signalfd => CrFdDescTmpl {
            fmt: "signalfd",
            magic: SIGNALFD_MAGIC,
            oflags: 0,
        },
        InotifyFile => CrFdDescTmpl {
            fmt: "inotify",
            magic: INOTIFY_FILE_MAGIC,
            oflags: 0,
        },
        InotifyWd => CrFdDescTmpl {
            fmt: "inotify-wd",
            magic: INOTIFY_WD_MAGIC,
            oflags: 0,
        },
        FanotifyFile => CrFdDescTmpl {
            fmt: "fanotify",
            magic: FANOTIFY_FILE_MAGIC,
            oflags: 0,
        },
        FanotifyMark => CrFdDescTmpl {
            fmt: "fanotify-mark",
            magic: FANOTIFY_MARK_MAGIC,
            oflags: 0,
        },
        TtyFiles => CrFdDescTmpl {
            fmt: "tty",
            magic: TTY_FILES_MAGIC,
            oflags: 0,
        },
        TtyInfo => CrFdDescTmpl {
            fmt: "tty-info",
            magic: TTY_INFO_MAGIC,
            oflags: 0,
        },
        TtyData => CrFdDescTmpl {
            fmt: "tty-data",
            magic: TTY_DATA_MAGIC,
            oflags: O_NOBUF,
        },
        Utsns => CrFdDescTmpl {
            fmt: "utsns-%u",
            magic: UTSNS_MAGIC,
            oflags: 0,
        },
        Mnts => CrFdDescTmpl {
            fmt: "mountpoints-%u",
            magic: MNTS_MAGIC,
            oflags: 0,
        },
        Userns => CrFdDescTmpl {
            fmt: "userns-%u",
            magic: USERNS_MAGIC,
            oflags: 0,
        },
        Timens => CrFdDescTmpl {
            fmt: "timens-%u",
            magic: TIMENS_MAGIC,
            oflags: 0,
        },
        Pidns => CrFdDescTmpl {
            fmt: "pidns-%u",
            magic: PIDNS_MAGIC,
            oflags: 0,
        },
        Netns => CrFdDescTmpl {
            fmt: "netns-%u",
            magic: NETNS_MAGIC,
            oflags: 0,
        },
        Netdev => CrFdDescTmpl {
            fmt: "netdev-%u",
            magic: NETDEV_MAGIC,
            oflags: 0,
        },
        IpcVar => CrFdDescTmpl {
            fmt: "ipcns-var-%u",
            magic: IPC_VAR_MAGIC,
            oflags: 0,
        },
        IpcnsShm => CrFdDescTmpl {
            fmt: "ipcns-shm-%u",
            magic: IPCNS_SHM_MAGIC,
            oflags: O_NOBUF,
        },
        IpcnsMsg => CrFdDescTmpl {
            fmt: "ipcns-msg-%u",
            magic: IPCNS_MSG_MAGIC,
            oflags: 0,
        },
        IpcnsSem => CrFdDescTmpl {
            fmt: "ipcns-sem-%u",
            magic: IPCNS_SEM_MAGIC,
            oflags: 0,
        },
        Ifaddr => CrFdDescTmpl {
            fmt: "ifaddr-%u",
            magic: IFADDR_MAGIC,
            oflags: O_NOBUF,
        },
        Route => CrFdDescTmpl {
            fmt: "route-%u",
            magic: ROUTE_MAGIC,
            oflags: O_NOBUF,
        },
        Route6 => CrFdDescTmpl {
            fmt: "route6-%u",
            magic: ROUTE6_MAGIC,
            oflags: O_NOBUF,
        },
        Rule => CrFdDescTmpl {
            fmt: "rule-%u",
            magic: RULE_MAGIC,
            oflags: O_NOBUF,
        },
        Iptables => CrFdDescTmpl {
            fmt: "iptables-%u",
            magic: IPTABLES_MAGIC,
            oflags: O_NOBUF,
        },
        Ip6tables => CrFdDescTmpl {
            fmt: "ip6tables-%u",
            magic: IP6TABLES_MAGIC,
            oflags: O_NOBUF,
        },
        Nftables => CrFdDescTmpl {
            fmt: "nftables-%u",
            magic: NFTABLES_MAGIC,
            oflags: O_NOBUF,
        },
        NetnfCt => CrFdDescTmpl {
            fmt: "netns-ct-%u",
            magic: NETNF_CT_MAGIC,
            oflags: 0,
        },
        NetnfExp => CrFdDescTmpl {
            fmt: "netns-exp-%u",
            magic: NETNF_EXP_MAGIC,
            oflags: 0,
        },
        FileLocks => CrFdDescTmpl {
            fmt: "filelocks",
            magic: FILE_LOCKS_MAGIC,
            oflags: 0,
        },
        Signal => CrFdDescTmpl {
            fmt: "signal-s-%u",
            magic: SIGNAL_MAGIC,
            oflags: 0,
        },
        Psignal => CrFdDescTmpl {
            fmt: "signal-p-%u",
            magic: PSIGNAL_MAGIC,
            oflags: 0,
        },
        Cgroup => CrFdDescTmpl {
            fmt: "cgroup",
            magic: CGROUP_MAGIC,
            oflags: 0,
        },
        Seccomp => CrFdDescTmpl {
            fmt: "seccomp",
            magic: SECCOMP_MAGIC,
            oflags: 0,
        },
        Timerfd => CrFdDescTmpl {
            fmt: "timerfd",
            magic: TIMERFD_MAGIC,
            oflags: 0,
        },
        Cpuinfo => CrFdDescTmpl {
            fmt: "cpuinfo",
            magic: CPUINFO_MAGIC,
            oflags: 0,
        },
        Tunfile => CrFdDescTmpl {
            fmt: "tunfile",
            magic: TUNFILE_MAGIC,
            oflags: 0,
        },
        Packetsk => CrFdDescTmpl {
            fmt: "packetsk",
            magic: PACKETSK_MAGIC,
            oflags: 0,
        },
        NetlinkSk => CrFdDescTmpl {
            fmt: "netlinksk",
            magic: NETLINK_SK_MAGIC,
            oflags: 0,
        },
        SkQueues => CrFdDescTmpl {
            fmt: "sk-queues",
            magic: SK_QUEUES_MAGIC,
            oflags: O_NOBUF,
        },
        RemapFpath => CrFdDescTmpl {
            fmt: "remap-fpath",
            magic: REMAP_FPATH_MAGIC,
            oflags: 0,
        },
        GhostFile => CrFdDescTmpl {
            fmt: "ghost-file-%x",
            magic: GHOST_FILE_MAGIC,
            oflags: O_NOBUF,
        },
        TcpStream => CrFdDescTmpl {
            fmt: "tcp-stream-%x",
            magic: TCP_STREAM_MAGIC,
            oflags: 0,
        },
        ShmemPagemap => CrFdDescTmpl {
            fmt: "pagemap-shmem-%lu",
            magic: SHMEM_PAGEMAP_MAGIC,
            oflags: 0,
        },
        ShmPagesOld => CrFdDescTmpl {
            fmt: "pages-shmem-%ld",
            magic: SHM_PAGES_OLD_MAGIC,
            oflags: O_NOBUF,
        },
        BinfmtMisc => CrFdDescTmpl {
            fmt: "binfmt-misc",
            magic: BINFMT_MISC_MAGIC,
            oflags: 0,
        },
        BinfmtMiscOld => CrFdDescTmpl {
            fmt: "binfmt-misc-%u",
            magic: BINFMT_MISC_OLD_MAGIC,
            oflags: 0,
        },
        TmpfsImg => CrFdDescTmpl {
            fmt: "tmpfs-%u.tar.gz",
            magic: TMPFS_IMG_MAGIC,
            oflags: O_NOBUF,
        },
        TmpfsDev => CrFdDescTmpl {
            fmt: "tmpfs-dev-%u.tar.gz",
            magic: TMPFS_DEV_MAGIC,
            oflags: O_NOBUF,
        },
        Autofs => CrFdDescTmpl {
            fmt: "autofs-%u",
            magic: AUTOFS_MAGIC,
            oflags: O_NOBUF,
        },
        MemfdInode => CrFdDescTmpl {
            fmt: "memfd",
            magic: MEMFD_INODE_MAGIC,
            oflags: O_NOBUF,
        },
        MemfdFile => CrFdDescTmpl {
            fmt: "memfd-file",
            magic: MEMFD_INODE_MAGIC,
            oflags: 0,
        },
        Apparmor => CrFdDescTmpl {
            fmt: "apparmor",
            magic: APPARMOR_MAGIC,
            oflags: 0,
        },
        BpfmapFile => CrFdDescTmpl {
            fmt: "bpfmap-file",
            magic: BPFMAP_FILE_MAGIC,
            oflags: O_NOBUF,
        },
        BpfmapData => CrFdDescTmpl {
            fmt: "bpfmap-data",
            magic: BPFMAP_DATA_MAGIC,
            oflags: O_NOBUF,
        },
        Pidfd => CrFdDescTmpl {
            fmt: "pidfd",
            magic: PIDFD_MAGIC,
            oflags: 0,
        },
        IrmapCache => CrFdDescTmpl {
            fmt: "irmap-cache",
            magic: IRMAP_CACHE_MAGIC,
            oflags: crate::criu::image::O_SERVICE | crate::criu::image::O_FORCE_LOCAL,
        },
        Max => CrFdDescTmpl {
            fmt: "",
            magic: 0,
            oflags: 0,
        },
    }
}
