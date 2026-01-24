use std::os::unix::io::RawFd;
use std::sync::OnceLock;

use crate::criu::image::{close_image, open_image};
use crate::criu::image_desc::CrFdType;
use crate::criu::protobuf::{pb_read_one, pb_read_one_eof};
use crate::criu::pstree::root_item_idx;
use crate::criu::rst_malloc::shmalloc;
use crate::proto::{PidnsEntry, UsernsEntry};

pub static MNT_NS_DESC: NsDesc = NsDesc::new(libc::CLONE_NEWNS as u32, "mnt");

static ROOT_NS_MASK: OnceLock<u64> = OnceLock::new();

struct NsIdsPtr(*mut NsId);
unsafe impl Send for NsIdsPtr {}
unsafe impl Sync for NsIdsPtr {}

static NS_IDS: OnceLock<std::sync::Mutex<NsIdsPtr>> = OnceLock::new();

pub fn set_root_ns_mask(mask: u64) -> Result<(), u64> {
    ROOT_NS_MASK.set(mask)
}

pub fn root_ns_mask() -> u64 {
    *ROOT_NS_MASK.get().expect("root_ns_mask not initialized")
}

pub fn root_ns_mask_try() -> Option<u64> {
    ROOT_NS_MASK.get().copied()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NsType {
    #[default]
    Unknown = 0,
    Criu,
    Root,
    Other,
}

#[derive(Debug, Clone)]
pub struct NsDesc {
    pub cflag: u32,
    pub name: &'static str,
}

impl NsDesc {
    pub const fn new(cflag: u32, name: &'static str) -> Self {
        Self { cflag, name }
    }

    pub fn len(&self) -> usize {
        self.name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_empty()
    }
}

pub mod ns_desc {
    use super::NsDesc;

    pub const NET: NsDesc = NsDesc::new(libc::CLONE_NEWNET as u32, "net");
    pub const UTS: NsDesc = NsDesc::new(libc::CLONE_NEWUTS as u32, "uts");
    pub const IPC: NsDesc = NsDesc::new(libc::CLONE_NEWIPC as u32, "ipc");
    pub const PID: NsDesc = NsDesc::new(libc::CLONE_NEWPID as u32, "pid");
    pub const USER: NsDesc = NsDesc::new(libc::CLONE_NEWUSER as u32, "user");
    pub const MNT: NsDesc = NsDesc::new(libc::CLONE_NEWNS as u32, "mnt");
    pub const CGROUP: NsDesc = NsDesc::new(libc::CLONE_NEWCGROUP as u32, "cgroup");
}

#[derive(Debug, Default)]
pub struct NsIdMnt {
    pub nsfd_id: i32,
    pub root_fd_id: i32,
    pub mntinfo_tree: Option<usize>,
    pub mntinfo_list: Option<usize>,
}

#[derive(Debug, Default)]
pub struct NsIdNet {
    // ns_fd is used when network namespaces are being restored. On this stage
    // we access these file descriptors many times and it is more efficient to
    // have them opened rather than to get them from fdstore.
    //
    // nsfd_id is used to restore sockets. On this stage we can't use random
    // file descriptors to not conflict with restored file descriptors.
    pub ns_fd: RawFd, // a namespace file descriptor
    pub nlsk: RawFd,  // for sockets collection
    pub seqsk: RawFd, // to talk to parasite daemons
    pub netns: Option<crate::proto::NetnsEntry>,
}

#[derive(Debug)]
pub enum NsIdData {
    None,
    Mnt(NsIdMnt),
    Net(NsIdNet),
}

impl Default for NsIdData {
    fn default() -> Self {
        NsIdData::None
    }
}

#[repr(C)]
pub struct NsId {
    pub kid: u32,
    pub id: u32,
    pub ns_pid: libc::pid_t,
    pub nd: &'static NsDesc,
    pub next: *mut NsId,
    pub ns_type: NsType,
    pub ext_key: Option<String>,
    /*
     * For mount namespaces on restore -- indicates that
     * the namespace in question is created (all mounts
     * are mounted) and other tasks may do setns on it
     * and proceed.
     */
    pub ns_populated: bool,
    pub data: NsIdData,
}

impl NsId {
    pub fn new(nd: &'static NsDesc, id: u32, ns_pid: libc::pid_t) -> Self {
        Self {
            kid: 0,
            id,
            ns_pid,
            nd,
            next: std::ptr::null_mut(),
            ns_type: NsType::Unknown,
            ext_key: None,
            ns_populated: false,
            data: NsIdData::None,
        }
    }
}

#[derive(Default)]
pub struct NsIdStore {
    namespaces: Vec<NsId>,
}

impl NsIdStore {
    pub fn new() -> Self {
        Self {
            namespaces: Vec::new(),
        }
    }

    pub fn nsid_add(&mut self, ns: NsId) -> usize {
        let idx = self.namespaces.len();
        log::info!("Add {} ns {} pid {}", ns.nd.name, ns.id, ns.ns_pid);
        self.namespaces.push(ns);
        idx
    }

    pub fn get(&self, idx: usize) -> Option<&NsId> {
        self.namespaces.get(idx)
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<&mut NsId> {
        self.namespaces.get_mut(idx)
    }

    pub fn len(&self) -> usize {
        self.namespaces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.namespaces.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &NsId> {
        self.namespaces.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut NsId> {
        self.namespaces.iter_mut()
    }

    pub fn lookup_ns_by_id(&self, id: u32, nd: &NsDesc) -> Option<usize> {
        self.namespaces
            .iter()
            .position(|ns| ns.id == id && ns.nd.cflag == nd.cflag)
    }
}

pub fn restore_ns(rst: RawFd, nd: &NsDesc) -> i32 {
    let ret = unsafe { libc::setns(rst, nd.cflag as i32) };
    if ret < 0 {
        log::error!("Can't restore ns back");
    }

    unsafe { libc::close(rst) };

    ret
}

pub fn write_id_map(
    pid: libc::pid_t,
    extents: &[crate::proto::UidGidExtent],
    id_map: &str,
) -> i32 {
    use std::ffi::CString;
    use std::io::Write;

    /*
     *  We can perform only a single write (that may contain multiple
     *  newline-delimited records) to a uid_map and a gid_map files.
     */
    let mut buf = Vec::with_capacity(4096);
    for ext in extents {
        if writeln!(buf, "{} {} {}", ext.first, ext.lower_first, ext.count).is_err() {
            log::error!("Unable to form the user/group mappings buffer");
            return -1;
        }
    }

    // Open /proc/<pid>/<id_map> for writing
    let path = format!("/proc/{}/{}", pid, id_map);
    let c_path = match CString::new(path.clone()) {
        Ok(p) => p,
        Err(_) => {
            log::error!("Invalid path: {}", path);
            return -1;
        }
    };

    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY) };
    if fd < 0 {
        log::error!("Failed to open {}", path);
        return -1;
    }

    // Single write of entire buffer
    let written = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if written as usize != buf.len() {
        log::error!("Unable to write into {}", id_map);
        unsafe { libc::close(fd) };
        return -1;
    }

    unsafe { libc::close(fd) };
    0
}

fn get_ns_ids() -> &'static std::sync::Mutex<NsIdsPtr> {
    NS_IDS.get_or_init(|| std::sync::Mutex::new(NsIdsPtr(std::ptr::null_mut())))
}

fn nsid_add_to_list(ns: *mut NsId, nd: &'static NsDesc, id: u32, pid: libc::pid_t) {
    unsafe {
        (*ns).nd = nd;
        (*ns).id = id;
        (*ns).ns_pid = pid;

        let mut guard = get_ns_ids().lock().unwrap();
        (*ns).next = guard.0;
        guard.0 = ns;
    }

    log::info!("Add {} ns {} pid {}", nd.name, id, pid);
}

pub fn rst_new_ns_id(
    id: u32,
    pid: libc::pid_t,
    nd: &'static NsDesc,
    ns_type: NsType,
) -> *mut NsId {
    let nsid = shmalloc(std::mem::size_of::<NsId>()) as *mut NsId;
    if nsid.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        (*nsid).kid = 0;
        (*nsid).ns_type = ns_type;
        (*nsid).ext_key = None;
        (*nsid).ns_populated = false;
        (*nsid).data = NsIdData::None;

        nsid_add_to_list(nsid, nd, id, pid);

        if nd.cflag == libc::CLONE_NEWNET as u32 {
            (*nsid).data = NsIdData::Net(NsIdNet {
                ns_fd: -1,
                nlsk: -1,
                seqsk: -1,
                netns: None,
            });
        }
    }

    nsid
}

pub fn lookup_ns_by_id_ptr(id: u32, nd: &NsDesc) -> *mut NsId {
    let guard = get_ns_ids().lock().unwrap();
    let mut nsid = guard.0;

    while !nsid.is_null() {
        unsafe {
            if (*nsid).id == id && (*nsid).nd.cflag == nd.cflag {
                return nsid;
            }
            nsid = (*nsid).next;
        }
    }

    std::ptr::null_mut()
}

pub fn rst_add_ns_id(
    id: u32,
    item_idx: usize,
    pid: libc::pid_t,
    nd: &'static NsDesc,
) -> i32 {
    let nsid = lookup_ns_by_id_ptr(id, nd);
    if !nsid.is_null() {
        unsafe {
            if crate::criu::pstree::pid_rst_prio(pid as u32, (*nsid).ns_pid as u32) {
                (*nsid).ns_pid = pid;
            }
        }
        return 0;
    }

    let root_idx = root_item_idx();
    let ns_type = if item_idx == root_idx {
        NsType::Root
    } else {
        NsType::Other
    };

    let nsid = rst_new_ns_id(id, pid, nd, ns_type);
    if nsid.is_null() {
        return -1;
    }

    0
}

pub fn switch_ns_by_fd(nsfd: RawFd, nd: &NsDesc, save_current: bool) -> Result<Option<RawFd>, i32> {
    use std::ffi::CString;

    let mut old_ns: RawFd = -1;

    if save_current {
        let path = format!("/proc/self/ns/{}", nd.name);
        let c_path = CString::new(path).map_err(|_| -1)?;
        old_ns = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
        if old_ns < 0 {
            return Err(-1);
        }
    }

    let ret = unsafe { libc::setns(nsfd, nd.cflag as i32) };
    if ret < 0 {
        log::error!("Can't setns {}/{}", nsfd, nd.name);
        if old_ns >= 0 {
            unsafe { libc::close(old_ns) };
        }
        return Err(-1);
    }

    if save_current {
        Ok(Some(old_ns))
    } else {
        Ok(None)
    }
}

pub fn switch_ns(pid: libc::pid_t, nd: &NsDesc, save_current: bool) -> Result<Option<RawFd>, i32> {
    use std::ffi::CString;

    let path = format!("/proc/{}/ns/{}", pid, nd.name);
    let c_path = CString::new(path).map_err(|_| -1)?;

    let nsfd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY) };
    if nsfd < 0 {
        return Err(-1);
    }

    let result = switch_ns_by_fd(nsfd, nd, save_current);

    unsafe { libc::close(nsfd) };

    result
}

pub fn read_pid_ns_img(dfd: RawFd) -> i32 {
    let guard = get_ns_ids().lock().unwrap();
    let mut nsid = guard.0;

    while !nsid.is_null() {
        unsafe {
            if (*nsid).nd.cflag != ns_desc::PID.cflag {
                nsid = (*nsid).next;
                continue;
            }

            let id = (*nsid).id;
            let path = format!("pidns-{}", id);

            let mut img = match open_image(dfd, CrFdType::Pidns, &path) {
                Ok(img) => img,
                Err(_) => return -1,
            };

            let result: Result<Option<PidnsEntry>, _> = pb_read_one_eof(&mut img);
            close_image(&mut img);

            match result {
                Ok(Some(e)) => {
                    (*nsid).ext_key = e.ext_key;
                }
                Ok(None) => {
                    // EOF, no entry - that's fine
                }
                Err(e) => {
                    log::error!("Can not read pidns object: {}", e);
                    return -1;
                }
            }

            nsid = (*nsid).next;
        }
    }

    0
}

// Usernsd constants
pub const UNS_ASYNC: i32 = 0x1;
pub const UNS_FDOUT: i32 = 0x2;
pub const MAX_UNSFD_MSG_SIZE: usize = 8192;

/// Function type for usernsd calls
/// Arguments: (arg buffer, fd, pid) -> result
pub type UnsCallFn = fn(*mut libc::c_void, RawFd, libc::pid_t) -> i32;

/// Message structure for usernsd communication
#[repr(C)]
pub struct UnscMsg {
    pub h: libc::msghdr,
    /*
     * 0th is the call address
     * 1st is the flags
     * 2nd is the optional (NULL in response) arguments
     */
    pub iov: [libc::iovec; 3],
    pub c: [u8; Self::CMSG_SPACE],
}

impl UnscMsg {
    // CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))
    const CMSG_SPACE: usize = unsafe {
        libc::CMSG_SPACE(std::mem::size_of::<libc::ucred>() as u32) as usize
            + libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) as usize
    };
}

impl Default for UnscMsg {
    fn default() -> Self {
        Self {
            h: unsafe { std::mem::zeroed() },
            iov: [libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; 3],
            c: [0u8; Self::CMSG_SPACE],
        }
    }
}

pub fn unsc_msg_init(
    m: &mut UnscMsg,
    call: *mut UnsCallFn,
    flags: *mut i32,
    arg: *mut libc::c_void,
    asize: usize,
    fd: RawFd,
    pid: Option<libc::pid_t>,
) {
    m.h.msg_iov = m.iov.as_mut_ptr();
    m.h.msg_iovlen = 2;

    m.iov[0].iov_base = call as *mut libc::c_void;
    m.iov[0].iov_len = std::mem::size_of::<UnsCallFn>();
    m.iov[1].iov_base = flags as *mut libc::c_void;
    m.iov[1].iov_len = std::mem::size_of::<i32>();

    if !arg.is_null() {
        m.iov[2].iov_base = arg;
        m.iov[2].iov_len = asize;
        m.h.msg_iovlen = 3;
    }

    m.h.msg_name = std::ptr::null_mut();
    m.h.msg_namelen = 0;
    m.h.msg_flags = 0;

    m.h.msg_control = m.c.as_mut_ptr() as *mut libc::c_void;
    m.c.fill(0);
    m.h.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::ucred>() as u32) } as usize;

    let ch = unsafe { libc::CMSG_FIRSTHDR(&m.h) };
    if !ch.is_null() {
        unsafe {
            (*ch).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as u32) as usize;
            (*ch).cmsg_level = libc::SOL_SOCKET;
            (*ch).cmsg_type = libc::SCM_CREDENTIALS;

            let ucred = libc::CMSG_DATA(ch) as *mut libc::ucred;
            (*ucred).pid = pid.unwrap_or_else(|| libc::getpid());
            (*ucred).uid = libc::getuid();
            (*ucred).gid = libc::getgid();
        }
    }

    if fd >= 0 {
        m.h.msg_controllen +=
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
        let ch2 = unsafe { libc::CMSG_NXTHDR(&m.h, ch) };
        if !ch2.is_null() {
            unsafe {
                (*ch2).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
                (*ch2).cmsg_level = libc::SOL_SOCKET;
                (*ch2).cmsg_type = libc::SCM_RIGHTS;
                *(libc::CMSG_DATA(ch2) as *mut i32) = fd;
            }
        }
    }
}

pub fn unsc_msg_pid_fd(um: &UnscMsg, pid: Option<&mut libc::pid_t>, fd: &mut RawFd) {
    let ch = unsafe { libc::CMSG_FIRSTHDR(&um.h) };
    debug_assert!(!ch.is_null());
    debug_assert_eq!(
        unsafe { (*ch).cmsg_len },
        unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as u32) } as usize
    );
    debug_assert_eq!(unsafe { (*ch).cmsg_level }, libc::SOL_SOCKET);
    debug_assert_eq!(unsafe { (*ch).cmsg_type }, libc::SCM_CREDENTIALS);

    if let Some(pid_out) = pid {
        let ucred = unsafe { libc::CMSG_DATA(ch) as *const libc::ucred };
        *pid_out = unsafe { (*ucred).pid };
    }

    let ch2 = unsafe { libc::CMSG_NXTHDR(&um.h, ch) };

    if !ch2.is_null()
        && unsafe { (*ch2).cmsg_len }
            == unsafe { libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) } as usize
    {
        debug_assert_eq!(unsafe { (*ch2).cmsg_level }, libc::SOL_SOCKET);
        debug_assert_eq!(unsafe { (*ch2).cmsg_type }, libc::SCM_RIGHTS);
        *fd = unsafe { *(libc::CMSG_DATA(ch2) as *const i32) };
    } else {
        *fd = -1;
    }
}

// Global usernsd pid
static USERNSD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

fn get_usernsd_pid() -> libc::pid_t {
    USERNSD_PID.load(std::sync::atomic::Ordering::SeqCst)
}

fn set_usernsd_pid(pid: libc::pid_t) {
    USERNSD_PID.store(pid, std::sync::atomic::Ordering::SeqCst);
}

/*
 * Seqpacket to
 *
 * a) Help daemon distinguish individual requests from
 *    each other easily. Stream socket require manual
 *    messages boundaries.
 *
 * b) Make callers note the daemon death by seeing the
 *    disconnected socket. In case of dgram socket
 *    callers would just get stuck in receiving the
 *    response.
 */
pub fn start_unix_cred_daemon(pid: &mut libc::pid_t, daemon_func: fn(RawFd) -> i32) -> RawFd {
    let mut sk: [RawFd; 2] = [-1, -1];
    let one: i32 = 1;

    if unsafe { libc::socketpair(libc::PF_UNIX, libc::SOCK_SEQPACKET, 0, sk.as_mut_ptr()) } != 0 {
        log::error!("Can't make usernsd socket");
        return -1;
    }

    if unsafe {
        libc::setsockopt(
            sk[0],
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            &one as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    } < 0
    {
        log::error!("failed to setsockopt");
        unsafe {
            libc::close(sk[0]);
            libc::close(sk[1]);
        }
        return -1;
    }

    if unsafe {
        libc::setsockopt(
            sk[1],
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            &one as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    } < 0
    {
        log::error!("failed to setsockopt");
        unsafe {
            libc::close(sk[0]);
            libc::close(sk[1]);
        }
        return -1;
    }

    *pid = unsafe { libc::fork() };
    if *pid < 0 {
        log::error!("Can't fork unix daemon");
        unsafe {
            libc::close(sk[0]);
            libc::close(sk[1]);
        }
        return -1;
    }

    if *pid == 0 {
        unsafe { libc::close(sk[0]) };
        let ret = daemon_func(sk[1]);
        std::process::exit(ret);
    }

    unsafe { libc::close(sk[1]) };

    sk[0]
}

fn usernsd(sk: RawFd) -> i32 {
    log::info!("uns: Daemon started");

    loop {
        let mut um = UnscMsg::default();
        let mut msg = [0u8; MAX_UNSFD_MSG_SIZE];
        let mut call: UnsCallFn = |_, _, _| 0;
        let mut flags: i32 = 0;

        unsc_msg_init(
            &mut um,
            &mut call as *mut UnsCallFn,
            &mut flags,
            msg.as_mut_ptr() as *mut libc::c_void,
            msg.len(),
            0,
            None,
        );

        let ret = unsafe { libc::recvmsg(sk, &mut um.h, 0) };
        if ret <= 0 {
            log::error!("uns: recv req error");
            return -1;
        }

        let mut pid: libc::pid_t = 0;
        let mut fd: RawFd = -1;
        unsc_msg_pid_fd(&um, Some(&mut pid), &mut fd);
        log::debug!(
            "uns: daemon calls {:p} ({}, {}, {:x})",
            call as *const (),
            pid,
            fd,
            flags
        );

        /*
         * Caller has sent us bare address of the routine it
         * wants to call. Since the caller is fork()-ed from the
         * same process as the daemon is, the latter has exactly
         * the same code at exactly the same address as the
         * former guy has. So go ahead and just call one!
         */
        let ret = call(msg.as_mut_ptr() as *mut libc::c_void, fd, pid);

        if fd >= 0 {
            unsafe { libc::close(fd) };
        }

        if (flags & UNS_ASYNC) != 0 {
            /*
             * Async call failed and the called doesn't know
             * about it. Exit now and let the stop_usernsd()
             * check the exit code and abort the restoration.
             *
             * We'd get there either by the end of restore or
             * from the next userns_call() due to failed
             * sendmsg() in there.
             */
            if ret < 0 {
                log::error!("uns: Async call failed. Exiting");
                return -1;
            }

            continue;
        }

        let resp_fd = if (flags & UNS_FDOUT) != 0 { ret } else { -1 };

        let mut resp_ret = ret;
        unsc_msg_init(
            &mut um,
            &mut call as *mut UnsCallFn,
            &mut resp_ret,
            std::ptr::null_mut(),
            0,
            resp_fd,
            None,
        );

        if unsafe { libc::sendmsg(sk, &um.h, 0) } <= 0 {
            log::error!("uns: send resp error");
            return -1;
        }

        if resp_fd >= 0 {
            unsafe { libc::close(resp_fd) };
        }
    }
}

pub fn userns_call(
    call: UnsCallFn,
    flags: i32,
    arg: *mut libc::c_void,
    arg_size: usize,
    fd: RawFd,
    sfd_state: &crate::criu::servicefd::ServiceFdState,
) -> i32 {
    let is_async = (flags & UNS_ASYNC) != 0;

    if arg_size > MAX_UNSFD_MSG_SIZE {
        log::error!("uns: message size exceeded");
        return -1;
    }

    let usernsd_pid = get_usernsd_pid();
    if usernsd_pid == 0 {
        return call(arg, fd, unsafe { libc::getpid() });
    }

    let sk = sfd_state.get_service_fd(crate::criu::servicefd::SfdType::UsernsdSk);
    if sk < 0 {
        log::error!("Cannot get USERNSD_SK fd");
        return -1;
    }
    log::debug!("uns: calling {:p} ({}, {:x})", call as *const (), fd, flags);

    if !is_async {
        /*
         * Why don't we lock for async requests? Because
         * they just put the request in the daemon's
         * queue and do not wait for the response. Thus
         * when daemon response there's only one client
         * waiting for it in recvmsg below, so he
         * responses to proper caller.
         */
        crate::criu::task_entries::task_entries().userns_sync_lock.lock();
    } else {
        /*
         * If we want the callback to give us and FD then
         * we should NOT do the asynchronous call.
         */
        debug_assert!((flags & UNS_FDOUT) == 0);
    }

    // Send the request
    let mut um = UnscMsg::default();
    let mut call_ptr = call;
    let mut flags_copy = flags;
    unsc_msg_init(
        &mut um,
        &mut call_ptr as *mut UnsCallFn,
        &mut flags_copy,
        arg,
        arg_size,
        fd,
        None,
    );

    let ret = unsafe { libc::sendmsg(sk, &um.h, 0) };
    if ret <= 0 {
        log::error!("uns: send req error");
        if !is_async {
            crate::criu::task_entries::task_entries().userns_sync_lock.unlock();
        }
        return -1;
    }

    if is_async {
        return 0;
    }

    // Get the response back
    let mut resp_call: UnsCallFn = |_, _, _| 0;
    let mut res: i32 = 0;
    unsc_msg_init(
        &mut um,
        &mut resp_call as *mut UnsCallFn,
        &mut res,
        std::ptr::null_mut(),
        0,
        0,
        None,
    );

    let ret = unsafe { libc::recvmsg(sk, &mut um.h, 0) };
    if ret <= 0 {
        log::error!("uns: recv resp error");
        crate::criu::task_entries::task_entries().userns_sync_lock.unlock();
        return -1;
    }

    // Decode the result and return
    let result = if (flags & UNS_FDOUT) != 0 {
        let mut fd_out: RawFd = -1;
        unsc_msg_pid_fd(&um, None, &mut fd_out);
        fd_out
    } else {
        res
    };

    crate::criu::task_entries::task_entries().userns_sync_lock.unlock();

    result
}

fn exit_usernsd(arg: *mut libc::c_void, _fd: RawFd, _pid: libc::pid_t) -> i32 {
    let code = unsafe { *(arg as *const i32) };
    log::info!("uns: `- daemon exits w/ {}", code);
    std::process::exit(code);
}

pub fn start_usernsd(sfd_state: &mut crate::criu::servicefd::ServiceFdState) -> i32 {
    if (root_ns_mask() & libc::CLONE_NEWUSER as u64) == 0 {
        return 0;
    }

    let mut pid: libc::pid_t = 0;
    let sk = start_unix_cred_daemon(&mut pid, usernsd);
    if sk < 0 {
        log::error!("failed to start usernsd");
        return -1;
    }

    set_usernsd_pid(pid);

    if sfd_state.install_service_fd(crate::criu::servicefd::SfdType::UsernsdSk, sk) < 0 {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        set_usernsd_pid(0);
        return -1;
    }

    0
}

pub fn stop_usernsd(sfd_state: &crate::criu::servicefd::ServiceFdState) -> i32 {
    let mut ret = 0;

    let usernsd_pid = get_usernsd_pid();
    if usernsd_pid != 0 {
        let mut status: i32 = -1;

        /*
         * Don't let the sigchld_handler() mess with us
         * calling waitpid() on the exited daemon. The
         * same is done in cr_system().
         */
        let mut blockmask: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut oldmask: libc::sigset_t = unsafe { std::mem::zeroed() };

        unsafe {
            libc::sigemptyset(&mut blockmask);
            libc::sigaddset(&mut blockmask, libc::SIGCHLD);
            libc::sigprocmask(libc::SIG_BLOCK, &blockmask, &mut oldmask);
        }

        /*
         * Send a message to make sure the daemon _has_
         * proceeded all its queue of asynchronous requests.
         *
         * All the restoring processes might have already
         * closed their USERNSD_SK descriptors, but daemon
         * still has its in connected state -- this is us
         * who hold the last reference on the peer.
         *
         * If daemon has exited "in advance" due to async
         * call or socket error, the userns_call() and the
         * waitpid() below would both fail and we'll see
         * bad exit status.
         */
        userns_call(
            exit_usernsd,
            UNS_ASYNC,
            &mut ret as *mut i32 as *mut libc::c_void,
            std::mem::size_of::<i32>(),
            -1,
            sfd_state,
        );

        unsafe { libc::waitpid(usernsd_pid, &mut status, 0) };

        if libc::WIFEXITED(status) {
            ret = libc::WEXITSTATUS(status);
        } else {
            ret = -1;
        }

        set_usernsd_pid(0);
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &oldmask, std::ptr::null_mut()) };

        if ret != 0 {
            log::error!("uns: daemon exited abnormally");
        } else {
            log::info!("uns: daemon stopped");
        }
    }

    ret
}

pub fn netns_keep_nsfd(sfd_state: &mut crate::criu::servicefd::ServiceFdState) -> i32 {
    if (root_ns_mask() & libc::CLONE_NEWNET as u64) == 0 {
        return 0;
    }

    /*
     * When restoring a net namespace we need to communicate
     * with the original (i.e. -- init) one. Thus, prepare for
     * that before we leave the existing namespaces.
     */
    let path = std::ffi::CString::new("/proc/self/ns/net").unwrap();
    let ns_fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if ns_fd < 0 {
        log::error!("Can't open /proc/self/ns/net");
        return -1;
    }

    let ret = sfd_state.install_service_fd(crate::criu::servicefd::SfdType::NsFdOff, ns_fd);
    if ret < 0 {
        log::error!("Can't install ns net reference");
    } else {
        log::info!("Saved netns fd for links restore");
    }

    if ret >= 0 { 0 } else { -1 }
}

pub fn prepare_namespace_before_tasks(
    sfd_state: &mut crate::criu::servicefd::ServiceFdState,
    mount_store: &mut crate::criu::mount::MountInfoStore,
    ns_ids: &mut [NsId],
    dfd: RawFd,
    externals: &[crate::criu::external::External],
) -> i32 {
    if start_usernsd(sfd_state) != 0 {
        return -1;
    }

    if netns_keep_nsfd(sfd_state) != 0 {
        stop_usernsd(sfd_state);
        return -1;
    }

    if crate::criu::mount::mntns_maybe_create_roots(root_ns_mask()).is_err() {
        stop_usernsd(sfd_state);
        return -1;
    }

    if crate::criu::mount::read_mnt_ns_img(mount_store, ns_ids, dfd, root_ns_mask(), externals)
        .is_err()
    {
        crate::criu::mount::cleanup_mnt_ns();
        stop_usernsd(sfd_state);
        return -1;
    }

    if read_net_ns_img(dfd) != 0 {
        crate::criu::mount::cleanup_mnt_ns();
        stop_usernsd(sfd_state);
        return -1;
    }

    if read_pid_ns_img(dfd) != 0 {
        crate::criu::mount::cleanup_mnt_ns();
        stop_usernsd(sfd_state);
        return -1;
    }

    0
}

pub fn read_net_ns_img(dfd: RawFd) -> i32 {
    use crate::criu::image::{close_image, open_image};
    use crate::criu::image_desc::CrFdType;
    use crate::criu::protobuf::pb_read_one_eof;
    use crate::proto::NetnsEntry;

    if (root_ns_mask() & libc::CLONE_NEWNET as u64) == 0 {
        return 0;
    }

    let guard = get_ns_ids().lock().unwrap();
    let mut nsid = guard.0;

    while !nsid.is_null() {
        unsafe {
            if (*nsid).nd.cflag != ns_desc::NET.cflag {
                nsid = (*nsid).next;
                continue;
            }

            let id = (*nsid).id;
            let path = format!("netns-{}", id);

            let mut img = match open_image(dfd, CrFdType::Netns, &path) {
                Ok(img) => img,
                Err(_) => return -1,
            };

            // Check if image is empty (backward compatibility)
            if img.is_empty() {
                close_image(&mut img);
                nsid = (*nsid).next;
                continue;
            }

            let result: Result<Option<NetnsEntry>, _> = pb_read_one_eof(&mut img);
            close_image(&mut img);

            match result {
                Ok(Some(e)) => {
                    // Store ext_key at NsId level
                    (*nsid).ext_key = e.ext_key.clone();
                    // Store the full netns entry in the net data
                    if let NsIdData::Net(ref mut net_data) = (*nsid).data {
                        net_data.netns = Some(e);
                    }
                }
                Ok(None) => {
                    // EOF, no entry - that's fine
                }
                Err(e) => {
                    log::error!("Can not read netns object: {}", e);
                    return -1;
                }
            }

            nsid = (*nsid).next;
        }
    }

    0
}

/// Prepare user namespace by writing uid/gid maps.
/// Maps to: prepare_userns (criu/namespaces.c:1574-1595)
pub fn prepare_userns(
    dfd: RawFd,
    user_ns_id: u32,
    pid_real: libc::pid_t,
) -> i32 {
    let path = format!("{}", user_ns_id);
    let mut img = match open_image(dfd, CrFdType::Userns, &path) {
        Ok(img) => img,
        Err(e) => {
            log::error!("Failed to open userns image: {}", e);
            return -1;
        }
    };

    let e: UsernsEntry = match pb_read_one(&mut img) {
        Ok(entry) => entry,
        Err(err) => {
            log::error!("Failed to read userns entry: {}", err);
            close_image(&mut img);
            return -1;
        }
    };
    close_image(&mut img);

    if write_id_map(pid_real, &e.uid_map, "uid_map") != 0 {
        return -1;
    }

    if write_id_map(pid_real, &e.gid_map, "gid_map") != 0 {
        return -1;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nsid_add() {
        let mut store = NsIdStore::new();
        assert!(store.is_empty());

        let ns = NsId::new(&ns_desc::PID, 1, 1234);
        let idx = store.nsid_add(ns);

        assert_eq!(idx, 0);
        assert_eq!(store.len(), 1);

        let ns_ref = store.get(idx).unwrap();
        assert_eq!(ns_ref.id, 1);
        assert_eq!(ns_ref.ns_pid, 1234);
        assert_eq!(ns_ref.nd.name, "pid");
        assert_eq!(ns_ref.nd.cflag, libc::CLONE_NEWPID as u32);
    }

    #[test]
    fn test_nsid_add_multiple() {
        let mut store = NsIdStore::new();

        let ns1 = NsId::new(&ns_desc::PID, 1, 100);
        let ns2 = NsId::new(&ns_desc::NET, 2, 200);
        let ns3 = NsId::new(&ns_desc::MNT, 3, 300);

        let idx1 = store.nsid_add(ns1);
        let idx2 = store.nsid_add(ns2);
        let idx3 = store.nsid_add(ns3);

        assert_eq!(store.len(), 3);
        assert_eq!(store.get(idx1).unwrap().nd.name, "pid");
        assert_eq!(store.get(idx2).unwrap().nd.name, "net");
        assert_eq!(store.get(idx3).unwrap().nd.name, "mnt");
    }

    #[test]
    fn test_ns_desc_constants() {
        assert_eq!(ns_desc::NET.cflag, libc::CLONE_NEWNET as u32);
        assert_eq!(ns_desc::PID.cflag, libc::CLONE_NEWPID as u32);
        assert_eq!(ns_desc::MNT.cflag, libc::CLONE_NEWNS as u32);
        assert_eq!(ns_desc::USER.cflag, libc::CLONE_NEWUSER as u32);
        assert_eq!(ns_desc::IPC.cflag, libc::CLONE_NEWIPC as u32);
        assert_eq!(ns_desc::UTS.cflag, libc::CLONE_NEWUTS as u32);
        assert_eq!(ns_desc::CGROUP.cflag, libc::CLONE_NEWCGROUP as u32);
    }

    #[test]
    fn test_switch_ns_by_fd_invalid_fd() {
        // Switching to an invalid fd should fail
        let result = switch_ns_by_fd(-1, &ns_desc::NET, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_switch_ns_by_fd_no_save() {
        // Invalid fd without save should return Err
        let result = switch_ns_by_fd(-1, &ns_desc::PID, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_lookup_ns_by_id() {
        let mut store = NsIdStore::new();

        let ns1 = NsId::new(&ns_desc::PID, 100, 1000);
        let ns2 = NsId::new(&ns_desc::NET, 200, 2000);

        store.nsid_add(ns1);
        store.nsid_add(ns2);

        // Find existing namespace
        let idx = store.lookup_ns_by_id(100, &ns_desc::PID);
        assert_eq!(idx, Some(0));

        let idx = store.lookup_ns_by_id(200, &ns_desc::NET);
        assert_eq!(idx, Some(1));

        // Different type with same ID should not match
        let idx = store.lookup_ns_by_id(100, &ns_desc::NET);
        assert_eq!(idx, None);

        // Non-existent ID should not match
        let idx = store.lookup_ns_by_id(999, &ns_desc::PID);
        assert_eq!(idx, None);
    }

    #[test]
    fn test_write_id_map_empty_extents() {
        // Writing empty extents to non-existent PID should fail at open
        let extents: Vec<crate::proto::UidGidExtent> = vec![];
        let result = write_id_map(999999, &extents, "uid_map");
        // Should fail because /proc/999999 doesn't exist
        assert_eq!(result, -1);
    }

    #[test]
    fn test_write_id_map_invalid_pid() {
        // Non-existent PID should fail to open
        let extents = vec![crate::proto::UidGidExtent {
            first: 0,
            lower_first: 1000,
            count: 1,
        }];
        let result = write_id_map(999999, &extents, "uid_map");
        assert_eq!(result, -1);
    }
}
