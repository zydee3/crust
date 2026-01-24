use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

use crate::criu::cr_restore::cr_restore_tasks;
use crate::criu::log::log_get_fd;
use crate::criu::options::opts;
use crate::criu::pstree::root_item_pid_real_try;

pub const CR_DEFAULT_SERVICE_ADDRESS: &str = "/var/run/criu_service.socket";

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CriuReqType {
    Empty = 0,
    Dump = 1,
    Restore = 2,
    Check = 3,
    PreDump = 4,
    PageServer = 5,
    Notify = 6,
    CpuinfoDump = 7,
    CpuinfoCheck = 8,
    FeatureCheck = 9,
    Version = 10,
    WaitPid = 11,
    PageServerChld = 12,
    SinglePreDump = 13,
}

#[derive(Debug, Clone, Default)]
pub struct RpcCriuOpts {
    pub images_dir_fd: i32,
    pub images_dir: Option<String>,
    pub pid: Option<i32>,
    pub leave_running: bool,
    pub ext_unix_sk: bool,
    pub tcp_established: bool,
    pub evasive_devices: bool,
    pub shell_job: bool,
    pub file_locks: bool,
    pub log_level: i32,
    pub log_file: Option<String>,
    pub root: Option<String>,
    pub parent_img: Option<String>,
    pub track_mem: bool,
    pub auto_dedup: bool,
    pub work_dir_fd: i32,
    pub link_remap: bool,
    pub cpu_cap: u32,
    pub force_irmap: bool,
    pub exec_cmd: Vec<String>,
    pub manage_cgroups: bool,
    pub rst_sibling: bool,
    pub auto_ext_mnt: bool,
    pub ext_sharing: bool,
    pub ext_masters: bool,
    pub ghost_limit: u32,
    pub empty_ns: u32,
    pub timeout: u32,
    pub tcp_skip_in_flight: bool,
    pub weak_sysctls: bool,
    pub lazy_pages: bool,
    pub status_fd: i32,
    pub orphan_pts_master: bool,
    pub config_file: Option<String>,
    pub tcp_close: bool,
    pub lsm_profile: Option<String>,
    pub cgroup_yard: Option<String>,
    pub lsm_mount_context: Option<String>,
    pub mntns_compat_mode: bool,
    pub skip_file_rwx_check: bool,
    pub unprivileged: bool,
    pub leave_stopped: bool,
    pub display_stats: bool,
    pub log_to_stderr: bool,
    pub restore_detach: bool,
}

#[derive(Debug, Clone)]
pub struct CriuReq {
    pub req_type: CriuReqType,
    pub opts: Option<RpcCriuOpts>,
    pub notify_success: bool,
    pub keep_open: bool,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct CriuRestoreResp {
    pub pid: i32,
}

#[derive(Debug, Clone)]
pub struct CriuResp {
    pub resp_type: CriuReqType,
    pub success: bool,
    pub restore: Option<CriuRestoreResp>,
    pub cr_errno: Option<i32>,
    pub cr_errmsg: Option<String>,
}

fn recv_criu_msg(sk: RawFd) -> io::Result<CriuReq> {
    let mut buf = vec![0u8; 65536];
    let len = unsafe { libc::recv(sk, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    if len == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed"));
    }

    buf.truncate(len as usize);

    Ok(CriuReq {
        req_type: CriuReqType::Restore,
        opts: Some(RpcCriuOpts {
            images_dir_fd: -1,
            ..Default::default()
        }),
        notify_success: false,
        keep_open: false,
        pid: None,
    })
}

fn send_criu_msg(sk: RawFd, msg: &CriuResp) -> io::Result<()> {
    let _ = (sk, msg);
    Ok(())
}

fn send_criu_restore_resp(sk: RawFd, success: bool, pid: i32) -> io::Result<()> {
    let resp = CriuResp {
        resp_type: CriuReqType::Restore,
        success,
        restore: if success {
            Some(CriuRestoreResp { pid })
        } else {
            None
        },
        cr_errno: None,
        cr_errmsg: None,
    };
    send_criu_msg(sk, &resp)
}

fn send_criu_err(sk: RawFd, msg: &str) {
    let resp = CriuResp {
        resp_type: CriuReqType::Empty,
        success: false,
        restore: None,
        cr_errno: Some(-1),
        cr_errmsg: Some(msg.to_string()),
    };
    let _ = send_criu_msg(sk, &resp);
}

fn setup_opts_from_req(_sk: RawFd, _req: &RpcCriuOpts) -> i32 {
    0
}

fn open_image_dir_for_restore(req: &RpcCriuOpts) -> RawFd {
    if req.images_dir_fd >= 0 {
        return req.images_dir_fd;
    }

    if let Some(ref dir) = req.images_dir {
        let c_dir = match CString::new(dir.as_str()) {
            Ok(c) => c,
            Err(_) => return -1,
        };
        let fd = unsafe { libc::open(c_dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        return fd;
    }

    let fd = unsafe { libc::open(b".\0".as_ptr() as *const i8, libc::O_RDONLY | libc::O_DIRECTORY) };
    fd
}

pub fn restore_using_req(sk: RawFd, req: &RpcCriuOpts) -> i32 {
    let mut success = false;

    /*
     * We can't restore processes under arbitrary task yet.
     * Thus for now we force the detached restore under the
     * cr service task.
     */

    if setup_opts_from_req(sk, req) != 0 {
        let pid = root_item_pid_real_try().unwrap_or(-1);
        if send_criu_restore_resp(sk, success, pid).is_err() {
            log::error!("Can't send response");
        }
        return 1;
    }

    let dfd = open_image_dir_for_restore(req);
    if dfd < 0 {
        log::error!("Can't open images directory");
        if send_criu_restore_resp(sk, false, -1).is_err() {
            log::error!("Can't send response");
        }
        return 1;
    }

    if cr_restore_tasks(dfd) != 0 {
        let pid = root_item_pid_real_try().unwrap_or(-1);
        if send_criu_restore_resp(sk, success, pid).is_err() {
            log::error!("Can't send response");
        }
        if req.images_dir_fd < 0 {
            unsafe { libc::close(dfd) };
        }
        return 1;
    }

    success = true;
    let pid = root_item_pid_real_try().unwrap_or(-1);

    if send_criu_restore_resp(sk, success, pid).is_err() {
        log::error!("Can't send response");
        success = false;
    }

    if req.images_dir_fd < 0 {
        unsafe { libc::close(dfd) };
    }

    if success && !opts().exec_cmd.is_empty() {
        let logfd = log_get_fd();
        if unsafe { libc::dup2(logfd, libc::STDOUT_FILENO) } == -1
            || unsafe { libc::dup2(logfd, libc::STDERR_FILENO) } == -1
        {
            log::error!("Failed to redirect stdout and stderr to the logfile");
            return 1;
        }

        unsafe { libc::close(sk) };

        let exec_cmd = &opts().exec_cmd;
        let c_args: Vec<CString> = exec_cmd
            .iter()
            .filter_map(|s| CString::new(s.as_str()).ok())
            .collect();
        let c_ptrs: Vec<*const i8> = c_args
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        unsafe {
            libc::execvp(c_ptrs[0], c_ptrs.as_ptr() as *const *const i8);
        }
        log::error!("Failed to exec cmd {}", exec_cmd[0]);
        success = false;
    }

    if success { 0 } else { 1 }
}

fn chk_keepopen_req(_msg: &CriuReq) -> i32 {
    0
}

pub fn cr_service_work(sk: RawFd) -> i32 {
    let mut ret: i32 = -1;

    loop {
        let msg = match recv_criu_msg(sk) {
            Ok(m) => m,
            Err(e) => {
                log::error!("Can't recv request: {}", e);
                return ret;
            }
        };

        if chk_keepopen_req(&msg) != 0 {
            return ret;
        }

        ret = match msg.req_type {
            CriuReqType::Restore => {
                if let Some(ref req_opts) = msg.opts {
                    restore_using_req(sk, req_opts)
                } else {
                    send_criu_err(sk, "Missing opts");
                    -1
                }
            }
            CriuReqType::Dump => {
                send_criu_err(sk, "Dump not implemented");
                -1
            }
            CriuReqType::Check => {
                send_criu_err(sk, "Check not implemented");
                -1
            }
            CriuReqType::PreDump => {
                send_criu_err(sk, "PreDump not implemented");
                -1
            }
            CriuReqType::PageServer | CriuReqType::PageServerChld => {
                send_criu_err(sk, "PageServer not implemented");
                -1
            }
            CriuReqType::WaitPid => {
                send_criu_err(sk, "WaitPid not implemented");
                -1
            }
            CriuReqType::CpuinfoDump | CriuReqType::CpuinfoCheck => {
                send_criu_err(sk, "Cpuinfo not implemented");
                -1
            }
            CriuReqType::FeatureCheck => {
                send_criu_err(sk, "FeatureCheck not implemented");
                -1
            }
            CriuReqType::Version => {
                send_criu_err(sk, "Version not implemented");
                -1
            }
            CriuReqType::SinglePreDump => {
                send_criu_err(sk, "SinglePreDump not implemented");
                -1
            }
            _ => {
                send_criu_err(sk, "Invalid req");
                -1
            }
        };

        if ret == 0 && msg.keep_open {
            continue;
        }
        break;
    }

    ret
}

pub fn cr_service(daemon_mode: bool) -> i32 {
    let server_fd: RawFd;

    server_fd = unsafe { libc::socket(libc::AF_LOCAL, libc::SOCK_SEQPACKET, 0) };
    if server_fd == -1 {
        log::error!("Can't initialize service socket");
        return -1;
    }

    let mut server_addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    server_addr.sun_family = libc::AF_LOCAL as u16;

    let addr = opts()
        .addr
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or(CR_DEFAULT_SERVICE_ADDRESS);

    let addr_bytes = addr.as_bytes();
    let copy_len = std::cmp::min(addr_bytes.len(), server_addr.sun_path.len() - 1);
    for (i, &byte) in addr_bytes[..copy_len].iter().enumerate() {
        server_addr.sun_path[i] = byte as i8;
    }

    unsafe {
        libc::unlink(server_addr.sun_path.as_ptr());
    }

    let bind_result = unsafe {
        libc::bind(
            server_fd,
            &server_addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as u32,
        )
    };
    if bind_result == -1 {
        log::error!("Can't bind to {}", addr);
        unsafe { libc::close(server_fd) };
        return -1;
    }

    if unsafe { libc::listen(server_fd, 16) } == -1 {
        log::error!("Can't listen on service socket");
        unsafe { libc::close(server_fd) };
        return -1;
    }

    if daemon_mode {
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            log::error!("Can't fork");
            unsafe { libc::close(server_fd) };
            return -1;
        }
        if pid > 0 {
            return 0;
        }
        unsafe { libc::setsid() };
    }

    log::info!("Service started on {}", addr);

    loop {
        let mut client_addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let mut client_addr_len: libc::socklen_t =
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;

        let client_fd = unsafe {
            libc::accept(
                server_fd,
                &mut client_addr as *mut libc::sockaddr_un as *mut libc::sockaddr,
                &mut client_addr_len,
            )
        };

        if client_fd == -1 {
            if unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            log::error!("Accept failed");
            break;
        }

        let child_pid = unsafe { libc::fork() };
        if child_pid < 0 {
            log::error!("Can't fork");
            unsafe { libc::close(client_fd) };
            continue;
        }

        if child_pid == 0 {
            unsafe { libc::close(server_fd) };
            let ret = cr_service_work(client_fd);
            unsafe { libc::close(client_fd) };
            unsafe { libc::_exit(ret) };
        }

        unsafe { libc::close(client_fd) };
    }

    unsafe { libc::close(server_fd) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criu_req_type_values() {
        assert_eq!(CriuReqType::Empty as i32, 0);
        assert_eq!(CriuReqType::Dump as i32, 1);
        assert_eq!(CriuReqType::Restore as i32, 2);
        assert_eq!(CriuReqType::Check as i32, 3);
    }

    #[test]
    fn test_default_service_address() {
        assert_eq!(CR_DEFAULT_SERVICE_ADDRESS, "/var/run/criu_service.socket");
    }

    #[test]
    fn test_rpc_criu_opts_default() {
        let opts = RpcCriuOpts::default();
        assert_eq!(opts.images_dir_fd, 0); // i32 default is 0
        assert!(opts.images_dir.is_none());
    }
}
