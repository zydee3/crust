use crate::criu::namespaces::NsId;
use crate::proto::InetSkEntry;

pub struct SocketDesc {
    pub family: u32,
    pub ino: u32,
    pub next: Option<Box<SocketDesc>>,
    pub sk_ns: Option<*mut NsId>,
    pub already_dumped: i32,
}

// SAFETY: SocketDesc is only used in single-threaded CRIU restore context.
// The raw pointers (sk_ns) are not dereferenced across thread boundaries.
unsafe impl Send for SocketDesc {}
unsafe impl Sync for SocketDesc {}

pub struct InetSkDesc {
    pub sd: SocketDesc,
    pub typ: u32,
    pub src_port: u32,
    pub dst_port: u32,
    pub state: u32,
    pub rqlen: u32,
    pub wqlen: u32,
    pub uwqlen: u32,
    pub src_addr: [u32; 4],
    pub dst_addr: [u32; 4],
    pub shutdown: u16,
    pub cork: bool,
    pub rfd: i32,
    pub cpt_reuseaddr: i32,
    pub priv_data: Option<*mut std::ffi::c_void>,
}

// SAFETY: InetSkDesc is only used in single-threaded CRIU restore context.
// The raw pointers are not dereferenced across thread boundaries.
unsafe impl Send for InetSkDesc {}
unsafe impl Sync for InetSkDesc {}

pub struct InetSkInfo {
    pub ie: InetSkEntry,
    pub sk_fd: i32,
}

impl InetSkInfo {
    pub fn new(ie: InetSkEntry, sk_fd: i32) -> Self {
        Self { ie, sk_fd }
    }
}

pub fn sk_setbufs(sk: i32, sndbuf: u32, rcvbuf: u32, unprivileged: bool) -> i32 {
    let sndbuf_val = sndbuf;
    let rcvbuf_val = rcvbuf;

    let force_ret = unsafe {
        let snd_ret = libc::setsockopt(
            sk,
            libc::SOL_SOCKET,
            libc::SO_SNDBUFFORCE,
            &sndbuf_val as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
        let rcv_ret = libc::setsockopt(
            sk,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &rcvbuf_val as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
        snd_ret != 0 || rcv_ret != 0
    };

    if force_ret {
        if unprivileged {
            log::info!(
                "Unable to set SO_SNDBUFFORCE/SO_RCVBUFFORCE, falling back to SO_SNDBUF/SO_RCVBUF"
            );
            let fallback_ret = unsafe {
                let snd_ret = libc::setsockopt(
                    sk,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &sndbuf_val as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                );
                let rcv_ret = libc::setsockopt(
                    sk,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &rcvbuf_val as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                );
                snd_ret != 0 || rcv_ret != 0
            };

            if fallback_ret {
                log::error!("Unable to set socket SO_SNDBUF/SO_RCVBUF");
                return -1;
            }
        } else {
            log::error!("Unable to set socket SO_SNDBUFFORCE/SO_RCVBUFFORCE");
            return -1;
        }
    }

    0
}

pub fn do_restore_opt(sk: i32, level: i32, name: i32, val: *const libc::c_void, len: libc::socklen_t) -> i32 {
    let ret = unsafe { libc::setsockopt(sk, level, name, val, len) };
    if ret < 0 {
        log::error!("Can't set {}:{} (len {})", level, name, len);
        return -1;
    }
    0
}

#[inline]
pub fn restore_opt<T>(sk: i32, level: i32, name: i32, val: &T) -> i32 {
    do_restore_opt(
        sk,
        level,
        name,
        val as *const T as *const libc::c_void,
        std::mem::size_of::<T>() as libc::socklen_t,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sk_setbufs_invalid_socket() {
        // Invalid socket should fail
        let result = sk_setbufs(-1, 65536, 65536, false);
        assert_eq!(result, -1);
    }

    #[test]
    fn test_sk_setbufs_valid_socket_unprivileged() {
        // Create a socket and try to set buffers in unprivileged mode
        let sk = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if sk < 0 {
            // Skip if socket creation fails
            return;
        }

        // Should succeed with fallback to non-force options
        let result = sk_setbufs(sk, 65536, 65536, true);
        assert_eq!(result, 0);

        unsafe { libc::close(sk) };
    }

    #[test]
    fn test_restore_opt_invalid_socket() {
        let val: i32 = 1;
        let result = restore_opt(-1, libc::SOL_SOCKET, libc::SO_REUSEADDR, &val);
        assert_eq!(result, -1);
    }

    #[test]
    fn test_restore_opt_valid_socket() {
        let sk = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if sk < 0 {
            return;
        }

        let val: i32 = 1;
        let result = restore_opt(sk, libc::SOL_SOCKET, libc::SO_REUSEADDR, &val);
        assert_eq!(result, 0);

        unsafe { libc::close(sk) };
    }
}
