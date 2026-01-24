pub mod sk_flags {
    pub const FREE_RQ: u32 = 0x1; // recv_queue was allocated
    pub const FREE_SQ: u32 = 0x2; // send_queue was allocated
    pub const FREE_SA: u32 = 0x4; // src_addr was allocated
    pub const FREE_DA: u32 = 0x8; // dst_addr was allocated
}

#[derive(Clone)]
pub enum LibsoccrAddr {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

impl LibsoccrAddr {
    pub fn as_sockaddr(&self) -> &libc::sockaddr {
        match self {
            LibsoccrAddr::V4(v4) => unsafe {
                &*(v4 as *const libc::sockaddr_in as *const libc::sockaddr)
            },
            LibsoccrAddr::V6(v6) => unsafe {
                &*(v6 as *const libc::sockaddr_in6 as *const libc::sockaddr)
            },
        }
    }
}

#[derive(Clone, Default)]
pub struct LibsoccrSkData {
    pub state: u32,
    pub inq_len: u32,
    pub inq_seq: u32,
    pub outq_len: u32,
    pub outq_seq: u32,
    pub unsq_len: u32,
    pub opt_mask: u32,
    pub mss_clamp: u32,
    pub snd_wscale: u32,
    pub rcv_wscale: u32,
    pub timestamp: u32,
    pub flags: u32,
    pub snd_wl1: u32,
    pub snd_wnd: u32,
    pub max_window: u32,
    pub rcv_wnd: u32,
    pub rcv_wup: u32,
}

pub struct LibsoccrSk {
    pub fd: i32,
    pub flags: u32,
    pub recv_queue: Option<Vec<u8>>,
    pub send_queue: Option<Vec<u8>>,
    pub src_addr: Option<Box<LibsoccrAddr>>,
    pub dst_addr: Option<Box<LibsoccrAddr>>,
}

impl LibsoccrSk {
    pub fn new(fd: i32) -> Self {
        Self {
            fd,
            flags: 0,
            recv_queue: None,
            send_queue: None,
            src_addr: None,
            dst_addr: None,
        }
    }
}

pub fn libsoccr_release(sk: LibsoccrSk) {
    drop(sk);
}

pub fn tcp_repair_off(fd: i32) -> i32 {
    let aux: i32 = 0;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_TCP,
            libc::TCP_REPAIR,
            &aux as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        // In CRIU this logs an error, but we just return the error code
        return ret;
    }
    ret
}

pub fn libsoccr_resume(sk: LibsoccrSk) {
    tcp_repair_off(sk.fd);
    libsoccr_release(sk);
}

impl Drop for LibsoccrSk {
    fn drop(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_libsoccr_sk_new() {
        let sk = LibsoccrSk::new(42);
        assert_eq!(sk.fd, 42);
        assert_eq!(sk.flags, 0);
        assert!(sk.recv_queue.is_none());
        assert!(sk.send_queue.is_none());
    }

    #[test]
    fn test_libsoccr_release() {
        let mut sk = LibsoccrSk::new(42);
        sk.recv_queue = Some(vec![1, 2, 3]);
        sk.send_queue = Some(vec![4, 5, 6]);
        sk.flags = sk_flags::FREE_RQ | sk_flags::FREE_SQ;

        // This should not panic - memory is properly released
        libsoccr_release(sk);
    }
}
