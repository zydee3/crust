use std::mem;
use std::ptr;

pub const CR_SCM_MAX_FD: usize = 252;
pub const CR_SCM_MSG_SIZE: usize = 1024;

#[repr(C)]
pub struct ScmFdset {
    pub hdr: libc::msghdr,
    pub iov: libc::iovec,
    pub msg_buf: [u8; CR_SCM_MSG_SIZE],
}

impl ScmFdset {
    pub fn new() -> Self {
        Self {
            hdr: unsafe { mem::zeroed() },
            iov: libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            },
            msg_buf: [0u8; CR_SCM_MSG_SIZE],
        }
    }
}

impl Default for ScmFdset {
    fn default() -> Self {
        Self::new()
    }
}

pub fn scm_fdset_init(
    fdset: &mut ScmFdset,
    saddr: Option<&mut libc::sockaddr_un>,
    saddr_len: libc::socklen_t,
) -> *mut i32 {
    // Static assertion equivalent: ensure msg_buf is large enough
    // CMSG_SPACE(sizeof(int) * CR_SCM_MAX_FD) should fit in msg_buf
    const _: () = assert!(
        CR_SCM_MSG_SIZE >= unsafe { libc::CMSG_SPACE((mem::size_of::<i32>() * CR_SCM_MAX_FD) as u32) as usize }
    );

    // Initialize with sentinel value (matches CRIU's 0xdeadbeef)
    fdset.iov.iov_base = 0xdeadbeef_usize as *mut libc::c_void;

    fdset.hdr.msg_iov = &mut fdset.iov as *mut libc::iovec;
    fdset.hdr.msg_iovlen = 1;

    if let Some(addr) = saddr {
        fdset.hdr.msg_name = addr as *mut libc::sockaddr_un as *mut libc::c_void;
        fdset.hdr.msg_namelen = saddr_len;
    } else {
        fdset.hdr.msg_name = ptr::null_mut();
        fdset.hdr.msg_namelen = 0;
    }

    fdset.hdr.msg_control = fdset.msg_buf.as_mut_ptr() as *mut libc::c_void;
    fdset.hdr.msg_controllen = unsafe {
        libc::CMSG_LEN((mem::size_of::<i32>() * CR_SCM_MAX_FD) as u32) as usize
    };

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&fdset.hdr) };
    unsafe {
        (*cmsg).cmsg_len = fdset.hdr.msg_controllen;
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;

        libc::CMSG_DATA(cmsg) as *mut i32
    }
}

pub fn scm_fdset_init_chunk(
    fdset: &mut ScmFdset,
    nr_fds: usize,
    data: Option<&mut [u8]>,
    ch_size: usize,
) {
    static mut DUMMY: u8 = 0;

    fdset.hdr.msg_controllen = unsafe {
        libc::CMSG_LEN((mem::size_of::<i32>() * nr_fds) as u32) as usize
    };

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&fdset.hdr) };
    unsafe {
        (*cmsg).cmsg_len = fdset.hdr.msg_controllen;
    }

    if let Some(buf) = data {
        fdset.iov.iov_base = buf.as_mut_ptr() as *mut libc::c_void;
        fdset.iov.iov_len = nr_fds * ch_size;
    } else {
        fdset.iov.iov_base = &raw mut DUMMY as *mut libc::c_void;
        fdset.iov.iov_len = 1;
    }
}

pub fn send_fds(
    sock: i32,
    saddr: Option<&mut libc::sockaddr_un>,
    saddr_len: libc::socklen_t,
    fds: &[i32],
    data: Option<&mut [u8]>,
    ch_size: usize,
) -> Result<(), i32> {
    let mut fdset = ScmFdset::new();
    let cmsg_data = scm_fdset_init(&mut fdset, saddr, saddr_len);

    let nr_fds = fds.len();
    let mut i = 0usize;

    // Get raw pointer and length for data if present
    let (data_ptr, data_len) = match &data {
        Some(d) => (d.as_ptr() as *mut u8, d.len()),
        None => (ptr::null_mut(), 0),
    };
    let mut data_offset = 0usize;

    while i < nr_fds {
        let min_fd = std::cmp::min(CR_SCM_MAX_FD, nr_fds - i);

        // Prepare data slice for this chunk if present
        let chunk_data = if !data_ptr.is_null() {
            let end = data_offset + min_fd * ch_size;
            if end <= data_len {
                Some(unsafe {
                    std::slice::from_raw_parts_mut(data_ptr.add(data_offset), min_fd * ch_size)
                })
            } else {
                None
            }
        } else {
            None
        };

        scm_fdset_init_chunk(&mut fdset, min_fd, chunk_data, ch_size);

        // Copy file descriptors into control message
        unsafe {
            ptr::copy_nonoverlapping(fds.as_ptr().add(i), cmsg_data, min_fd);
        }

        let ret = unsafe { libc::sendmsg(sock, &fdset.hdr, 0) };
        if ret <= 0 {
            if ret == 0 {
                return Err(-1);
            }
            return Err(unsafe { *libc::__errno_location() });
        }

        if !data_ptr.is_null() {
            data_offset += min_fd * ch_size;
        }

        i += min_fd;
    }

    Ok(())
}

#[inline]
pub fn send_fd(
    sock: i32,
    saddr: Option<&mut libc::sockaddr_un>,
    saddr_len: libc::socklen_t,
    fd: i32,
) -> Result<(), i32> {
    send_fds(sock, saddr, saddr_len, &[fd], None, 0)
}

pub fn recv_fds(
    sock: i32,
    fds: &mut [i32],
    data: Option<&mut [u8]>,
    ch_size: usize,
    flags: i32,
) -> i32 {
    let mut fdset = ScmFdset::new();
    let cmsg_data = scm_fdset_init(&mut fdset, None, 0);

    let nr_fds = fds.len();
    let mut i = 0usize;

    // Get raw pointer and length for data if present
    let (data_ptr, _data_len) = match &data {
        Some(d) => (d.as_ptr() as *mut u8, d.len()),
        None => (ptr::null_mut(), 0),
    };
    let mut data_offset = 0usize;

    while i < nr_fds {
        let min_fd = std::cmp::min(CR_SCM_MAX_FD, nr_fds - i);

        // Prepare data slice for this chunk if present
        let chunk_data = if !data_ptr.is_null() {
            Some(unsafe {
                std::slice::from_raw_parts_mut(data_ptr.add(data_offset), min_fd * ch_size)
            })
        } else {
            None
        };

        scm_fdset_init_chunk(&mut fdset, min_fd, chunk_data, ch_size);

        let ret = unsafe { libc::recvmsg(sock, &mut fdset.hdr, flags) };
        if ret <= 0 {
            if ret == 0 {
                return -libc::ENOMSG;
            }
            return -unsafe { *libc::__errno_location() };
        }

        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&fdset.hdr) };
        if cmsg.is_null() {
            return -libc::EINVAL;
        }
        let cmsg_type = unsafe { (*cmsg).cmsg_type };
        if cmsg_type != libc::SCM_RIGHTS {
            return -libc::EINVAL;
        }
        if (fdset.hdr.msg_flags & libc::MSG_CTRUNC) != 0 {
            return -libc::ENFILE;
        }

        // Calculate actual number of fds received
        let cmsg_len = unsafe { (*cmsg).cmsg_len };
        let received_fds = (cmsg_len - mem::size_of::<libc::cmsghdr>()) / mem::size_of::<i32>();

        if received_fds > CR_SCM_MAX_FD {
            // Kernel returned too many fds - bug
            return -libc::EBADFD;
        }

        if received_fds == 0 {
            return -libc::EBADFD;
        }

        // Copy received fds
        unsafe {
            ptr::copy_nonoverlapping(cmsg_data, fds.as_mut_ptr().add(i), received_fds);
        }

        if !data_ptr.is_null() {
            data_offset += received_fds * ch_size;
        }

        i += received_fds;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scm_fdset_new() {
        let fdset = ScmFdset::new();
        assert_eq!(fdset.iov.iov_len, 0);
    }

    #[test]
    fn test_scm_fdset_init() {
        let mut fdset = ScmFdset::new();
        let fds_ptr = scm_fdset_init(&mut fdset, None, 0);

        assert!(!fds_ptr.is_null());
        assert_eq!(fdset.hdr.msg_iovlen, 1);
        assert!(fdset.hdr.msg_name.is_null());
    }

    #[test]
    fn test_scm_fdset_init_chunk() {
        let mut fdset = ScmFdset::new();
        let _ = scm_fdset_init(&mut fdset, None, 0);

        scm_fdset_init_chunk(&mut fdset, 3, None, 0);
        assert_eq!(fdset.iov.iov_len, 1); // dummy byte when no data
    }
}
