use std::os::unix::io::RawFd;

use super::util::{rlimit_unlimit_nofile, service_fd_rlim_cur, set_service_fd_rlim_cur};

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfdType {
    ServiceFdMin = 0,

    LogFdOff,
    ImgFdOff,
    ImgStreamerFdOff,
    ProcFdOff,
    ProcPidFdOff,
    ProcSelfFdOff,
    CrProcFdOff,
    RootFdOff,
    CgroupYard,
    CgroupdSk,
    UsernsdSk,
    NsFdOff,
    TransportFdOff,
    RpcSkOff,
    FdstoreSkOff,

    ServiceFdMax,
}

pub struct ServiceFdState {
    sfd_map: u32,
    sfd_arr: [RawFd; SfdType::ServiceFdMax as usize],
    service_fd_base: RawFd,
    service_fd_id: i32,
}

impl Default for ServiceFdState {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceFdState {
    pub const fn new() -> Self {
        Self {
            sfd_map: 0,
            sfd_arr: [-1; SfdType::ServiceFdMax as usize],
            service_fd_base: 0,
            service_fd_id: 0,
        }
    }

    fn test_bit(&self, bit: SfdType) -> bool {
        (self.sfd_map & (1 << bit as u32)) != 0
    }

    pub fn set_bit(&mut self, bit: SfdType) {
        self.sfd_map |= 1 << bit as u32;
    }

    pub fn clear_bit(&mut self, bit: SfdType) {
        self.sfd_map &= !(1 << bit as u32);
    }

    fn __get_service_fd(&self, sfd_type: SfdType) -> RawFd {
        self.service_fd_base - sfd_type as RawFd - SfdType::ServiceFdMax as RawFd * self.service_fd_id
    }

    pub fn get_service_fd(&self, sfd_type: SfdType) -> RawFd {
        debug_assert!(
            (sfd_type as i32) > SfdType::ServiceFdMin as i32
                && (sfd_type as i32) < SfdType::ServiceFdMax as i32
        );

        if !self.test_bit(sfd_type) {
            return -1;
        }

        if self.service_fd_base == 0 {
            self.sfd_arr[sfd_type as usize]
        } else {
            self.__get_service_fd(sfd_type)
        }
    }

    pub fn set_service_fd(&mut self, sfd_type: SfdType, fd: RawFd) {
        self.sfd_arr[sfd_type as usize] = fd;
        self.set_bit(sfd_type);
    }

    /// Installs a file descriptor as a service fd of the given type.
    /// If service_fd_base is 0 (pre-fork mode), stores fd directly in sfd_arr.
    /// Otherwise, dups the fd to the expected service fd number.
    /// Returns the installed fd on success, -1 on error.
    pub fn install_service_fd(&mut self, sfd_type: SfdType, fd: RawFd) -> RawFd {
        debug_assert!(
            (sfd_type as i32) > SfdType::ServiceFdMin as i32
                && (sfd_type as i32) < SfdType::ServiceFdMax as i32
        );

        if self.service_fd_base == 0 {
            // Pre-fork mode: store fd directly
            if self.test_bit(sfd_type) {
                unsafe { libc::close(self.sfd_arr[sfd_type as usize]) };
            }
            self.sfd_arr[sfd_type as usize] = fd;
            self.set_bit(sfd_type);
            return fd;
        }

        // Post-fork mode: dup to the expected slot
        let sfd = self.__get_service_fd(sfd_type);
        let tmp = if !self.test_bit(sfd_type) {
            unsafe { libc::fcntl(fd, libc::F_DUPFD, sfd) }
        } else {
            unsafe { libc::dup3(fd, sfd, libc::O_CLOEXEC) }
        };

        if tmp < 0 {
            unsafe { libc::close(fd) };
            return -1;
        } else if tmp != sfd {
            unsafe {
                libc::close(tmp);
                libc::close(fd);
            }
            return -1;
        }

        self.set_bit(sfd_type);
        unsafe { libc::close(fd) };
        sfd
    }

    /// Closes the service fd of the given type.
    /// Returns 0 on success, -1 on error.
    pub fn close_service_fd(&mut self, sfd_type: SfdType) -> i32 {
        let fd = self.get_service_fd(sfd_type);
        if fd < 0 {
            return 0;
        }

        let ret = unsafe { libc::close(fd) };
        if ret != 0 {
            return -1;
        }

        self.clear_bit(sfd_type);
        0
    }

    pub fn is_any_service_fd(&self, fd: RawFd) -> bool {
        let sfd_min_fd = self.__get_service_fd(SfdType::ServiceFdMax);
        let sfd_max_fd = self.__get_service_fd(SfdType::ServiceFdMin);

        if fd > sfd_min_fd && fd < sfd_max_fd {
            let type_val =
                SfdType::ServiceFdMax as i32 - (fd - sfd_min_fd);
            if type_val > SfdType::ServiceFdMin as i32 && type_val < SfdType::ServiceFdMax as i32 {
                let sfd_type = unsafe { std::mem::transmute::<i32, SfdType>(type_val) };
                return self.test_bit(sfd_type);
            }
        }

        false
    }
}

#[repr(C)]
struct Rlimit64 {
    rlim_cur: u64,
    rlim_max: u64,
}

pub fn init_service_fd() -> i32 {
    rlimit_unlimit_nofile();

    let mut rlimit = Rlimit64 {
        rlim_cur: 0,
        rlim_max: 0,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_prlimit64,
            libc::getpid(),
            libc::RLIMIT_NOFILE,
            std::ptr::null::<Rlimit64>(),
            &mut rlimit as *mut Rlimit64,
        )
    };

    if ret != 0 {
        log::error!("Can't get rlimit");
        return -1;
    }

    set_service_fd_rlim_cur(rlimit.rlim_cur as u32);
    0
}

fn sfd_type_name(sfd_type: SfdType) -> &'static str {
    match sfd_type {
        SfdType::ServiceFdMin => "SERVICE_FD_MIN",
        SfdType::LogFdOff => "LOG_FD",
        SfdType::ImgFdOff => "IMG_FD",
        SfdType::ImgStreamerFdOff => "IMG_STREAMER_FD",
        SfdType::ProcFdOff => "PROC_FD",
        SfdType::ProcPidFdOff => "PROC_PID_FD",
        SfdType::ProcSelfFdOff => "PROC_SELF_FD",
        SfdType::CrProcFdOff => "CR_PROC_FD",
        SfdType::RootFdOff => "ROOT_FD",
        SfdType::CgroupYard => "CGROUP_YARD",
        SfdType::CgroupdSk => "CGROUPD_SK",
        SfdType::UsernsdSk => "USERNSD_SK",
        SfdType::NsFdOff => "NS_FD",
        SfdType::TransportFdOff => "TRANSPORT_FD",
        SfdType::RpcSkOff => "RPC_SK",
        SfdType::FdstoreSkOff => "FDSTORE_SK",
        SfdType::ServiceFdMax => "SERVICE_FD_MAX",
    }
}

fn round_down(x: u32, align: u32) -> u32 {
    (x / align) * align
}

impl ServiceFdState {
    pub fn set_service_fd_base(&mut self, base: RawFd) {
        self.service_fd_base = base;
    }

    pub fn set_service_fd_id(&mut self, id: i32) {
        self.service_fd_id = id;
    }

    pub fn get_service_fd_base(&self) -> RawFd {
        self.service_fd_base
    }

    pub fn get_service_fd_id(&self) -> i32 {
        self.service_fd_id
    }

    fn move_service_fd(
        &mut self,
        sfd_type: SfdType,
        new_id: i32,
        new_base: RawFd,
        clone_flags: u64,
    ) -> i32 {
        let old = self.get_service_fd(sfd_type);
        let new = new_base - sfd_type as RawFd - SfdType::ServiceFdMax as RawFd * new_id;

        if old < 0 {
            return 0;
        }

        let ret = if !self.test_bit(sfd_type) {
            unsafe { libc::fcntl(old, libc::F_DUPFD, new) }
        } else {
            unsafe { libc::dup2(old, new) }
        };

        if ret == -1 {
            log::error!(
                "{} unable to clone {}->{}",
                sfd_type_name(sfd_type),
                old,
                new
            );
            return -1;
        } else if ret != new {
            log::error!(
                "{} busy target {} -> {}",
                sfd_type_name(sfd_type),
                old,
                new
            );
            return -1;
        } else if (clone_flags & libc::CLONE_FILES as u64) == 0 {
            unsafe { libc::close(old) };
        }

        0
    }
}

pub fn choose_service_fd_base(
    sfd_state: &ServiceFdState,
    max_fd: i32,
    fdt_nr: i32,
    service_fd_id: i32,
) -> i32 {
    let id = service_fd_id;

    // If this is not the owner of the fdt (id != 0), use existing base
    if id != 0 && sfd_state.service_fd_base > 0 {
        return sfd_state.service_fd_base;
    }

    let mut nr = max_fd;

    // Service fds go after max fd near right border of alignment
    nr += (SfdType::ServiceFdMax as i32 - SfdType::ServiceFdMin as i32) * fdt_nr;
    nr += 16; // Safety pad

    let real_nr = nr;

    // Compute alignment (fdtable allocation uses powers of 2)
    let pointer_bits = std::mem::size_of::<*const ()>() as i32;
    let align = 1024 / pointer_bits;

    nr /= align;
    if nr > 0 {
        // Round up to next power of 2
        nr = 1 << (32 - (nr as u32).leading_zeros());
    } else {
        nr = 1;
    }
    nr *= align;

    let rlim_cur = service_fd_rlim_cur() as i32;
    if nr > rlim_cur {
        // Right border is bigger than rlim. OK, then just aligned value is enough
        nr = round_down(rlim_cur as u32, align as u32) as i32;
        if nr < real_nr {
            log::error!("Can't choose service_fd_base: {} {}", nr, real_nr);
            return -1;
        }
    }

    nr
}

pub fn clone_service_fd(
    sfd_state: &mut ServiceFdState,
    service_fd_id: i32,
    max_fd: i32,
    fdt_nr: i32,
    clone_flags: u64,
) -> i32 {
    let new_base = choose_service_fd_base(sfd_state, max_fd, fdt_nr, service_fd_id);

    if new_base == -1 {
        return -1;
    }

    // Check if already at the right position
    let log_fd = sfd_state.get_service_fd(SfdType::LogFdOff);
    let expected_log_fd = new_base
        - SfdType::LogFdOff as RawFd
        - SfdType::ServiceFdMax as RawFd * service_fd_id;

    if log_fd == expected_log_fd {
        return 0;
    }

    // Dup sfds in memmove() style: they may overlap
    if log_fd < expected_log_fd {
        // Moving forward, iterate from min to max
        for i in (SfdType::ServiceFdMin as i32 + 1)..(SfdType::ServiceFdMax as i32) {
            let sfd_type = unsafe { std::mem::transmute::<i32, SfdType>(i) };
            if sfd_state.move_service_fd(sfd_type, service_fd_id, new_base, clone_flags) != 0 {
                return -1;
            }
        }
    } else {
        // Moving backward, iterate from max to min
        for i in ((SfdType::ServiceFdMin as i32 + 1)..(SfdType::ServiceFdMax as i32)).rev() {
            let sfd_type = unsafe { std::mem::transmute::<i32, SfdType>(i) };
            if sfd_state.move_service_fd(sfd_type, service_fd_id, new_base, clone_flags) != 0 {
                return -1;
            }
        }
    }

    sfd_state.set_service_fd_base(new_base);
    sfd_state.set_service_fd_id(service_fd_id);

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_fd_state() {
        let mut state = ServiceFdState::new();
        assert_eq!(state.get_service_fd(SfdType::CgroupYard), -1);

        state.set_service_fd(SfdType::CgroupYard, 42);
        assert_eq!(state.get_service_fd(SfdType::CgroupYard), 42);

        state.clear_bit(SfdType::CgroupYard);
        assert_eq!(state.get_service_fd(SfdType::CgroupYard), -1);
    }
}
