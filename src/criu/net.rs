use std::ffi::CString;
use std::os::unix::io::RawFd;

use crate::criu::external::{external_for_each_type, External};
use crate::criu::kerndat::kdat;
use crate::criu::namespaces::{ns_desc, restore_ns, switch_ns};
use crate::criu::nft;
use crate::criu::options::{opts, NetworkLockMethod};
use crate::criu::pstree::root_item_pid_real;
use crate::criu::util::cr_system;
use crate::criu::util::CRS_CAN_FAIL;

pub const SOCCR_MARK: u32 = 0xC114;
const IFNAMSIZ: usize = 16;
const SIOCBRADDIF: libc::c_ulong = 0x89a2;
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
const IFF_UP: libc::c_short = 0x1;

fn close_safe(fd: &mut RawFd) {
    if *fd >= 0 {
        unsafe { libc::close(*fd) };
        *fd = -1;
    }
}

pub fn iptables_has_criu_jump_target() -> bool {
    let mut fd: RawFd;
    let argv = ["sh", "-c", "iptables -C INPUT -j CRIU"];

    let c_path = CString::new("/dev/null").unwrap();
    fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        fd = -1;
        log::error!("failed to open /dev/null, using log fd");
    }

    let ret = cr_system(fd, fd, fd, "sh", &argv, CRS_CAN_FAIL);
    close_safe(&mut fd);
    ret == 0
}

pub fn iptables_restore(ipv6: bool, buf: &[u8]) -> i32 {
    let mut pfd: [RawFd; 2] = [-1, -1];

    let cmd4 = ["iptables-restore", "-w", "--noflush"];
    let cmd6 = ["ip6tables-restore", "-w", "--noflush"];
    let cmd: &[&str] = if ipv6 { &cmd6 } else { &cmd4 };

    if unsafe { libc::pipe(pfd.as_mut_ptr()) } < 0 {
        log::error!("Unable to create pipe");
        return -1;
    }

    let written = unsafe { libc::write(pfd[1], buf.as_ptr() as *const libc::c_void, buf.len()) };
    if written < 0 || (written as usize) < buf.len() {
        log::error!("Unable to write iptables configuration");
        close_safe(&mut pfd[0]);
        close_safe(&mut pfd[1]);
        return -1;
    }
    close_safe(&mut pfd[1]);

    let ret = cr_system(pfd[0], -1, -1, cmd[0], cmd, 0);

    close_safe(&mut pfd[1]);
    close_safe(&mut pfd[0]);
    ret
}

pub fn iptables_network_unlock_internal() -> i32 {
    let delete_jump_targets = b"*filter\n\
                                :CRIU - [0:0]\n\
                                -D INPUT -j CRIU\n\
                                -D OUTPUT -j CRIU\n\
                                COMMIT\n";

    let delete_criu_chain = b"*filter\n\
                              :CRIU - [0:0]\n\
                              -X CRIU\n\
                              COMMIT\n";

    let mut ret = 0;

    ret |= iptables_restore(false, delete_jump_targets);
    if kdat().ipv6 {
        ret |= iptables_restore(true, delete_jump_targets);
    }

    /*
     * For compatibility with iptables-nft backend, we need to make sure that all jump
     * targets have been removed before deleting the CRIU chain.
     */
    if iptables_has_criu_jump_target() {
        ret |= iptables_restore(false, delete_jump_targets);
        if kdat().ipv6 {
            ret |= iptables_restore(true, delete_jump_targets);
        }
    }

    ret |= iptables_restore(false, delete_criu_chain);
    if kdat().ipv6 {
        ret |= iptables_restore(true, delete_criu_chain);
    }

    ret
}

pub fn iptables_network_lock_internal() -> i32 {
    let conf = format!(
        "*filter\n\
         :CRIU - [0:0]\n\
         -I INPUT -j CRIU\n\
         -I OUTPUT -j CRIU\n\
         -A CRIU -m mark --mark {} -j ACCEPT\n\
         -A CRIU -j DROP\n\
         COMMIT\n",
        SOCCR_MARK
    );

    let mut ret = 0;

    ret |= iptables_restore(false, conf.as_bytes());
    if kdat().ipv6 {
        ret |= iptables_restore(true, conf.as_bytes());
    }

    if ret != 0 {
        log::error!(
            "Locking network failed: iptables-restore returned {}. \
             This may be connected to disabled \
             CONFIG_NETFILTER_XT_MARK kernel build config \
             option.",
            ret
        );
    }

    ret
}

fn nftables_network_unlock() -> i32 {
    nft::nftables_unlock_network_all(kdat().ipv6)
}

fn nftables_lock_network_internal(_restore: bool) -> i32 {
    nft::nftables_lock_network_all(kdat().ipv6)
}

pub fn network_lock_internal(restore: bool) -> i32 {
    let mut ret = 0;

    if opts().network_lock_method == NetworkLockMethod::Skip {
        return 0;
    }

    let nsret = match switch_ns(root_item_pid_real(), &ns_desc::NET, true) {
        Ok(Some(fd)) => fd,
        Ok(None) => return -1,
        Err(_) => return -1,
    };

    if opts().network_lock_method == NetworkLockMethod::Iptables {
        ret = iptables_network_lock_internal();
    } else if opts().network_lock_method == NetworkLockMethod::Nftables {
        ret = nftables_lock_network_internal(restore);
    }

    if restore_ns(nsret, &ns_desc::NET) != 0 {
        ret = -1;
    }

    ret
}

pub fn network_unlock_internal() -> i32 {
    let mut ret = 0;

    if opts().network_lock_method == NetworkLockMethod::Skip {
        return 0;
    }

    let nsret = match switch_ns(root_item_pid_real(), &ns_desc::NET, true) {
        Ok(Some(fd)) => fd,
        Ok(None) => return -1,
        Err(_) => return -1,
    };

    if opts().network_lock_method == NetworkLockMethod::Iptables {
        ret = iptables_network_unlock_internal();
    } else if opts().network_lock_method == NetworkLockMethod::Nftables {
        ret = nftables_network_unlock();
    }

    if restore_ns(nsret, &ns_desc::NET) != 0 {
        ret = -1;
    }

    ret
}

pub fn network_unlock() {
    use crate::criu::namespaces::root_ns_mask;
    use crate::criu::sk_tcp::{cpt_unlock_tcp_connections, rst_unlock_tcp_connections};

    log::info!("Unlock network");

    cpt_unlock_tcp_connections();
    rst_unlock_tcp_connections();

    if (root_ns_mask() & libc::CLONE_NEWNET as u64) != 0 {
        // run_scripts(ACT_NET_UNLOCK) - scripts not yet implemented
        network_unlock_internal();
    } else if opts().network_lock_method == NetworkLockMethod::Nftables {
        nftables_network_unlock();
    }
}

#[repr(C)]
struct Ifreq {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_union: IfreqUnion,
}

#[repr(C)]
union IfreqUnion {
    ifr_ifindex: libc::c_int,
    ifr_flags: libc::c_short,
}

fn if_nametoindex(name: &str) -> libc::c_uint {
    let c_name = match CString::new(name) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    unsafe { libc::if_nametoindex(c_name.as_ptr()) }
}

fn copy_to_ifname(dest: &mut [libc::c_char; IFNAMSIZ], src: &str) {
    let bytes = src.as_bytes();
    let len = std::cmp::min(bytes.len(), IFNAMSIZ - 1);
    for i in 0..len {
        dest[i] = bytes[i] as libc::c_char;
    }
    dest[len] = 0;
}

fn changeflags(s: RawFd, ifname: &str, flags: libc::c_short) -> i32 {
    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    copy_to_ifname(&mut ifr.ifr_name, ifname);
    ifr.ifr_union.ifr_flags = flags;

    let ret = unsafe { libc::ioctl(s, SIOCSIFFLAGS, &ifr) };
    if ret < 0 {
        log::error!("Can't set flags of interface {}", ifname);
        return -1;
    }
    0
}

fn move_to_bridge(ext: &External, sk: &mut RawFd) -> i32 {
    let val = match ext.id.find(':') {
        Some(pos) => &ext.id[pos + 1..],
        None => return -1,
    };

    let at_pos = match val.find('@') {
        Some(pos) => pos,
        None => return 0,
    };

    let out = &val[..at_pos];
    let br = &val[at_pos + 1..];

    log::debug!("\tMoving dev {} to bridge {}", out, br);

    if *sk == -1 {
        *sk = unsafe { libc::socket(libc::AF_LOCAL, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if *sk < 0 {
            log::error!("Can't create control socket");
            return -1;
        }
    }

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_union.ifr_ifindex = if_nametoindex(out) as libc::c_int;
    if unsafe { ifr.ifr_union.ifr_ifindex } == 0 {
        log::error!("Can't get index of {}", out);
        return -1;
    }
    copy_to_ifname(&mut ifr.ifr_name, br);
    let ret = unsafe { libc::ioctl(*sk, SIOCBRADDIF, &ifr) };
    if ret < 0 {
        log::error!("Can't add interface {} to bridge {}", out, br);
        return -1;
    }

    let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_union.ifr_ifindex = 0;
    copy_to_ifname(&mut ifr.ifr_name, out);
    let ret = unsafe { libc::ioctl(*sk, SIOCGIFFLAGS, &ifr) };
    if ret < 0 {
        log::error!("Can't get flags of interface {}", out);
        return -1;
    }

    let flags = unsafe { ifr.ifr_union.ifr_flags };
    if (flags & IFF_UP) != 0 {
        return 0;
    }

    if changeflags(*sk, out, flags | IFF_UP) < 0 {
        return -1;
    }

    0
}

/// Move veth interfaces to their bridges.
/// Maps to: move_veth_to_bridge (criu/net.c:3827-3836)
pub fn move_veth_to_bridge() -> i32 {
    let externals = &opts().external;

    let ext_list: Vec<External> = externals
        .iter()
        .map(|s| External::new(s.clone()))
        .collect();

    let mut sk: RawFd = -1;

    let ret = external_for_each_type(&ext_list, "veth", |ext| move_to_bridge(ext, &mut sk));

    if sk >= 0 {
        close_safe(&mut sk);
    }

    ret
}
