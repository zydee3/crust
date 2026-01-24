use std::sync::Mutex;

use crate::criu::namespaces::root_ns_mask_try;
use crate::criu::netfilter::{iptables_unlock_connection, iptables_unlock_connection_info};
use crate::criu::options::{opts, NetworkLockMethod};
use crate::criu::soccr::{libsoccr_resume, LibsoccrSk};
use crate::criu::sockets::{restore_opt, InetSkDesc, InetSkInfo};

static CPT_TCP_REPAIR_SOCKETS: Mutex<Vec<Box<InetSkDesc>>> = Mutex::new(Vec::new());
static RST_TCP_REPAIR_SOCKETS: Mutex<Vec<Box<InetSkInfo>>> = Mutex::new(Vec::new());

pub fn cpt_tcp_repair_add(sk: Box<InetSkDesc>) {
    CPT_TCP_REPAIR_SOCKETS.lock().unwrap().push(sk);
}

pub fn rst_tcp_repair_add(sk: Box<InetSkInfo>) {
    RST_TCP_REPAIR_SOCKETS.lock().unwrap().push(sk);
}

pub fn unlock_connection(sk: &InetSkDesc) -> i32 {
    match opts().network_lock_method {
        NetworkLockMethod::Iptables => {
            if iptables_unlock_connection(sk).is_err() {
                -1
            } else {
                0
            }
        }
        // All connections will be unlocked in network_unlock(void)
        NetworkLockMethod::Nftables => 0,
        NetworkLockMethod::Skip => 0,
    }
}

pub fn unlock_connection_info(si: &InetSkInfo) -> i32 {
    match opts().network_lock_method {
        NetworkLockMethod::Iptables => iptables_unlock_connection_info(si),
        // All connections will be unlocked in network_unlock(void)
        NetworkLockMethod::Nftables => 0,
        NetworkLockMethod::Skip => 0,
    }
}

fn tcp_unlock_one(sk: &mut InetSkDesc) {
    if root_ns_mask_try().map_or(true, |mask| (mask & libc::CLONE_NEWNET as u64) == 0) {
        let ret = unlock_connection(sk);
        if ret < 0 {
            log::error!("Failed to unlock TCP connection {:x}", sk.sd.ino);
        }
    }

    if let Some(priv_ptr) = sk.priv_data.take() {
        // SAFETY: priv_data was allocated as a Box<LibsoccrSk>
        let libsoccr_sk = unsafe { Box::from_raw(priv_ptr as *mut LibsoccrSk) };
        libsoccr_resume(*libsoccr_sk);
    }

    /*
     * tcp_repair_off modifies SO_REUSEADDR so
     * don't forget to restore original value.
     */
    restore_opt(sk.rfd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &sk.cpt_reuseaddr);

    unsafe { libc::close(sk.rfd) };
}

pub fn cpt_unlock_tcp_connections() {
    let mut sockets = CPT_TCP_REPAIR_SOCKETS.lock().unwrap();
    for sk in sockets.iter_mut() {
        tcp_unlock_one(sk);
    }
    sockets.clear();
}

pub fn rst_unlock_tcp_connections() {
    if opts().tcp_close != 0 {
        return;
    }

    // Network will be unlocked by network-unlock scripts
    if root_ns_mask_try().map_or(false, |mask| (mask & libc::CLONE_NEWNET as u64) != 0) {
        return;
    }

    let sockets = RST_TCP_REPAIR_SOCKETS.lock().unwrap();
    for ii in sockets.iter() {
        unlock_connection_info(ii);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpt_tcp_repair_add() {
        // Clear any existing sockets
        CPT_TCP_REPAIR_SOCKETS.lock().unwrap().clear();

        let sk = Box::new(InetSkDesc {
            sd: crate::criu::sockets::SocketDesc {
                family: 0,
                ino: 0,
                next: None,
                sk_ns: None,
                already_dumped: 0,
            },
            typ: 0,
            src_port: 0,
            dst_port: 0,
            state: 0,
            rqlen: 0,
            wqlen: 0,
            uwqlen: 0,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            shutdown: 0,
            cork: false,
            rfd: -1,
            cpt_reuseaddr: 0,
            priv_data: None,
        });

        cpt_tcp_repair_add(sk);
        assert_eq!(CPT_TCP_REPAIR_SOCKETS.lock().unwrap().len(), 1);

        // Clean up
        CPT_TCP_REPAIR_SOCKETS.lock().unwrap().clear();
    }
}
