//! Native nftables support using rustables.
//!
//! Replaces shell-out to iptables-restore/nft CLI with direct netlink communication.

use rustables::expr::{Cmp, CmpOp, Meta, MetaType, Register};
use rustables::{Batch, Chain, ChainPolicy, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table};

use crate::criu::net::SOCCR_MARK;

const CRIU_TABLE_NAME: &str = "CRIU";

fn create_criu_table(family: ProtocolFamily) -> Table {
    Table::new(family).with_name(CRIU_TABLE_NAME)
}

fn create_input_chain(table: &Table) -> Chain {
    Chain::new(table)
        .with_name("input")
        .with_hook(Hook::new(HookClass::In, 0))
        .with_policy(ChainPolicy::Drop)
}

fn create_output_chain(table: &Table) -> Chain {
    Chain::new(table)
        .with_name("output")
        .with_hook(Hook::new(HookClass::Out, 0))
        .with_policy(ChainPolicy::Drop)
}

fn create_mark_accept_rule(chain: &Chain) -> Result<Rule, rustables::error::QueryError> {
    let mut rule = Rule::new(chain)?;

    // Load packet mark into register
    let meta = Meta::default()
        .with_key(MetaType::Mark)
        .with_dreg(Register::Reg1);
    rule = rule.with_expr(meta);

    // Compare mark value with SOCCR_MARK
    let cmp = Cmp::new(CmpOp::Eq, SOCCR_MARK.to_ne_bytes().to_vec());
    rule = rule.with_expr(cmp);

    // Accept matching packets
    rule = rule.accept();

    Ok(rule)
}

/// Locks network traffic using nftables.
///
/// Creates a CRIU table with input/output chains that drop all traffic
/// except packets marked with SOCCR_MARK (used by TCP repair mode).
pub fn nftables_lock_network(ipv6: bool) -> Result<(), rustables::error::QueryError> {
    let family = if ipv6 {
        ProtocolFamily::Ipv6
    } else {
        ProtocolFamily::Ipv4
    };

    let table = create_criu_table(family);
    let input_chain = create_input_chain(&table);
    let output_chain = create_output_chain(&table);

    let input_rule = create_mark_accept_rule(&input_chain)?;
    let output_rule = create_mark_accept_rule(&output_chain)?;

    let mut batch = Batch::new();
    batch.add(&table, MsgType::Add);
    batch.add(&input_chain, MsgType::Add);
    batch.add(&output_chain, MsgType::Add);
    batch.add(&input_rule, MsgType::Add);
    batch.add(&output_rule, MsgType::Add);

    batch.send()?;
    Ok(())
}

/// Unlocks network traffic by removing the CRIU nftables table.
pub fn nftables_unlock_network(ipv6: bool) -> Result<(), rustables::error::QueryError> {
    let family = if ipv6 {
        ProtocolFamily::Ipv6
    } else {
        ProtocolFamily::Ipv4
    };

    let table = create_criu_table(family);

    let mut batch = Batch::new();
    batch.add(&table, MsgType::Del);

    batch.send()?;
    Ok(())
}

/// Locks network for both IPv4 and IPv6 if available.
pub fn nftables_lock_network_all(ipv6_enabled: bool) -> i32 {
    if let Err(e) = nftables_lock_network(false) {
        log::error!("Failed to lock IPv4 network with nftables: {}", e);
        return -1;
    }

    if ipv6_enabled {
        if let Err(e) = nftables_lock_network(true) {
            log::error!("Failed to lock IPv6 network with nftables: {}", e);
            // Try to clean up IPv4 rules
            let _ = nftables_unlock_network(false);
            return -1;
        }
    }

    0
}

/// Unlocks network for both IPv4 and IPv6.
pub fn nftables_unlock_network_all(ipv6_enabled: bool) -> i32 {
    let mut ret = 0;

    if let Err(e) = nftables_unlock_network(false) {
        log::error!("Failed to unlock IPv4 network with nftables: {}", e);
        ret = -1;
    }

    if ipv6_enabled {
        if let Err(e) = nftables_unlock_network(true) {
            log::error!("Failed to unlock IPv6 network with nftables: {}", e);
            ret = -1;
        }
    }

    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_table() {
        let table = create_criu_table(ProtocolFamily::Ipv4);
        assert_eq!(table.get_name().map(|s| s.as_str()), Some(CRIU_TABLE_NAME));
    }

    #[test]
    fn test_create_chains() {
        let table = create_criu_table(ProtocolFamily::Ipv4);
        let input = create_input_chain(&table);
        let output = create_output_chain(&table);

        assert_eq!(input.get_name().map(|s| s.as_str()), Some("input"));
        assert_eq!(output.get_name().map(|s| s.as_str()), Some("output"));
    }
}
