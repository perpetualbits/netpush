// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The pure heart of `netpush`: merge what three independent sources say about
//! each IP address — **NetBox** (intended inventory), **DNS** (the PTR records
//! actually served), and a **live probe** (ping/ARP) — into one [`AddressStatus`].
//!
//! ## Why this exists
//! No single source is trustworthy. Allocating one iDRAC address in `10.87.3.0/24`
//! showed all three failure modes at once:
//! - NetBox listed only 11 of ~40 addresses actually in use (under-populated);
//! - several addresses had DNS PTRs but no NetBox entry (`iprotect-*`, cameras);
//! - one address answered ARP while appearing in neither (a squatter).
//!
//! Merging the sources is the only safe way to answer "is this address free?".
//! This module does **no I/O**, so the rule stays trivial to test against known cases.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// What NetBox knows about one address — for now just the forward DNS name it
/// claims (`None` if reserved without a name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetBoxRecord {
    /// The `dns_name` field of the NetBox IP-address object, if set.
    pub dns_name: Option<String>,
}

/// Everything gathered about a single address, one field per source. A field being
/// `None`/`false` means "that source does not claim this address".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressFacts {
    /// The address these facts describe.
    pub addr: Ipv4Addr,
    /// NetBox's record, or `None` if NetBox has no object for this address.
    pub netbox: Option<NetBoxRecord>,
    /// The reverse-DNS (PTR) name, or `None` if the resolver returned nothing.
    pub ptr: Option<String>,
    /// `true` if the address answered a ping / ARP probe on its own L2.
    pub live: bool,
}

/// The single verdict for one address after merging all sources. Only
/// [`AddressStatus::Free`] is safe to allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressStatus {
    /// No source claims it — safe to allocate.
    Free,
    /// In NetBox **and** DNS, names agree — a clean, complete allocation.
    Allocated,
    /// In NetBox but with no PTR yet — reserved, DNS not pushed.
    NetBoxOnly,
    /// Has a PTR but no NetBox object — real-world drift NetBox missed.
    DnsOnly,
    /// Answers the live probe but is in neither NetBox nor DNS — a squatter.
    LiveUnregistered,
    /// In NetBox and DNS, but the two names disagree — needs a human decision.
    Conflict,
}

impl AddressStatus {
    /// Whether this status means the address can be safely handed out.
    #[must_use]
    pub fn is_free(self) -> bool {
        matches!(self, AddressStatus::Free)
    }
}

/// One row of the reconciled view: an address, its verdict, and the best name we
/// know for it (NetBox's name if present, otherwise the PTR).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRow {
    /// The address.
    pub addr: Ipv4Addr,
    /// The merged verdict.
    pub status: AddressStatus,
    /// The most authoritative name we have, normalized (lower-case, no trailing dot).
    pub name: Option<String>,
}

/// Normalize a DNS name for comparison: strip a trailing dot and lower-case it.
///
/// DNS is case-insensitive and PTRs carry a trailing dot while NetBox's `dns_name`
/// does not, so both must be folded away before comparing two names.
fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Decide the [`AddressStatus`] for one address from its facts.
///
/// How: if both NetBox and DNS claim the address we compare their normalized names
/// (equal ⇒ `Allocated`, different ⇒ `Conflict`); exactly one source ⇒ the matching
/// `*Only` variant; neither but it answered the probe ⇒ `LiveUnregistered`; neither
/// and silent ⇒ `Free`. The principle: an address is only safe to reuse when every
/// source agrees it is unused, so any single claim means "taken".
#[must_use]
pub fn classify(facts: &AddressFacts) -> AddressStatus {
    let nb_name = facts
        .netbox
        .as_ref()
        .and_then(|r| r.dns_name.as_deref())
        .map(normalize);
    let ptr_name = facts.ptr.as_deref().map(normalize);

    match (facts.netbox.is_some(), facts.ptr.is_some()) {
        (true, true) => match (nb_name, ptr_name) {
            (Some(a), Some(b)) if a != b => AddressStatus::Conflict,
            _ => AddressStatus::Allocated,
        },
        (true, false) => AddressStatus::NetBoxOnly,
        (false, true) => AddressStatus::DnsOnly,
        (false, false) if facts.live => AddressStatus::LiveUnregistered,
        (false, false) => AddressStatus::Free,
    }
}

/// The best display name for an address: NetBox's `dns_name`, else the PTR.
fn best_name(facts: &AddressFacts) -> Option<String> {
    facts
        .netbox
        .as_ref()
        .and_then(|r| r.dns_name.as_deref())
        .or(facts.ptr.as_deref())
        .map(normalize)
}

/// Build the reconciled table for every usable host address in `range`.
///
/// How: index `facts` by address, then walk every host address in the CIDR;
/// addresses with no facts default to `Free`. The result is sorted by address.
#[must_use]
pub fn reconcile(range: Cidr, facts: &[AddressFacts]) -> Vec<AddressRow> {
    let by_addr: HashMap<Ipv4Addr, &AddressFacts> =
        facts.iter().map(|f| (f.addr, f)).collect();

    range
        .hosts()
        .map(|addr| match by_addr.get(&addr) {
            Some(f) => AddressRow {
                addr,
                status: classify(f),
                name: best_name(f),
            },
            None => AddressRow {
                addr,
                status: AddressStatus::Free,
                name: None,
            },
        })
        .collect()
}

/// The lowest free address in a reconciled table, if any.
#[must_use]
pub fn first_free(rows: &[AddressRow]) -> Option<Ipv4Addr> {
    rows.iter().find(|r| r.status.is_free()).map(|r| r.addr)
}

/// A tally of how many addresses fall into each status — for the header bar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Number of `Free` addresses.
    pub free: usize,
    /// Number of `Allocated` addresses.
    pub allocated: usize,
    /// Number of `NetBoxOnly` addresses.
    pub netbox_only: usize,
    /// Number of `DnsOnly` addresses.
    pub dns_only: usize,
    /// Number of `LiveUnregistered` addresses.
    pub live_unregistered: usize,
    /// Number of `Conflict` addresses.
    pub conflict: usize,
}

/// Count how many addresses fall into each [`AddressStatus`].
#[must_use]
pub fn counts(rows: &[AddressRow]) -> Counts {
    let mut c = Counts::default();
    for r in rows {
        match r.status {
            AddressStatus::Free => c.free += 1,
            AddressStatus::Allocated => c.allocated += 1,
            AddressStatus::NetBoxOnly => c.netbox_only += 1,
            AddressStatus::DnsOnly => c.dns_only += 1,
            AddressStatus::LiveUnregistered => c.live_unregistered += 1,
            AddressStatus::Conflict => c.conflict += 1,
        }
    }
    c
}

/// An IPv4 CIDR block, e.g. `10.87.3.0/24`, stored as base address + prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    /// The base address as written (not necessarily the network address).
    pub base: Ipv4Addr,
    /// The prefix length in bits, 0..=32.
    pub prefix_len: u8,
}

impl Cidr {
    /// Parse a CIDR string like `"10.87.3.0/24"`.
    ///
    /// # Errors
    /// Returns a human-readable message if the address or prefix length is invalid.
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let (addr, len) = s
            .split_once('/')
            .ok_or_else(|| format!("missing '/prefix' in {s:?}"))?;
        let base: Ipv4Addr = addr
            .parse()
            .map_err(|_| format!("invalid IPv4 address {addr:?}"))?;
        let prefix_len: u8 = len
            .parse()
            .map_err(|_| format!("invalid prefix length {len:?}"))?;
        if prefix_len > 32 {
            return Err(format!("prefix length {prefix_len} exceeds 32"));
        }
        Ok(Cidr { base, prefix_len })
    }

    /// The subnet mask as a `u32` (`/20` → `0xFFFF_F000`). A `/0` needs a special
    /// case because shifting a `u32` by 32 is undefined in Rust.
    fn mask(self) -> u32 {
        if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        }
    }

    /// The network address (base with the host bits cleared).
    #[must_use]
    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.base) & self.mask())
    }

    /// Whether `ip` lies inside this block.
    #[must_use]
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.base) & self.mask()
    }

    /// Iterate the **usable host** addresses of the block: for `/1`–`/30` we skip
    /// the network and broadcast addresses; `/31` yields both (RFC 3021) and `/32`
    /// the single address.
    #[must_use]
    pub fn hosts(self) -> impl Iterator<Item = Ipv4Addr> {
        let net = u32::from(self.base) & self.mask();
        let bcast = net | !self.mask();
        let (start, end) = match self.prefix_len {
            32 => (net, net),
            31 => (net, bcast),
            _ => (net + 1, bcast - 1),
        };
        (start..=end).map(Ipv4Addr::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small constructor to keep the known-case tests readable.
    fn facts(addr: &str, netbox: Option<Option<&str>>, ptr: Option<&str>, live: bool) -> AddressFacts {
        AddressFacts {
            addr: addr.parse().unwrap(),
            netbox: netbox.map(|dns| NetBoxRecord {
                dns_name: dns.map(str::to_string),
            }),
            ptr: ptr.map(str::to_string),
            live,
        }
    }

    #[test]
    fn free_address_is_free() {
        // 10.87.3.69 today: no PTR, no ping, not in NetBox → the one we allocated.
        let f = facts("10.87.3.69", None, None, false);
        assert_eq!(classify(&f), AddressStatus::Free);
        assert!(classify(&f).is_free());
    }

    #[test]
    fn dns_without_netbox_is_dns_only() {
        // 10.87.3.11 today: iprotect-keyreader has a PTR but NetBox never recorded it.
        let f = facts("10.87.3.11", None, Some("iprotect-keyreader.nfra.nl."), false);
        assert_eq!(classify(&f), AddressStatus::DnsOnly);
        assert!(!classify(&f).is_free());
    }

    #[test]
    fn live_but_unknown_is_squatter() {
        // 10.87.3.90 today: answered ARP, but no PTR and not in NetBox.
        let f = facts("10.87.3.90", None, None, true);
        assert_eq!(classify(&f), AddressStatus::LiveUnregistered);
    }

    #[test]
    fn netbox_and_matching_dns_is_allocated() {
        // Clean allocation: NetBox name and PTR agree (bar the trailing dot/case).
        let f = facts("10.87.3.68", Some(Some("dop21-ipmi.nfra.nl")), Some("DOP21-IPMI.nfra.nl."), true);
        assert_eq!(classify(&f), AddressStatus::Allocated);
    }

    #[test]
    fn netbox_reserved_without_ptr_is_netbox_only() {
        let f = facts("10.87.3.147", Some(None), None, false);
        assert_eq!(classify(&f), AddressStatus::NetBoxOnly);
    }

    #[test]
    fn disagreeing_names_are_a_conflict() {
        let f = facts("10.87.3.50", Some(Some("alpha.nfra.nl")), Some("beta.nfra.nl."), false);
        assert_eq!(classify(&f), AddressStatus::Conflict);
    }

    #[test]
    fn cidr_parse_and_host_counts() {
        let c24 = Cidr::parse("10.87.3.0/24").unwrap();
        assert_eq!(c24.hosts().count(), 254); // .1 – .254
        let c20 = Cidr::parse("10.87.0.0/20").unwrap();
        assert_eq!(c20.hosts().count(), 4094); // 4096 − network − broadcast
        assert!(c20.contains("10.87.3.69".parse().unwrap()));
        assert!(!c20.contains("10.87.16.1".parse().unwrap()));
        assert_eq!(c24.network(), "10.87.3.0".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn cidr_parse_rejects_bad_input() {
        assert!(Cidr::parse("10.87.3.0").is_err());
        assert!(Cidr::parse("10.87.3.0/33").is_err());
        assert!(Cidr::parse("not.an.ip/24").is_err());
    }

    #[test]
    fn reconcile_fills_gaps_as_free_and_counts() {
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let f = vec![
            facts("10.87.3.11", None, Some("iprotect-keyreader.nfra.nl."), false),
            facts("10.87.3.90", None, None, true),
            facts("10.87.3.68", Some(Some("dop21-ipmi.nfra.nl")), Some("dop21-ipmi.nfra.nl."), true),
        ];
        let rows = reconcile(range, &f);
        assert_eq!(rows.len(), 254);

        let c = counts(&rows);
        assert_eq!(c.dns_only, 1);
        assert_eq!(c.live_unregistered, 1);
        assert_eq!(c.allocated, 1);
        assert_eq!(c.free, 251);

        assert_eq!(first_free(&rows), Some("10.87.3.1".parse().unwrap()));
    }
}
