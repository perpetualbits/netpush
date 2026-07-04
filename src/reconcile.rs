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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    /// The address these facts describe (IPv4 or IPv6).
    pub addr: IpAddr,
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
    /// The address (IPv4 or IPv6).
    pub addr: IpAddr,
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

/// The reconciled row for one set of facts: its verdict and best display name.
#[must_use]
pub fn row_from_facts(facts: &AddressFacts) -> AddressRow {
    AddressRow { addr: facts.addr, status: classify(facts), name: best_name(facts) }
}

/// The reconciled row for the address at `index` in `range`, looked up in `facts`.
///
/// This is the lazy, `O(1)` core of pagination: the address is computed by
/// arithmetic ([`Cidr::host_at`]) and classified from the (bounded) fact map, so a
/// caller can render just the visible window of a `/8` without building 16M rows.
/// An address absent from `facts` is `Free`.
#[must_use]
pub fn reconcile_at(range: Cidr, facts: &HashMap<IpAddr, AddressFacts>, index: u128) -> AddressRow {
    let addr = range.host_at(index);
    match facts.get(&addr) {
        Some(f) => row_from_facts(f),
        None => AddressRow { addr, status: AddressStatus::Free, name: None },
    }
}

/// Build the reconciled table for every usable host address in `range`.
///
/// How: index `facts` by address, then walk every host address in the CIDR;
/// addresses with no facts default to `Free`. Materializes the whole range, so it is a
/// **test-only** oracle for [`reconcile_at`]; production code reconciles lazily
/// (a v6 range would be `2^128` rows).
#[cfg(test)]
#[must_use]
pub fn reconcile(range: Cidr, facts: &[AddressFacts]) -> Vec<AddressRow> {
    let by_addr: HashMap<IpAddr, &AddressFacts> =
        facts.iter().map(|f| (f.addr, f)).collect();

    range
        .hosts()
        .map(|addr| match by_addr.get(&addr) {
            Some(f) => row_from_facts(f),
            None => AddressRow { addr, status: AddressStatus::Free, name: None },
        })
        .collect()
}

/// A tally of how many addresses fall into each status — for the header bar.
///
/// Counts are `u128` because a sparse IPv6 range's `free` count can reach `2^128`; the
/// non-free buckets are bounded by the (small) fact set but share the type for uniformity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Number of `Free` addresses.
    pub free: u128,
    /// Number of `Allocated` addresses.
    pub allocated: u128,
    /// Number of `NetBoxOnly` addresses.
    pub netbox_only: u128,
    /// Number of `DnsOnly` addresses.
    pub dns_only: u128,
    /// Number of `LiveUnregistered` addresses.
    pub live_unregistered: u128,
    /// Number of `Conflict` addresses.
    pub conflict: u128,
}

/// Tally one status into `c`.
fn tally(c: &mut Counts, status: AddressStatus) {
    match status {
        AddressStatus::Free => c.free += 1,
        AddressStatus::Allocated => c.allocated += 1,
        AddressStatus::NetBoxOnly => c.netbox_only += 1,
        AddressStatus::DnsOnly => c.dns_only += 1,
        AddressStatus::LiveUnregistered => c.live_unregistered += 1,
        AddressStatus::Conflict => c.conflict += 1,
    }
}

/// Tally the status counts for a whole range **without enumerating it**: classify
/// the (bounded) known facts, then treat every remaining address as `Free`.
///
/// `free = total − known-non-free`, so a mostly-empty `/8` is counted in O(facts),
/// not O(16M). A stray fact that itself classifies `Free` is handled correctly.
#[must_use]
pub fn counts_from_facts(total: u128, facts: &HashMap<IpAddr, AddressFacts>) -> Counts {
    let mut c = Counts::default();
    let mut free_known = 0u128;
    for f in facts.values() {
        let status = classify(f);
        tally(&mut c, status);
        if status == AddressStatus::Free {
            free_known += 1;
        }
    }
    // The addresses no source mentioned are all free; add them to any already tallied.
    let unknown = total.saturating_sub(facts.len() as u128);
    c.free = unknown + free_known;
    c
}

/// A subnet as NetBox defines it: a CIDR block with a human label. Unlike the map's
/// Hilbert cells (fixed-length at each zoom level), real subnets have **varying** prefix
/// lengths, so several may nest around a single address — the /26 you're in sits inside
/// a /24 sits inside a /20.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subnet {
    /// The block, e.g. `10.87.3.0/26`.
    pub cidr: Cidr,
    /// A human label (NetBox description, role, or VLAN name); may be empty.
    pub name: String,
}

impl Subnet {
    /// The most-specific (longest-prefix) subnet in `subnets` that contains `addr`, or
    /// `None` if none covers it.
    ///
    /// How: keep every subnet whose block contains `addr`, then take the one with the
    /// largest `prefix_len`. Longest-prefix-match is the standard rule — the tightest
    /// real subnet an address sits in is the most useful "where am I".
    #[must_use]
    pub fn most_specific(subnets: &[Subnet], addr: IpAddr) -> Option<&Subnet> {
        subnets
            .iter()
            .filter(|s| s.cidr.contains(addr))
            .max_by_key(|s| s.cidr.prefix_len)
    }
}

/// A CIDR block — **IPv4 or IPv6** — as base address + prefix length, e.g.
/// `10.87.3.0/24` or `2001:db8::/48`.
///
/// All the arithmetic runs on the address as a `u128` (IPv4 lives in the low 32 bits),
/// so a single code path serves both families; the `base`'s variant records the width
/// (32 vs 128 bits). Counts are `u128` because an IPv6 block can hold up to `2^128`
/// addresses — far more than any list could hold, so views treat a block bigger than
/// [`ENUMERATION_CAP`] as *sparse* (see [`is_enumerable`](Cidr::is_enumerable)) and show
/// only the addresses some source actually reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    /// The base address as written (not necessarily the network address).
    pub base: IpAddr,
    /// The prefix length in bits: `0..=32` for IPv4, `0..=128` for IPv6.
    pub prefix_len: u8,
}

/// Above this many addresses a block is **sparse**: too large to list every address, so
/// views show only the known ones. `2^32` keeps every IPv4 block enumerable (a `/0` is
/// 4 G rows, still lazy-cheap) while any IPv6 block wider than a `/96` goes sparse.
pub const ENUMERATION_CAP: u128 = 1 << 32;

impl Cidr {
    /// Parse a CIDR string like `"10.87.3.0/24"` or `"2001:db8::/48"`.
    ///
    /// # Errors
    /// Returns a human-readable message if the address or prefix length is invalid, or
    /// the prefix exceeds the address family's width (32 for IPv4, 128 for IPv6).
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let (addr, len) = s.split_once('/').ok_or_else(|| format!("missing '/prefix' in {s:?}"))?;
        let base: IpAddr = addr.parse().map_err(|_| format!("invalid IP address {addr:?}"))?;
        let prefix_len: u8 = len.parse().map_err(|_| format!("invalid prefix length {len:?}"))?;
        let max = if base.is_ipv6() { 128 } else { 32 };
        if u32::from(prefix_len) > max {
            return Err(format!("prefix length {prefix_len} exceeds {max}"));
        }
        Ok(Cidr { base, prefix_len })
    }

    /// Whether this is an IPv6 block.
    #[must_use]
    pub fn is_v6(self) -> bool {
        self.base.is_ipv6()
    }

    /// The address width in bits — 32 for IPv4, 128 for IPv6.
    #[must_use]
    pub fn width(self) -> u32 {
        if self.is_v6() {
            128
        } else {
            32
        }
    }

    /// The number of host bits below the prefix (`width − prefix`).
    #[must_use]
    pub fn host_bits(self) -> u32 {
        self.width() - u32::from(self.prefix_len)
    }

    /// The base address as a `u128` (IPv4 in the low 32 bits).
    fn value(self) -> u128 {
        match self.base {
            IpAddr::V4(a) => u128::from(u32::from(a)),
            IpAddr::V6(a) => u128::from(a),
        }
    }

    /// Rebuild an address of this block's family from a `u128` value.
    fn to_addr(self, v: u128) -> IpAddr {
        if self.is_v6() {
            IpAddr::V6(Ipv6Addr::from(v))
        } else {
            IpAddr::V4(Ipv4Addr::from(v as u32))
        }
    }

    /// The host mask: the low `host_bits` bits set (`block_len − 1`), saturating for a
    /// `/0` where the whole width is host bits.
    fn hostmask(self) -> u128 {
        let hb = self.host_bits();
        if hb >= 128 {
            u128::MAX
        } else {
            (1u128 << hb) - 1
        }
    }

    /// The network mask over the address width (host bits cleared, upper bits beyond the
    /// family's width left zero).
    fn mask(self) -> u128 {
        let width_mask = if self.is_v6() { u128::MAX } else { u128::from(u32::MAX) };
        width_mask & !self.hostmask()
    }

    /// The network address (base with the host bits cleared).
    #[must_use]
    pub fn network(self) -> IpAddr {
        self.to_addr(self.value() & self.mask())
    }

    /// The last address of the block (network with all host bits set).
    #[must_use]
    pub fn last(self) -> IpAddr {
        self.to_addr((self.value() & self.mask()) | self.hostmask())
    }

    /// Whether `ip` lies inside this block. A mismatched address family is never inside.
    #[must_use]
    pub fn contains(self, ip: IpAddr) -> bool {
        if ip.is_ipv6() != self.is_v6() {
            return false;
        }
        let v = match ip {
            IpAddr::V4(a) => u128::from(u32::from(a)),
            IpAddr::V6(a) => u128::from(a),
        };
        (v & self.mask()) == (self.value() & self.mask())
    }

    /// The total number of addresses in the block — `2^host_bits`, a clean power of two
    /// (all addresses, no host/broadcast exclusion). This is the **map's** addressing
    /// space; it tiles evenly into CIDR quadrants, which the space-filling layout needs.
    /// Saturates to `u128::MAX` for a `/0`, whose `2^128` does not fit.
    #[must_use]
    pub fn block_len(self) -> u128 {
        let hb = self.host_bits();
        if hb >= 128 {
            u128::MAX
        } else {
            1u128 << hb
        }
    }

    /// The offset of `addr` within the block (`addr − network`), or `None` if `addr` is
    /// outside the block (including a mismatched family).
    #[must_use]
    pub fn offset_of(self, addr: IpAddr) -> Option<u128> {
        if !self.contains(addr) {
            return None;
        }
        let v = match addr {
            IpAddr::V4(a) => u128::from(u32::from(a)),
            IpAddr::V6(a) => u128::from(a),
        };
        Some(v - (self.value() & self.mask()))
    }

    /// The address at `offset` within the block (`network + offset`), clamped to the last
    /// address of the block.
    #[must_use]
    pub fn address_at_offset(self, offset: u128) -> IpAddr {
        let net = self.value() & self.mask();
        let last = net | self.hostmask();
        self.to_addr(net.saturating_add(offset).min(last))
    }

    /// The inclusive `(first, last)` usable-host address bounds, as `u128`.
    ///
    /// IPv6 has no broadcast, so every address in the block is usable. For IPv4, `/1`–`/30`
    /// skip the network and broadcast addresses; `/31` uses both (RFC 3021) and `/32` the
    /// single address. This is the arithmetic shared by [`hosts`](Cidr::hosts),
    /// [`host_count`](Cidr::host_count) and [`host_at`](Cidr::host_at).
    fn host_bounds(self) -> (u128, u128) {
        let net = self.value() & self.mask();
        let last = net | self.hostmask();
        if self.is_v6() {
            return (net, last);
        }
        match self.prefix_len {
            32 => (net, net),
            31 => (net, last),
            _ => (net + 1, last - 1),
        }
    }

    /// How many usable host addresses the block has — computed by arithmetic, so a `/8`
    /// (16 M hosts) is as cheap to size as a `/24`. Saturates for enormous IPv6 blocks.
    #[must_use]
    pub fn host_count(self) -> u128 {
        let (s, e) = self.host_bounds();
        (e - s).saturating_add(1)
    }

    /// Whether the block is small enough to list every address (≤ [`ENUMERATION_CAP`]).
    /// Large IPv6 blocks are not: views fall back to showing only the known addresses.
    #[must_use]
    pub fn is_enumerable(self) -> bool {
        self.host_count() <= ENUMERATION_CAP
    }

    /// The `index`-th usable host address (0-based), clamped to the last host.
    ///
    /// `O(1)` — the basis for lazily rendering only the visible slice of a range without
    /// ever materializing all of it.
    #[must_use]
    pub fn host_at(self, index: u128) -> IpAddr {
        let (s, e) = self.host_bounds();
        self.to_addr(s.saturating_add(index).min(e))
    }

    /// The 0-based host index of `addr`, or `None` if it is not a usable host of the
    /// block — the inverse of [`host_at`](Cidr::host_at).
    #[must_use]
    pub fn host_index(self, addr: IpAddr) -> Option<u128> {
        if addr.is_ipv6() != self.is_v6() {
            return None;
        }
        let (s, e) = self.host_bounds();
        let a = match addr {
            IpAddr::V4(x) => u128::from(u32::from(x)),
            IpAddr::V6(x) => u128::from(x),
        };
        (a >= s && a <= e).then_some(a - s)
    }

    /// Iterate the usable host addresses of the block.
    ///
    /// **Only call this on an [enumerable](Cidr::is_enumerable) block** — a large IPv6
    /// block would yield astronomically many addresses. Callers that sweep addresses
    /// (DNS, probe) must gate on `is_enumerable` first.
    #[must_use]
    pub fn hosts(self) -> impl Iterator<Item = IpAddr> {
        let (start, end) = self.host_bounds();
        (start..=end).map(move |v| self.to_addr(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_parse_contains_and_counts() {
        let c = Cidr::parse("2001:db8::/48").unwrap();
        assert!(c.is_v6());
        assert_eq!(c.width(), 128);
        assert_eq!(c.host_bits(), 80);
        assert_eq!(c.network(), "2001:db8::".parse::<IpAddr>().unwrap());
        assert!(c.contains("2001:db8:0:1234::5".parse().unwrap()));
        assert!(!c.contains("2001:db9::1".parse().unwrap())); // outside
        assert!(!c.contains("10.0.0.1".parse().unwrap())); // wrong family
        assert_eq!(c.block_len(), 1u128 << 80);
        assert!(!c.is_enumerable()); // 2^80 addresses → sparse
    }

    #[test]
    fn ipv6_small_prefix_is_enumerable_with_all_addresses_usable() {
        let c = Cidr::parse("2001:db8::/126").unwrap(); // 4 addresses
        assert!(c.is_enumerable());
        assert_eq!(c.host_count(), 4); // IPv6 keeps the network/all-ones addresses
        assert_eq!(c.host_at(0), "2001:db8::".parse::<IpAddr>().unwrap());
        assert_eq!(c.host_at(3), "2001:db8::3".parse::<IpAddr>().unwrap());
        assert_eq!(c.last(), "2001:db8::3".parse::<IpAddr>().unwrap());
        assert_eq!(c.host_index("2001:db8::2".parse().unwrap()), Some(2));
    }

    #[test]
    fn slash_zero_ipv6_saturates_rather_than_overflowing() {
        let c = Cidr::parse("::/0").unwrap();
        assert_eq!(c.host_count(), u128::MAX); // 2^128 doesn't fit — saturates
        assert!(!c.is_enumerable());
        assert!(c.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn most_specific_subnet_is_the_longest_prefix_match() {
        let sub = |c: &str, n: &str| Subnet { cidr: Cidr::parse(c).unwrap(), name: n.into() };
        let subs = vec![
            sub("10.87.0.0/20", "mgmt"),
            sub("10.87.3.0/24", "control"),
            sub("10.87.3.0/26", "ipmi"),
        ];
        // .10 is in all three → the /26 wins (longest prefix).
        let a = "10.87.3.10".parse().unwrap();
        assert_eq!(Subnet::most_specific(&subs, a).unwrap().name, "ipmi");
        // .200 is in the /24 and /20 but not the /26 → the /24 wins.
        let b = "10.87.3.200".parse().unwrap();
        assert_eq!(Subnet::most_specific(&subs, b).unwrap().name, "control");
        // Outside every subnet → None.
        let c = "10.99.0.1".parse().unwrap();
        assert!(Subnet::most_specific(&subs, c).is_none());
    }

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
        assert_eq!(c24.network(), "10.87.3.0".parse::<IpAddr>().unwrap());
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

        let map: HashMap<IpAddr, AddressFacts> = f.iter().cloned().map(|x| (x.addr, x)).collect();
        let c = counts_from_facts(range.host_count(), &map);
        assert_eq!(c.dns_only, 1);
        assert_eq!(c.live_unregistered, 1);
        assert_eq!(c.allocated, 1);
        assert_eq!(c.free, 251);

        // The lowest free address is .1 (nothing claims it).
        assert_eq!(rows.iter().find(|r| r.status.is_free()).map(|r| r.addr), Some("10.87.3.1".parse().unwrap()));
    }

    #[test]
    fn host_arithmetic_is_cheap_and_consistent() {
        let c24 = Cidr::parse("10.87.3.0/24").unwrap();
        assert_eq!(c24.host_count() as usize, c24.hosts().count());
        assert_eq!(c24.host_at(0), "10.87.3.1".parse::<IpAddr>().unwrap());
        assert_eq!(c24.host_at(67), "10.87.3.68".parse::<IpAddr>().unwrap());
        assert_eq!(c24.host_index("10.87.3.68".parse().unwrap()), Some(67));
        assert_eq!(c24.host_index("10.87.4.1".parse().unwrap()), None); // outside

        // A /8 is sized and addressed by arithmetic — no iteration.
        let c8 = Cidr::parse("10.0.0.0/8").unwrap();
        assert_eq!(c8.host_count(), 16_777_214); // 2^24 − 2
        assert_eq!(c8.host_at(0), "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(c8.host_at(16_777_213), "10.255.255.254".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn lazy_reconcile_matches_the_full_pass() {
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let f = vec![
            facts("10.87.3.11", None, Some("iprotect-keyreader.nfra.nl."), false),
            facts("10.87.3.90", None, None, true),
            facts("10.87.3.68", Some(Some("dop21-ipmi.nfra.nl")), Some("dop21-ipmi.nfra.nl."), true),
        ];
        let map: HashMap<IpAddr, AddressFacts> = f.iter().cloned().map(|x| (x.addr, x)).collect();
        let full = reconcile(range, &f);
        // reconcile_at(i) reproduces the full pass, address by address.
        for i in 0..range.host_count() {
            assert_eq!(reconcile_at(range, &map, i), full[i as usize]);
        }
        // And counts_from_facts matches the full pass — without enumerating it.
        let mut expected = Counts::default();
        for r in &full {
            tally(&mut expected, r.status);
        }
        assert_eq!(counts_from_facts(range.host_count(), &map), expected);
    }
}
