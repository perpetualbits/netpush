// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Where facts come from. Each live source fills exactly **one** field of
//! [`AddressFacts`] (NetBox → `netbox`, DNS → `ptr`, probe → `live`); [`merge`]
//! unions them per address so the reconciler sees the full picture.
//!
//! Everything ASTRON-internal is unreachable except over SSH, so live sources run
//! their queries on a [`Vantage`] host (see `vantage`). The parsing of each source's
//! output is a pure function, unit-tested with captured samples — only the SSH call
//! itself is unavoidably live.

pub mod dns;
pub mod estate;
pub mod inventory;
pub mod netbox;
pub mod probe;
pub mod vantage;

use std::collections::BTreeMap;

use crate::reconcile::{AddressFacts, Cidr};

pub use vantage::Vantage;

/// Practical cap on an **address-by-address sweep** (the reverse-DNS `host` sweep and the
/// ping probe). Above this many addresses a sweep is skipped: it would be minutes of
/// per-address lookups, and — the reason it *crashed* — embedding that many addresses in a
/// single remote command overflows the OS argument-length limit (`E2BIG`). Bigger blocks
/// rely on AXFR (which transfers whole zones cheaply) and NetBox instead. ~a `/19` of IPv4.
pub const SWEEP_CAP: u128 = 8192;

/// A provider of facts about the addresses in a range.
pub trait FactSource {
    /// Gather this source's facts for every relevant address in `range`.
    ///
    /// # Errors
    /// Returns an error if the underlying query (SSH, HTTP, DNS) fails.
    fn gather(&self, range: &Cidr) -> anyhow::Result<Vec<AddressFacts>>;
}

/// Union several sources' facts into one list, keyed by address.
///
/// How: start each address blank, then let every source contribute only the field
/// it owns — a NetBox record, a PTR, or a live flag — so partial knowledge from
/// different sources combines instead of overwriting. Sorted by address on the way
/// out (via `BTreeMap`), ready to reconcile.
#[must_use]
pub fn merge(sources: Vec<Vec<AddressFacts>>) -> Vec<AddressFacts> {
    let mut map: BTreeMap<std::net::IpAddr, AddressFacts> = BTreeMap::new();
    for facts in sources {
        for f in facts {
            let e = map.entry(f.addr).or_insert_with(|| AddressFacts {
                addr: f.addr,
                netbox: None,
                ptr: None,
                live: false,
            });
            if f.netbox.is_some() {
                e.netbox = f.netbox;
            }
            if f.ptr.is_some() {
                e.ptr = f.ptr;
            }
            if f.live {
                e.live = true;
            }
        }
    }
    map.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcile::{classify, AddressStatus, NetBoxRecord};

    fn addr(oct: u8) -> std::net::IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 87, 3, oct))
    }

    #[test]
    fn merge_unions_fields_from_separate_sources() {
        // NetBox knows .68's name; DNS knows its PTR; probe saw it live.
        let from_netbox = vec![AddressFacts {
            addr: addr(68),
            netbox: Some(NetBoxRecord { dns_name: Some("dop21-ipmi.nfra.nl".into()) }),
            ptr: None,
            live: false,
        }];
        let from_dns = vec![AddressFacts {
            addr: addr(68),
            netbox: None,
            ptr: Some("dop21-ipmi.nfra.nl.".into()),
            live: false,
        }];
        let from_probe = vec![AddressFacts { addr: addr(68), netbox: None, ptr: None, live: true }];

        let merged = merge(vec![from_netbox, from_dns, from_probe]);
        assert_eq!(merged.len(), 1);
        let f = &merged[0];
        assert!(f.netbox.is_some() && f.ptr.is_some() && f.live);
        // With all three agreeing, the address reconciles to a clean allocation.
        assert_eq!(classify(f), AddressStatus::Allocated);
    }

    #[test]
    fn merge_keeps_distinct_addresses_sorted() {
        let a = vec![AddressFacts { addr: addr(90), netbox: None, ptr: None, live: true }];
        let b = vec![AddressFacts {
            addr: addr(11),
            netbox: None,
            ptr: Some("iprotect-keyreader.nfra.nl.".into()),
            live: false,
        }];
        let merged = merge(vec![a, b]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].addr, addr(11)); // sorted ascending
        assert_eq!(merged[1].addr, addr(90));
    }
}
