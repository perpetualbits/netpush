// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! A frozen snapshot of the real `10.87.3.0/24` observations from the takkie
//! iDRAC job, so the TUI runs and demonstrates every status **offline** — no
//! NetBox token or ASTRON connectivity required. Live sources (a NetBox client
//! and a DNS/probe reader) will replace this behind the same fact shape.

use crate::reconcile::{AddressFacts, Cidr, NetBoxRecord};
use std::net::Ipv4Addr;

/// Build the demo range and facts exactly as reconnaissance found them.
///
/// How: each entry records what the sources said for one address. Hosts with a PTR
/// but no NetBox object become `DnsOnly` (the drift we hit); the NetBox-only
/// reservations become `NetBoxOnly`; the ARP-only host becomes `LiveUnregistered`;
/// everything unlisted reconciles to `Free`.
pub fn demo() -> (Cidr, Vec<AddressFacts>) {
    let range = Cidr::parse("10.87.3.0/24").expect("valid CIDR");

    // (last octet, PTR name) — hosts with reverse DNS but absent from NetBox.
    let dns_only: &[(u8, &str)] = &[
        (52, "netapp-dw1-bmc.nfra.nl"),
        (54, "netapp-dw2-bmc.nfra.nl"),
        (62, "netapp-dw3-bmc.nfra.nl"),
        (63, "netapp-dw4-bmc.nfra.nl"),
        (68, "dop21-ipmi.nfra.nl"),
        (71, "ntserver56-ipmi.nfra.nl"),
        (73, "ntserver20-ipmi.nfra.nl"),
        (74, "ntserver69-ipmi.nfra.nl"),
        (75, "ntserver35-ipmi.nfra.nl"),
        (76, "dop75-ipmi.nfra.nl"),
        (77, "ntserver19-ipmi.nfra.nl"),
        (11, "iprotect-keyreader.nfra.nl"),
        (12, "iprotect-ipu8-kloklijn-dw.nfra.nl"),
        (13, "iprotect-terminal-dw.nfra.nl"),
        (14, "jivecam.nfra.nl"),
        (15, "instrum4.nfra.nl"),
    ];
    // NetBox-recorded reservations we saw with no matching PTR.
    let netbox_only: &[u8] = &[131, 132, 139, 140, 147];
    // Answered ARP but present in neither NetBox nor DNS — a squatter.
    let live_unregistered: &[u8] = &[90];

    let mut facts = Vec::new();
    for &(oct, ptr) in dns_only {
        facts.push(AddressFacts {
            addr: v4(oct),
            netbox: None,
            ptr: Some(format!("{ptr}.")),
            live: true,
        });
    }
    for &oct in netbox_only {
        facts.push(AddressFacts {
            addr: v4(oct),
            netbox: Some(NetBoxRecord { dns_name: None }),
            ptr: None,
            live: false,
        });
    }
    for &oct in live_unregistered {
        facts.push(AddressFacts {
            addr: v4(oct),
            netbox: None,
            ptr: None,
            live: true,
        });
    }
    (range, facts)
}

/// Make `10.87.3.<oct>`.
fn v4(oct: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 87, 3, oct)
}
