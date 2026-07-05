// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The DNS **estate** as a routing table: which server masters which zones. Built from
//! the config's `dns_servers`, it answers "who is authoritative for this forward name?"
//! and "who masters the reverse zone this address falls in?", so the live paths can
//! transfer (and, later, edit) each zone on the right server instead of assuming a
//! single box.
//!
//! Pure — no I/O of its own; it only *informs* the SSH calls the [`dns`](super::dns)
//! source makes. The matching rules are the standard DNS ones: **longest-suffix match**
//! for a forward name, **longest-prefix match** for a reverse block.

use std::net::IpAddr;

use crate::config::DnsServer;
use crate::reconcile::Cidr;

/// One server's routing entry: how to reach it and the zones it masters.
#[derive(Debug, Clone)]
pub struct EstateServer {
    /// Short label (e.g. `dns1`), for logs and the preview.
    pub name: String,
    /// The server's own hostname/IP — the `dig … @host` AXFR target.
    pub host: String,
    /// SSH vantage to reach it on; empty means "use the global vantage".
    pub vantage: String,
    /// SSH `ProxyJump` chain to reach it; empty means "use the global jump".
    pub jump: String,
    /// Forward zones mastered here, normalized (lower-case, no leading/trailing dot).
    pub forward_zones: Vec<String>,
    /// Reverse blocks mastered here, parsed as CIDRs.
    pub reverse_blocks: Vec<Cidr>,
}

impl EstateServer {
    /// The SSH host to reach this server on: its own `vantage`, or `default` when unset.
    #[must_use]
    pub fn vantage_or<'a>(&'a self, default: &'a str) -> &'a str {
        if self.vantage.is_empty() {
            default
        } else {
            &self.vantage
        }
    }

    /// The SSH `ProxyJump` chain to reach this server: its own `jump`, or `default` (the
    /// site-wide jump) when unset.
    #[must_use]
    pub fn jump_or<'a>(&'a self, default: &'a str) -> &'a str {
        if self.jump.is_empty() {
            default
        } else {
            &self.jump
        }
    }
}

/// The whole estate: the servers and their authoritative zones. Empty when the config
/// lists none, in which case callers keep the legacy single-vantage behaviour.
#[derive(Debug, Clone, Default)]
pub struct DnsEstate {
    servers: Vec<EstateServer>,
}

impl DnsEstate {
    /// Build the estate from the config's DNS-server list.
    ///
    /// How: copy each server, fold its forward zones to lower-case without a trailing
    /// dot, and parse its reverse blocks as CIDRs. Why normalize the forward zones — DNS
    /// is case-insensitive and zone names carry an optional trailing dot, so folding both
    /// turns suffix-matching into a plain string compare.
    ///
    /// Units: forward zones are domain suffixes (`nfra.nl`); reverse blocks are CIDRs
    /// (`10.0.0.0/8`).
    ///
    /// # Errors
    /// Fails if a `reverse_zones` entry is not a valid CIDR.
    pub fn from_config(servers: &[DnsServer]) -> anyhow::Result<DnsEstate> {
        let mut out = Vec::with_capacity(servers.len());
        for s in servers {
            let reverse_blocks = s
                .reverse_zones
                .iter()
                .map(|z| Cidr::parse(z).map_err(|e| anyhow::anyhow!("dns_server {:?}: bad reverse zone {z:?}: {e}", s.name)))
                .collect::<anyhow::Result<Vec<_>>>()?;
            out.push(EstateServer {
                name: s.name.clone(),
                host: s.host.clone(),
                vantage: s.vantage.clone(),
                jump: s.jump.clone(),
                forward_zones: s.forward_zones.iter().map(|z| normalize_zone(z)).collect(),
                reverse_blocks,
            });
        }
        Ok(DnsEstate { servers: out })
    }

    /// Whether the estate lists no servers. When true, the DNS source stays on its legacy
    /// single-`axfr_server` path (so behaviour is unchanged without a configured estate).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// The server that masters the reverse zone `addr` falls in — the one whose reverse
    /// block contains `addr` with the **longest prefix** — or `None` if no server claims
    /// it (the caller then falls back to the default AXFR server / resolver).
    ///
    /// Longest-prefix-match is the standard routing rule: the tightest block covering the
    /// address is its most specific authority. Units: `addr` is any address in the zone.
    #[must_use]
    pub fn reverse_owner(&self, addr: IpAddr) -> Option<&EstateServer> {
        self.servers
            .iter()
            .filter_map(|s| {
                s.reverse_blocks
                    .iter()
                    .filter(|b| b.contains(addr))
                    .map(|b| b.prefix_len)
                    .max()
                    .map(|p| (s, p))
            })
            .max_by_key(|(_, p)| *p)
            .map(|(s, _)| s)
    }

    /// The server authoritative for the forward `name` — the one whose forward zone is
    /// the **longest matching suffix** of the name — or `None` when none owns it (the
    /// caller then falls back to the default forward server).
    ///
    /// A zone `z` owns `name` when `name == z` or `name` ends with `.z`; among all such,
    /// the zone with the most labels wins, mirroring how DNS delegation nests
    /// (`a.sub.nfra.nl` prefers `sub.nfra.nl` over `nfra.nl`).
    ///
    /// No live caller yet — the forward write path (a later roadmap phase) will route its
    /// edits through this; it is exercised by the tests below.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn forward_owner(&self, name: &str) -> Option<&EstateServer> {
        let n = normalize_zone(name);
        self.servers
            .iter()
            .filter_map(|s| {
                s.forward_zones
                    .iter()
                    .filter(|z| zone_owns(z, &n))
                    .map(|z| label_count(z))
                    .max()
                    .map(|c| (s, c))
            })
            .max_by_key(|(_, c)| *c)
            .map(|(s, _)| s)
    }

    /// A one-line-per-server summary of the estate, for the operator to see which boxes
    /// canopy will use before a live run.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut s = String::new();
        for srv in &self.servers {
            let via = if srv.vantage.is_empty() { "default vantage" } else { srv.vantage.as_str() };
            let fwd = srv.forward_zones.join(", ");
            let rev = srv
                .reverse_blocks
                .iter()
                .map(|b| format!("{}/{}", b.base, b.prefix_len))
                .collect::<Vec<_>>()
                .join(", ");
            s.push_str(&format!("  {} (@{}, via {}) forward: [{fwd}] reverse: [{rev}]\n", srv.name, srv.host, via));
        }
        s
    }
}

/// Fold a zone or name for suffix matching: trim spaces, drop any leading/trailing dot,
/// and lower-case. DNS is case-insensitive and names may carry a trailing dot, so both
/// have to be folded away before two names can be compared.
fn normalize_zone(z: &str) -> String {
    z.trim().trim_matches('.').to_ascii_lowercase()
}

/// Whether the (already normalized) forward zone `zone` is authoritative for `name`:
/// they are equal, or `name` ends with `.zone`. An empty zone owns nothing.
fn zone_owns(zone: &str, name: &str) -> bool {
    !zone.is_empty() && (name == zone || name.ends_with(&format!(".{zone}")))
}

/// The number of dot-separated labels in a zone — its suffix length, used to pick the
/// longest (most specific) matching zone.
fn label_count(zone: &str) -> usize {
    if zone.is_empty() {
        0
    } else {
        zone.split('.').count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small estate: dns1 masters the two forward zones, ntserver1 masters all of 10/8,
    /// and a third server masters a tighter 10.87.0.0/16 to test longest-prefix wins.
    fn estate() -> DnsEstate {
        let servers = vec![
            DnsServer {
                name: "dns1".into(),
                host: "dns1.astron.nl".into(),
                vantage: String::new(),
                forward_zones: vec!["NFRA.nl.".into(), "astron.nl".into()],
                reverse_zones: vec![],
                ..DnsServer::default()
            },
            DnsServer {
                name: "ntserver1".into(),
                host: "ntserver1.nfra.nl".into(),
                vantage: "jump.astron.nl".into(),
                forward_zones: vec![],
                reverse_zones: vec!["10.0.0.0/8".into()],
                ..DnsServer::default()
            },
            DnsServer {
                name: "sub16".into(),
                host: "sub16.astron.nl".into(),
                vantage: String::new(),
                forward_zones: vec!["sub.nfra.nl".into()],
                reverse_zones: vec!["10.87.0.0/16".into()],
                ..DnsServer::default()
            },
        ];
        DnsEstate::from_config(&servers).unwrap()
    }

    #[test]
    fn forward_name_routes_to_its_zone_server() {
        let e = estate();
        // A host in nfra.nl → dns1. Case and trailing dot are folded away.
        assert_eq!(e.forward_owner("dop21-ipmi.NFRA.nl.").unwrap().name, "dns1");
        assert_eq!(e.forward_owner("www.astron.nl").unwrap().name, "dns1");
    }

    #[test]
    fn forward_longest_suffix_wins_and_unknown_falls_back() {
        let e = estate();
        // sub.nfra.nl (2 labels of overlap deeper) beats the broader nfra.nl on dns1.
        assert_eq!(e.forward_owner("host.sub.nfra.nl").unwrap().name, "sub16");
        // A name in no listed zone has no owner → caller uses the default server.
        assert!(e.forward_owner("host.example.com").is_none());
    }

    #[test]
    fn reverse_block_routes_to_its_master() {
        let e = estate();
        let a: IpAddr = "10.200.4.5".parse().unwrap(); // only inside 10/8
        assert_eq!(e.reverse_owner(a).unwrap().name, "ntserver1");
    }

    #[test]
    fn reverse_longest_prefix_wins_and_unknown_falls_back() {
        let e = estate();
        // 10.87.3.10 is in both 10/8 and 10.87/16 → the tighter /16 server wins.
        let inside: IpAddr = "10.87.3.10".parse().unwrap();
        assert_eq!(e.reverse_owner(inside).unwrap().name, "sub16");
        // An address outside every reverse block has no owner → default AXFR fallback.
        let outside: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(e.reverse_owner(outside).is_none());
    }

    #[test]
    fn vantage_falls_back_to_the_global_when_unset() {
        let e = estate();
        let dns1 = e.forward_owner("x.nfra.nl").unwrap();
        assert_eq!(dns1.vantage_or("global.host"), "global.host"); // dns1 has no own vantage
        let nt = e.reverse_owner("10.200.0.1".parse().unwrap()).unwrap();
        assert_eq!(nt.vantage_or("global.host"), "jump.astron.nl"); // ntserver1 has its own
    }

    #[test]
    fn bad_reverse_zone_is_an_error() {
        let servers = vec![DnsServer {
            name: "broken".into(),
            host: "h".into(),
            vantage: String::new(),
            forward_zones: vec![],
            reverse_zones: vec!["not-a-cidr".into()],
            ..DnsServer::default()
        }];
        assert!(DnsEstate::from_config(&servers).is_err());
    }
}
