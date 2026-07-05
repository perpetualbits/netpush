// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Discover the **DNS estate** — which server masters which zones — by asking DNS itself.
//!
//! For each forward domain (derived from NetBox `dns_name`s) and each reverse block (the
//! surveyed prefixes) canopy runs `dig SOA` on the vantage and reads the zone apex and its
//! **primary master** (the SOA `MNAME`). Grouping the masters with the zones they own
//! yields `[[dns_servers]]` entries you can save into the site config, so a later `--live`
//! routes zone transfers to the right box.
//!
//! Only [`discover_dns_servers`] runs `dig`; everything else here is pure and unit-tested.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::{Config, DnsServer};
use crate::reconcile::Cidr;
use crate::sources::netbox::NetboxSource;
use crate::sources::Vantage;

/// Fold a DNS name for comparison/storage: drop a trailing dot and lower-case it.
fn fold(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// The `(zone apex, primary master)` from a `dig` response's SOA record, or `None`.
///
/// How: scan the answer/authority lines for the one carrying `SOA` — its owner is the
/// zone apex and the token just after `SOA` is the `MNAME` (the primary master). Comment
/// and question lines (starting `;`) are skipped, so a `dig SOA <host>` on a non-apex name
/// still yields the containing zone from the authority section.
#[must_use]
pub fn parse_soa(output: &str) -> Option<(String, String)> {
    for line in output.lines() {
        if line.starts_with(';') {
            continue; // dig comment / question line
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let Some(i) = f.iter().position(|&t| t == "SOA") else {
            continue;
        };
        if let (Some(apex), Some(mname)) = (f.first(), f.get(i + 1)) {
            return Some((fold(apex), fold(mname)));
        }
    }
    None
}

/// The parent domain of a name — drop the leftmost label: `dop21.nfra.nl` → `nfra.nl`.
/// `None` for a bare label (no dot). Used to turn a host's `dns_name` into a candidate
/// zone to look up; the SOA response then reveals the true apex regardless.
#[must_use]
pub fn parent_domain(name: &str) -> Option<String> {
    fold(name).split_once('.').map(|(_, rest)| rest.to_string())
}

/// The reverse-DNS name for an address: `10.87.3.1` → `1.3.87.10.in-addr.arpa`, and an
/// IPv6 address → its 32-nibble `…​.ip6.arpa` name. `dig SOA` on it returns the reverse
/// zone that covers the address.
#[must_use]
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let mut s = String::new();
            for b in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

/// The CIDR block a reverse-zone apex covers: `10.in-addr.arpa` → `10.0.0.0/8`,
/// `87.10.in-addr.arpa` → `10.87.0.0/16`, and an `…​.ip6.arpa` apex → its nibble prefix.
/// `None` for a name that is not a reverse zone. The inverse of [`reverse_name`]'s zone cut.
#[must_use]
pub fn reverse_zone_to_cidr(apex: &str) -> Option<Cidr> {
    let z = fold(apex);
    if let Some(labels) = z.strip_suffix(".in-addr.arpa") {
        let octs: Vec<u8> = labels.split('.').map(|p| p.parse().ok()).collect::<Option<_>>()?;
        if octs.is_empty() || octs.len() > 4 {
            return None;
        }
        let mut b = [0u8; 4];
        for (i, o) in octs.iter().rev().enumerate() {
            b[i] = *o; // labels are the network octets, most-significant last
        }
        return Some(Cidr { base: IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])), prefix_len: (octs.len() * 8) as u8 });
    }
    if let Some(labels) = z.strip_suffix(".ip6.arpa") {
        let nibs: Vec<u8> =
            labels.split('.').map(|p| u8::from_str_radix(p, 16).ok().filter(|n| *n < 16)).collect::<Option<_>>()?;
        if nibs.is_empty() || nibs.len() > 32 {
            return None;
        }
        let val = nibs.iter().enumerate().fold(0u128, |acc, (k, &n)| acc | (u128::from(n) << (4 * k)));
        let bits = (nibs.len() as u32) * 4;
        return Some(Cidr { base: IpAddr::V6(Ipv6Addr::from(val << (128 - bits))), prefix_len: bits as u8 });
    }
    None
}

/// Render discovered servers as a `[[dns_servers]]` TOML block for the site config,
/// omitting empty fields. Pure, so the exact text is testable and diffable.
#[must_use]
pub fn render_dns_servers(servers: &[DnsServer]) -> String {
    let list = |zs: &[String]| zs.iter().map(|z| format!("{z:?}")).collect::<Vec<_>>().join(", ");
    let mut s = String::new();
    for sv in servers {
        s.push_str("[[dns_servers]]\n");
        s.push_str(&format!("name = {:?}\n", sv.name));
        s.push_str(&format!("host = {:?}\n", sv.host));
        if !sv.forward_zones.is_empty() {
            s.push_str(&format!("forward_zones = [{}]\n", list(&sv.forward_zones)));
        }
        if !sv.reverse_zones.is_empty() {
            s.push_str(&format!("reverse_zones = [{}]\n", list(&sv.reverse_zones)));
        }
        s.push('\n');
    }
    s
}

/// The short label for a server: the first label of its hostname (`dns1.astron.nl` → `dns1`).
fn short_name(host: &str) -> String {
    host.split('.').next().unwrap_or(host).to_string()
}

/// Whether `host` belongs to the site — its name sits under one of the `owned` domains
/// (`ns1.lofar.eu` under `lofar.eu`). An empty `owned` list means "keep everything" (no
/// ownership configured). Used to drop servers a NetBox merely refers to (SURFnet's reverse
/// master for a delegated block, a peer university, a root/blackhole server).
fn is_ours(host: &str, owned: &[String]) -> bool {
    if owned.is_empty() {
        return true;
    }
    let h = fold(host);
    owned.iter().any(|d| h == *d || h.ends_with(&format!(".{d}")))
}

/// Assemble the per-master forward and reverse zone maps into sorted [`DnsServer`] entries.
fn assemble(fwd: &BTreeMap<String, BTreeSet<String>>, rev: &BTreeMap<String, BTreeSet<String>>) -> Vec<DnsServer> {
    let hosts: BTreeSet<&String> = fwd.keys().chain(rev.keys()).collect();
    hosts
        .into_iter()
        .map(|host| DnsServer {
            name: short_name(host),
            host: host.clone(),
            vantage: String::new(),
            jump: String::new(),
            forward_zones: fwd.get(host).map(|s| s.iter().cloned().collect()).unwrap_or_default(),
            reverse_zones: rev.get(host).map(|s| s.iter().cloned().collect()).unwrap_or_default(),
        })
        .collect()
}

/// Discover the DNS estate **live**: the servers mastering the forward domains in NetBox
/// and the reverse zones of the surveyed `blocks`, as `[[dns_servers]]` entries.
///
/// How: collect candidate forward zones from NetBox `dns_name`s (each name's parent
/// domain), and `dig SOA` each via the vantage to find its apex + master. For reverse,
/// `dig SOA` one address per block, skipping any block already covered by a reverse zone
/// we found — so each reverse zone is looked up once, not once per block. Group the masters
/// with the zones they own.
///
/// # Errors
/// Propagates the NetBox fetch failure. Individual `dig` failures are skipped (a server we
/// cannot reach just does not appear), so one dead zone does not abort discovery.
pub fn discover_dns_servers(cfg: &Config, token: &str, blocks: &[Cidr]) -> anyhow::Result<Vec<DnsServer>> {
    let vantage = Vantage::with_jump(&cfg.vantage, &cfg.jump);
    let netbox = NetboxSource { vantage: vantage.clone(), base_url: cfg.netbox_url.clone(), token: token.to_string() };

    let owned: Vec<String> = cfg.domains.iter().map(|d| fold(d)).collect();
    let mut fwd: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut rev: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    // Forward candidates: the owned domains (so an owned zone is probed even if no NetBox
    // host names it — the reason lofar.eu was missing), plus each NetBox dns_name's parent.
    let mut candidates: BTreeSet<String> = owned.iter().cloned().collect();
    candidates.extend(netbox.gather_dns_names()?.iter().filter_map(|n| parent_domain(n)));
    for zone in &candidates {
        if let Ok(out) = vantage.run(&format!("dig SOA {zone}")) {
            if let Some((apex, master)) = parse_soa(&out) {
                if is_ours(&master, &owned) {
                    fwd.entry(master).or_default().insert(apex);
                }
            }
        }
    }

    // Reverse: one SOA lookup per block, but skip a block already inside a reverse zone we
    // have already found (all 10.x blocks resolve to the same 10.in-addr.arpa, say). Zones
    // mastered off-site (a SURFnet-delegated reverse block) are dropped by the owned filter.
    let mut covered: Vec<Cidr> = Vec::new();
    for b in blocks {
        let net = b.network();
        if covered.iter().any(|c| c.contains(net)) {
            continue;
        }
        if let Ok(out) = vantage.run(&format!("dig SOA {}", reverse_name(net))) {
            if let Some((apex, master)) = parse_soa(&out) {
                if let Some(cidr) = reverse_zone_to_cidr(&apex) {
                    covered.push(cidr); // mark covered even if foreign, so we don't re-probe it
                    if is_ours(&master, &owned) {
                        rev.entry(master).or_default().insert(format!("{}/{}", cidr.base, cidr.prefix_len));
                    }
                }
            }
        }
    }

    Ok(assemble(&fwd, &rev))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_soa_apex_and_master() {
        // A real dig SOA: comment/question lines skipped, the SOA record read.
        let out = "\
; <<>> DiG <<>> SOA nfra.nl
;nfra.nl.\t\t\tIN\tSOA
nfra.nl.\t\t3600\tIN\tSOA\tdns1.astron.nl. hostmaster.astron.nl. 2026070300 3600 900 604800 3600";
        assert_eq!(parse_soa(out), Some(("nfra.nl".to_string(), "dns1.astron.nl".to_string())));
    }

    #[test]
    fn parses_soa_from_the_authority_section_for_a_host() {
        // dig SOA on a non-apex host: the SOA sits in the authority section.
        let out = "\
;host.sub.nfra.nl.\t\tIN\tSOA
nfra.nl.\t\t900\tIN\tSOA\tDNS1.astron.nl. root.nfra.nl. 42 1 2 3 4";
        assert_eq!(parse_soa(out), Some(("nfra.nl".to_string(), "dns1.astron.nl".to_string())));
    }

    #[test]
    fn parent_domain_drops_the_leftmost_label() {
        assert_eq!(parent_domain("dop21-ipmi.NFRA.nl."), Some("nfra.nl".to_string()));
        assert_eq!(parent_domain("a.control.lofar"), Some("control.lofar".to_string()));
        assert_eq!(parent_domain("bare"), None); // no dot → no parent
    }

    #[test]
    fn reverse_name_round_trips_through_the_zone_cut() {
        assert_eq!(reverse_name("10.87.3.1".parse().unwrap()), "1.3.87.10.in-addr.arpa");
        // The zone apex a lookup returns maps back to the block it covers.
        assert_eq!(reverse_zone_to_cidr("10.in-addr.arpa"), Some(Cidr::parse("10.0.0.0/8").unwrap()));
        assert_eq!(reverse_zone_to_cidr("87.10.in-addr.arpa"), Some(Cidr::parse("10.87.0.0/16").unwrap()));
        assert!(reverse_zone_to_cidr("nfra.nl").is_none()); // not a reverse zone
    }

    #[test]
    fn ipv6_reverse_name_and_zone_cut() {
        // The apex of an ip6.arpa zone maps back to its nibble prefix.
        assert_eq!(
            reverse_zone_to_cidr("a.a.a.a.8.b.d.0.1.0.0.2.ip6.arpa"),
            Some(Cidr::parse("2001:db8:aaaa::/48").unwrap())
        );
    }

    #[test]
    fn ownership_filters_foreign_servers() {
        let owned = vec!["astron.nl".to_string(), "lofar.eu".to_string(), "control.lofar".to_string()];
        // Ours: name sits under an owned domain (case/dot folded).
        assert!(is_ours("ns1.lofar.eu", &owned));
        assert!(is_ours("lcs020.control.lofar", &owned));
        assert!(is_ours("DNS1.ASTRON.NL.", &owned));
        // Not ours: the servers your NetBox merely refers to.
        assert!(!is_ours("ns1.surfnet.nl", &owned));
        assert!(!is_ours("ns1.utwente.nl", &owned));
        assert!(!is_ours("a.root-servers.net", &owned));
        assert!(!is_ours("localhost", &owned));
        // A near-miss must not match on a bare TLD suffix.
        assert!(!is_ours("evil-astron.nl", &owned)); // not ".astron.nl"
        // Empty owned list = keep everything (no ownership configured).
        assert!(is_ours("ns1.surfnet.nl", &[]));
    }

    #[test]
    fn renders_toml_omitting_empty_fields() {
        let servers = vec![
            DnsServer {
                name: "dns1".into(),
                host: "dns1.astron.nl".into(),
                vantage: String::new(),
                jump: String::new(),
                forward_zones: vec!["nfra.nl".into(), "astron.nl".into()],
                reverse_zones: vec![],
            },
            DnsServer {
                name: "ntserver1".into(),
                host: "ntserver1.nfra.nl".into(),
                vantage: String::new(),
                jump: String::new(),
                forward_zones: vec![],
                reverse_zones: vec!["10.0.0.0/8".into()],
            },
        ];
        let toml = render_dns_servers(&servers);
        assert!(toml.contains("[[dns_servers]]\nname = \"dns1\"\nhost = \"dns1.astron.nl\"\nforward_zones = [\"nfra.nl\", \"astron.nl\"]\n"));
        assert!(toml.contains("reverse_zones = [\"10.0.0.0/8\"]"));
        assert!(!toml.contains("vantage =")); // empty fields omitted
        // What we render must parse back as a valid config fragment.
        let parsed: crate::config::Config = toml::from_str(&toml).unwrap();
        assert_eq!(parsed.dns_servers.len(), 2);
        assert_eq!(parsed.dns_servers[0].forward_zones, vec!["nfra.nl", "astron.nl"]);
    }
}
