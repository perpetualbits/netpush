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

/// A label for a server built from the first `labels` of its hostname, joined by `-`
/// (`lcs020.control.lofar`, 2 → `lcs020-control`). Used to name servers uniquely when the
/// bare first label collides (two `lcs020.*` hosts).
fn label_name(host: &str, labels: usize) -> String {
    host.split('.').take(labels.max(1)).collect::<Vec<_>>().join("-")
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

/// A server's zones as `(forward domains, reverse CIDRs)`, accumulated from either source.
type ServerZones = (BTreeSet<String>, BTreeSet<String>);

/// Assemble the per-host zone map into sorted [`DnsServer`] entries, keeping only servers
/// under an `owned` domain and dropping any left with no zones. Each server is named by its
/// bare first label, or more labels when that would collide (`lcs020.control.lofar` /
/// `lcs020.offline.lofar` → `lcs020-control` / `lcs020-offline`).
fn assemble(zones: &BTreeMap<String, ServerZones>, owned: &[String]) -> Vec<DnsServer> {
    let hosts: Vec<&String> = zones.keys().filter(|h| is_ours(h, owned)).collect();
    // How many hosts share each bare first label — >1 means we must disambiguate.
    let mut first_label_counts: BTreeMap<String, usize> = BTreeMap::new();
    for h in &hosts {
        *first_label_counts.entry(label_name(h, 1)).or_default() += 1;
    }
    hosts
        .into_iter()
        .map(|host| {
            let (fwd, rev) = &zones[host];
            DnsServer {
                name: if first_label_counts[&label_name(host, 1)] > 1 { label_name(host, 2) } else { label_name(host, 1) },
                host: host.clone(),
                vantage: String::new(),
                jump: String::new(),
                manual: false,
                forward_zones: fwd.iter().cloned().collect(),
                reverse_zones: rev.iter().cloned().collect(),
            }
        })
        .filter(|s| !s.forward_zones.is_empty() || !s.reverse_zones.is_empty())
        .collect()
}

/// One zone from a BIND config, classified for the site file.
enum Entry {
    /// A forward domain (lower-cased).
    Forward(String),
    /// A reverse zone as its CIDR string.
    Reverse(String),
}

/// Parse `named-checkconf -p` output into `(zone-type, zone-name)` pairs, e.g.
/// `("master", "astron.nl")`. The pretty-printed config puts each `zone "…"` and its
/// `type …;` on their own lines, so we remember the current zone until its type appears.
#[must_use]
pub fn parse_named_conf(output: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in output.lines() {
        let t = line.trim();
        if t.starts_with("zone ") {
            cur = t.split('"').nth(1).map(str::to_string);
        } else if let Some(zone) = cur.clone() {
            if let Some(ty) = t.strip_prefix("type ") {
                let ty = ty.trim().trim_end_matches(';').trim();
                if ty == "master" || ty == "slave" {
                    out.push((ty.to_string(), zone));
                }
                cur = None; // this zone's type is settled
            }
        }
    }
    out
}

/// Classify a BIND zone name into a site-file entry, or `None` for BIND's built-in zones
/// (the root hint, `localhost`, the RFC1918 reverse defaults). A reverse zone becomes its
/// CIDR; anything else a forward domain.
fn zone_entry(name: &str) -> Option<Entry> {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() || n == "localhost" || n == "." {
        return None;
    }
    if n.ends_with("in-addr.arpa") || n.ends_with("ip6.arpa") {
        let c = reverse_zone_to_cidr(&n)?;
        if is_reserved_reverse(&c) {
            return None; // BIND's built-in loopback / this-host / broadcast reverse zones
        }
        return Some(Entry::Reverse(format!("{}/{}", c.base, c.prefix_len)));
    }
    // Skip local / policy zones (mDNS `.local`, an RPZ like `rpz.local`) — not routable
    // territory, just DNS-server machinery.
    if n.ends_with(".local") || n.ends_with(".localdomain") {
        return None;
    }
    Some(Entry::Forward(n))
}

/// Whether a reverse zone covers a reserved v4 block BIND serves by default — `0.0.0.0/8`,
/// `127.0.0.0/8` (loopback), `255.0.0.0/8` — or the v6 loopback/unspecified. Never real
/// estate, so it must not leak into the discovered `[[dns_servers]]`.
fn is_reserved_reverse(c: &Cidr) -> bool {
    match c.network() {
        IpAddr::V4(a) => matches!(a.octets()[0], 0 | 127 | 255),
        IpAddr::V6(a) => a.is_loopback() || a.is_unspecified(),
    }
}

/// Read the authoritative **master** zones from a server's BIND config over SSH, as
/// `(forward domains, reverse CIDRs)`.
///
/// This is the exact source of truth — immune to the split-horizon SOA MNAME and to zones
/// no NetBox name touches. Returns `None` when the server can't be reached, isn't BIND, or
/// has no `named-checkconf` (a Windows box, an off-net server), so the caller falls back to
/// SOA. Tries `sudo -n` first (the main config is often root-only) then a plain run.
fn read_named_conf(host: &str, jump: &str) -> Option<ServerZones> {
    let vantage = Vantage::with_jump(host, jump);
    let out = vantage.run("sudo -n named-checkconf -p 2>/dev/null || named-checkconf -p 2>/dev/null").ok()?;
    if out.trim().is_empty() {
        return None;
    }
    let mut fwd = BTreeSet::new();
    let mut rev = BTreeSet::new();
    for (ty, zone) in parse_named_conf(&out) {
        if ty != "master" {
            continue; // the server is the source of truth only for its master zones
        }
        match zone_entry(&zone) {
            Some(Entry::Forward(f)) => {
                fwd.insert(f);
            }
            Some(Entry::Reverse(r)) => {
                rev.insert(r);
            }
            None => {}
        }
    }
    Some((fwd, rev))
}

/// Discover the DNS estate **live**, as `[[dns_servers]]` entries.
///
/// Two backends, named.conf **preferred over SOA where we have access**:
/// 1. For each configured server we can SSH to, read `named-checkconf -p` — the exact
///    master zones, correctly attributed to the real host regardless of split-horizon.
/// 2. For everything else (Windows `ntserver1`, off-net servers) fall back to SOA probing:
///    `dig SOA` each candidate forward domain (owned domains + NetBox `dns_name` parents)
///    and one address per surveyed block, attributing by the SOA master — but only for
///    zones no authoritative server already covers, so the public split-horizon MNAME
///    (e.g. `ntserver1` shadowing `astron.nl`) doesn't duplicate the real master.
///
/// Servers not under an owned `domains` entry are filtered out throughout.
///
/// # Errors
/// Propagates a hard token/NetBox failure only if it blocks the reverse pass; individual
/// `dig`/SSH failures are skipped so one dead server never aborts discovery.
pub fn discover_dns_servers(cfg: &Config, token: &str, blocks: &[Cidr]) -> anyhow::Result<Vec<DnsServer>> {
    let owned: Vec<String> = cfg.domains.iter().map(|d| fold(d)).collect();
    // Hand-curated servers are left entirely alone — neither enumerated nor attributed to.
    let manual: BTreeSet<&str> = cfg.dns_servers.iter().filter(|s| s.manual).map(|s| s.host.as_str()).collect();
    let mut zones: BTreeMap<String, ServerZones> = BTreeMap::new();
    let mut covered_fwd: BTreeSet<String> = BTreeSet::new();
    let mut covered_rev: BTreeSet<String> = BTreeSet::new();

    // 1. AUTHORITATIVE: read named.conf on each configured server we can SSH to.
    for s in &cfg.dns_servers {
        if s.manual {
            continue;
        }
        let jump = if s.jump.is_empty() { cfg.jump.as_str() } else { s.jump.as_str() };
        if let Some((fwd, rev)) = read_named_conf(&s.host, jump) {
            covered_fwd.extend(fwd.iter().cloned());
            covered_rev.extend(rev.iter().cloned());
            let e = zones.entry(s.host.clone()).or_default();
            e.0.extend(fwd);
            e.1.extend(rev);
        }
    }

    // 2. SOA FALLBACK for what named.conf couldn't reach.
    let vantage = Vantage::with_jump(&cfg.vantage, &cfg.jump);
    let netbox = NetboxSource { vantage: vantage.clone(), base_url: cfg.netbox_url.clone(), token: token.to_string() };

    // Forward candidates: owned domains (probed even if no NetBox host names them) plus each
    // NetBox dns_name's parent. A NetBox outage is non-fatal — the owned seed still probes.
    let mut candidates: BTreeSet<String> = owned.iter().cloned().collect();
    if let Ok(names) = netbox.gather_dns_names() {
        candidates.extend(names.iter().filter_map(|n| parent_domain(n)));
    }
    for zone in &candidates {
        if let Ok(out) = vantage.run(&format!("dig SOA {zone}")) {
            if let Some((apex, master)) = parse_soa(&out) {
                if is_ours(&master, &owned) && !covered_fwd.contains(&apex) && !manual.contains(master.as_str()) {
                    zones.entry(master).or_default().0.insert(apex);
                }
            }
        }
    }

    // Reverse: one SOA lookup per block, skipping a block already inside a reverse zone we
    // found (all 10.x resolve to the same zone). Zones an authoritative server already has,
    // or that a non-owned server masters, are not added.
    let mut covered: Vec<Cidr> = Vec::new();
    for b in blocks {
        let net = b.network();
        if covered.iter().any(|c| c.contains(net)) {
            continue;
        }
        if let Ok(out) = vantage.run(&format!("dig SOA {}", reverse_name(net))) {
            if let Some((apex, master)) = parse_soa(&out) {
                if let Some(cidr) = reverse_zone_to_cidr(&apex) {
                    covered.push(cidr);
                    let cidr_s = format!("{}/{}", cidr.base, cidr.prefix_len);
                    if is_ours(&master, &owned) && !covered_rev.contains(&cidr_s) && !manual.contains(master.as_str()) {
                        zones.entry(master).or_default().1.insert(cidr_s);
                    }
                }
            }
        }
    }

    Ok(assemble(&zones, &owned))
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
    fn parses_named_conf_master_and_slave_zones() {
        let sample = "\
options {
    directory \"/var/bind\";
};
zone \".\" {
    type hint;
    file \"named.ca\";
};
zone \"astron.nl\" IN {
    type master;
    file \"master/astron.nl\";
};
zone \"124.145.in-addr.arpa\" IN {
    type master;
    file \"master/124.145\";
};
zone \"lofar.eu\" IN {
    type slave;
    masters { 1.2.3.4; };
};";
        let z = parse_named_conf(sample);
        assert!(z.contains(&("master".to_string(), "astron.nl".to_string())));
        assert!(z.contains(&("master".to_string(), "124.145.in-addr.arpa".to_string())));
        assert!(z.contains(&("slave".to_string(), "lofar.eu".to_string())));
        assert!(!z.iter().any(|(_, n)| n == ".")); // the root hint is neither master nor slave
    }

    #[test]
    fn zone_entry_classifies_forward_and_reverse_and_skips_builtins() {
        assert!(matches!(zone_entry("astron.nl"), Some(Entry::Forward(f)) if f == "astron.nl"));
        // Case-insensitive, and mapped back to a CIDR.
        assert!(matches!(zone_entry("124.145.IN-ADDR.ARPA"), Some(Entry::Reverse(r)) if r == "145.124.0.0/16"));
        assert!(matches!(zone_entry("8.6.5.0.0.1.6.0.1.0.0.2.ip6.arpa"), Some(Entry::Reverse(r)) if r == "2001:610:568::/48"));
        assert!(zone_entry("localhost").is_none());
        assert!(zone_entry("127.in-addr.arpa").is_none());
        // A loopback /24 (0.0.127.in-addr.arpa) and an RPZ/.local policy zone must not leak.
        assert!(zone_entry("0.0.127.in-addr.arpa").is_none());
        assert!(zone_entry("rpz.local").is_none());
        assert!(zone_entry("0.in-addr.arpa").is_none());
        // A real 10.x reverse is kept (it is not reserved-space).
        assert!(matches!(zone_entry("10.in-addr.arpa"), Some(Entry::Reverse(r)) if r == "10.0.0.0/8"));
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
                manual: false,
                forward_zones: vec!["nfra.nl".into(), "astron.nl".into()],
                reverse_zones: vec![],
            },
            DnsServer {
                name: "ntserver1".into(),
                host: "ntserver1.nfra.nl".into(),
                vantage: String::new(),
                jump: String::new(),
                manual: false,
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
