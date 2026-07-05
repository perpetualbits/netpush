// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! DNS as a fact source: the PTR records actually served. This is the most reliable
//! "is it allocated?" signal we found — it caught addresses NetBox never recorded.
//! We reverse-resolve every host on the vantage (its resolver knows the internal
//! zones), in parallel with bounded fan-out, and collect the answers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::estate::DnsEstate;
use super::{FactSource, Vantage};
use crate::reconcile::{AddressFacts, Cidr};

/// Reverse-resolves every host in a range via the vantage's resolver.
#[derive(Debug, Clone)]
pub struct DnsSource {
    /// A host whose resolver can see the internal reverse zones. Also the fallback SSH
    /// vantage for any reverse zone the estate does not route to a specific server.
    pub vantage: Vantage,
    /// Max concurrent lookups (the `xargs -P` fan-out) — bounds the burst on the
    /// resolver and the authoritative reverse server behind it.
    pub concurrency: usize,
    /// Default authoritative server to try a **zone transfer** (AXFR) from, used when no
    /// `estate` server claims a zone. When non-empty and transfer is permitted, one AXFR
    /// per `/24` replaces hundreds of `host` lookups; otherwise we fall back to the
    /// per-address sweep. Empty disables the default AXFR.
    pub axfr_server: String,
    /// The DNS estate, when configured: routes each reverse zone's AXFR to the server
    /// that masters it. Empty (the default) keeps the single-`axfr_server` path exactly.
    pub estate: DnsEstate,
}

/// One AXFR batch: the reverse zones to transfer and where from — the vantage to SSH
/// into and the DNS server to `dig … @host`.
struct ReverseGroup {
    /// The SSH vantage to run the transfers on.
    vantage: Vantage,
    /// The authoritative DNS server to transfer from (the `dig @host` target).
    host: String,
    /// The reverse zone names to transfer from `host`.
    zones: Vec<String>,
}

/// Safety cap on how many `/24` reverse zones an AXFR sweep will transfer. A range that
/// needs more is left to the per-address sweep rather than firing hundreds of transfers.
const MAX_ZONES: usize = 512;

impl FactSource for DnsSource {
    fn gather(&self, range: &Cidr) -> anyhow::Result<Vec<AddressFacts>> {
        self.gather_with_progress(range, |_frac, _label| {})
    }
}

impl DnsSource {
    /// Reverse-resolve every host in `range`, reporting progress through
    /// `on_progress(fraction, label)` as it goes, and return the PTR facts found.
    ///
    /// If an AXFR server is configured and transfer is permitted, this pulls whole `/24`
    /// reverse zones (one query each — dramatically fewer, and far lighter on the DNS
    /// server); otherwise it falls back to the per-address sweep.
    ///
    /// # Errors
    /// Propagates SSH failures.
    pub fn gather_with_progress(
        &self,
        range: &Cidr,
        mut on_progress: impl FnMut(f32, &str),
    ) -> anyhow::Result<Vec<AddressFacts>> {
        // AXFR is the light path (and the *only* reverse path for a huge IPv6 range, which
        // can't be swept address by address): `in-addr.arpa` for v4, `ip6.arpa` for v6.
        // Only if the server actually lets us transfer, though — otherwise fall through.
        //
        // With a configured estate, each reverse zone is routed to the server that masters
        // it; without one, we use the single default `axfr_server` exactly as before.
        if !self.estate.is_empty() {
            if let Some(facts) = self.try_axfr_routed(range, &mut on_progress)? {
                return Ok(facts);
            }
        } else if !self.axfr_server.is_empty() {
            if let Some(facts) = self.try_axfr(range, &mut on_progress)? {
                return Ok(facts);
            }
        }
        // No AXFR (unset or refused): fall back to a per-address sweep, which enumerates
        // the range. That is impossible for a huge IPv6 block and impractical (and, via
        // the remote command's argument list, unsafe) for a large IPv4 one — so anything
        // over [`SWEEP_CAP`] gets nothing here and relies on NetBox alone.
        if !range.is_enumerable() || range.host_count() > super::SWEEP_CAP {
            return Ok(Vec::new());
        }
        self.sweep(range, on_progress)
    }

    /// The per-address reverse sweep: one `host` lookup per address, in parallel with
    /// bounded fan-out.
    ///
    /// A serial `for` loop did one blocking `host` per address — for a /20 that is ~4000
    /// lookups back-to-back, each waiting out a timeout when there is no PTR, so it took
    /// minutes. `xargs -P` runs up to `concurrency` at once (bounding load on the
    /// resolver) and `host -W1` caps each lookup at ~1 s. Each worker prints `T` when
    /// done (a progress tick, streamed back and counted) and `R <ip> <name>` when a PTR
    /// exists; both lines are short enough to be written atomically to the pipe. `$0`
    /// inside the `sh -c` body is the address xargs handed it.
    fn sweep(&self, range: &Cidr, mut on_progress: impl FnMut(f32, &str)) -> anyhow::Result<Vec<AddressFacts>> {
        let ips = host_list(range);
        let par = self.concurrency.max(1);
        // The trailing `; true` matters: when a host has no PTR, `$h` is empty and the
        // `[ -n "$h" ]` test exits non-zero, which makes `xargs` exit 123 — read as "ssh
        // failed". Ending each worker with `true` lets a sweep with no PTRs finish cleanly.
        let remote = format!(
            "printf '%s\\n' {ips} | xargs -P{par} -n1 sh -c 'h=$(host -W1 \"$0\" 2>/dev/null | sed -n \"s/.*pointer //p\"); printf \"T\\n\"; [ -n \"$h\" ] && printf \"R %s %s\\n\" \"$0\" \"$h\"; true'"
        );
        let total = range.host_count().max(1);
        let step = (total / 100).max(1); // update ~every 1 % rather than per address
        let mut done = 0u128;
        let mut results = String::new();
        self.vantage.run_streaming(&remote, |line| {
            if line == "T" {
                done += 1;
                if done % step == 0 || done == total {
                    on_progress(done as f32 / total as f32, &format!("DNS reverse sweep {done}/{total}"));
                }
            } else if let Some(rest) = line.strip_prefix("R ") {
                results.push_str(rest);
                results.push('\n');
            }
        })?;
        Ok(parse_ptrs(&results))
    }

    /// Try to pull the reverse PTRs by zone transfer from the single default
    /// `axfr_server` (the no-estate path). Returns `Some(facts)` when AXFR is permitted
    /// and done, or `None` when the server refuses (or the range needs more than
    /// [`MAX_ZONES`] zones) so the caller falls back to the sweep.
    fn try_axfr(&self, range: &Cidr, mut on_progress: impl FnMut(f32, &str)) -> anyhow::Result<Option<Vec<AddressFacts>>> {
        let zones = reverse_zones(range);
        if zones.is_empty() {
            return Ok(None); // too large for AXFR — use the sweep
        }
        let total = zones.len();
        let mut facts = Vec::new();
        let mut done = 0usize;
        let ran = self.axfr_zones_from(&self.vantage, &self.axfr_server, &zones, range, &mut facts, &mut done, total, &mut on_progress)?;
        // A refusal (empty probe) leaves `ran` false → `None` so the caller sweeps, exactly
        // as before.
        Ok(ran.then_some(facts))
    }

    /// Try to pull the reverse PTRs by zone transfer, **routing each zone to the server
    /// that masters it** (the estate path). Returns `Some(facts)` — the union across
    /// servers — or `None` when the range is too large for AXFR, or no server (and no
    /// default `axfr_server` fallback) owns any of its zones, so the caller sweeps.
    ///
    /// Each reverse zone is mapped back to the network it covers ([`zone_network`]) and
    /// routed by longest-prefix match; zones no server claims go to the default
    /// `axfr_server` when one is set. A server that refuses simply contributes nothing —
    /// other servers may still transfer.
    fn try_axfr_routed(&self, range: &Cidr, mut on_progress: impl FnMut(f32, &str)) -> anyhow::Result<Option<Vec<AddressFacts>>> {
        let zones = reverse_zones(range);
        if zones.is_empty() {
            return Ok(None); // too large for AXFR — use the sweep
        }
        let groups = self.route_reverse_zones(&zones);
        if groups.is_empty() {
            return Ok(None); // nothing routable and no fallback → sweep instead
        }
        let total: usize = groups.iter().map(|g| g.zones.len()).sum();
        let mut facts = Vec::new();
        let mut done = 0usize;
        for g in &groups {
            let ran = self.axfr_zones_from(&g.vantage, &g.host, &g.zones, range, &mut facts, &mut done, total, &mut on_progress)?;
            if !ran {
                // This server refused (or was unreachable); its zones yield nothing. Keep
                // the bar honest and carry on with the other servers.
                done += g.zones.len();
                on_progress(done as f32 / total as f32, &format!("AXFR {done}/{total} zones"));
            }
        }
        Ok(Some(facts))
    }

    /// Group the reverse `zones` by the server that should transfer them.
    ///
    /// How: route each zone by the network it covers ([`zone_network`]) through the
    /// estate's longest-prefix match; a zone no server owns falls back to the default
    /// `axfr_server` (skipped entirely when that is unset). Zones bound for the same
    /// (vantage, server) pair are batched together so each server is contacted once.
    fn route_reverse_zones(&self, zones: &[String]) -> Vec<ReverseGroup> {
        let mut groups: Vec<ReverseGroup> = Vec::new();
        for z in zones {
            let owner = zone_network(z).and_then(|addr| self.estate.reverse_owner(addr));
            // Each server carries its own vantage + jump, falling back to the site's when
            // unset; an unowned zone uses the default vantage/jump and the fallback server.
            let (vantage_host, jump, host) = match owner {
                Some(s) => (
                    s.vantage_or(&self.vantage.host).to_string(),
                    s.jump_or(&self.vantage.jump).to_string(),
                    s.host.clone(),
                ),
                None if !self.axfr_server.is_empty() => {
                    (self.vantage.host.clone(), self.vantage.jump.clone(), self.axfr_server.clone())
                }
                None => continue, // unroutable and no fallback → left to the sweep
            };
            match groups.iter_mut().find(|g| g.vantage.host == vantage_host && g.vantage.jump == jump && g.host == host) {
                Some(g) => g.zones.push(z.clone()),
                None => groups.push(ReverseGroup { vantage: Vantage::with_jump(vantage_host, jump), host, zones: vec![z.clone()] }),
            }
        }
        groups
    }

    /// AXFR `zones` from `axfr_host` over `vantage`, appending the PTR facts found within
    /// `range` to `out`. Shared by the single-server and routed paths.
    ///
    /// Gate: transfer the first zone; an empty answer (no SOA, no PTR) means the server
    /// refuses, and we return `Ok(false)` having added nothing. Otherwise transfer the
    /// rest with bounded parallelism (transfers are heavier than lookups, so a smaller
    /// fan-out), advancing the shared zone counter `done` against `total` for the progress
    /// bar. Each answer line is prefixed `R ` so it is told apart from the `T` zone tick on
    /// the shared stream.
    #[allow(clippy::too_many_arguments)]
    fn axfr_zones_from(
        &self,
        vantage: &Vantage,
        axfr_host: &str,
        zones: &[String],
        range: &Cidr,
        out: &mut Vec<AddressFacts>,
        done: &mut usize,
        total: usize,
        mut on_progress: impl FnMut(f32, &str),
    ) -> anyhow::Result<bool> {
        if zones.is_empty() {
            return Ok(true);
        }
        // Probe the first zone. Any error (server unreachable, dig missing) → treat as a
        // refusal so the caller can fall back.
        let probe = match self.axfr_zone(vantage, axfr_host, &zones[0]) {
            Ok(out) => out,
            Err(_) => return Ok(false),
        };
        if !probe.contains("SOA") && !probe.contains(" PTR ") {
            return Ok(false); // empty answer = transfer refused
        }
        out.extend(parse_axfr(&probe, range));
        *done += 1;
        on_progress(*done as f32 / total as f32, &format!("AXFR {done}/{total} zones"));

        if zones.len() > 1 {
            let par = self.concurrency.clamp(1, 8);
            let args = zones[1..].join(" ");
            let remote = format!(
                "printf '%s\\n' {args} | xargs -P{par} -n1 sh -c 'dig +noall +answer AXFR \"$0\" @{axfr_host} 2>/dev/null | sed \"s/^/R /\"; printf \"T\\n\"'"
            );
            let mut results = String::new();
            vantage.run_streaming(&remote, |line| {
                if line == "T" {
                    *done += 1;
                    on_progress(*done as f32 / total as f32, &format!("AXFR {done}/{total} zones"));
                } else if let Some(rest) = line.strip_prefix("R ") {
                    results.push_str(rest);
                    results.push('\n');
                }
            })?;
            out.extend(parse_axfr(&results, range));
        }
        Ok(true)
    }

    /// Transfer a single reverse zone from `axfr_host` over `vantage`, returning dig's
    /// answer section (records only).
    fn axfr_zone(&self, vantage: &Vantage, axfr_host: &str, zone: &str) -> anyhow::Result<String> {
        let remote = format!("dig +noall +answer AXFR {zone} @{axfr_host}");
        vantage.run(&remote)
    }
}

/// The reverse zones (`in-addr.arpa` for IPv4, `ip6.arpa` for IPv6) that `range`
/// overlaps, aligned to the zone boundary — `/24` for v4, the nibble boundary for v6.
/// Empty when the range would need more than [`MAX_ZONES`] zones (skip AXFR, sweep
/// instead — or, for a huge v6 range with no zone, fall back to NetBox).
fn reverse_zones(range: &Cidr) -> Vec<String> {
    match range.network() {
        IpAddr::V4(net) => reverse_zones_v4(net, range.block_len()),
        IpAddr::V6(net) => reverse_zones_v6(net, u32::from(range.prefix_len)),
    }
}

/// IPv4 `/24` `in-addr.arpa` zones covering `block_len` addresses from `net`.
fn reverse_zones_v4(net: Ipv4Addr, block_len: u128) -> Vec<String> {
    let start = u64::from(u32::from(net));
    let end = start + block_len as u64; // exclusive (v4 block_len fits u64)
    let first = start & !0xFF; // align down to a /24 boundary
    let count = (end - first).div_ceil(256) as usize;
    if count > MAX_ZONES {
        return Vec::new();
    }
    (0..count)
        .map(|i| {
            let o = ((first + (i as u64) * 256) as u32).to_be_bytes(); // [a, b, c, d]
            format!("{}.{}.{}.in-addr.arpa", o[2], o[1], o[0])
        })
        .collect()
}

/// IPv6 `ip6.arpa` zones covering a `/prefix` from `net`, cut at the nibble boundary at
/// or below the prefix (so a `/48`, `/56` or `/64` is exactly one zone; a non-nibble
/// prefix rounds up and spans a few). AXFR of such a zone returns only the PTRs that
/// actually exist, so the transfer size is bounded by reality regardless of the zone's
/// span. Each zone name is the prefix's nibbles, least-significant first, then `ip6.arpa`.
fn reverse_zones_v6(net: Ipv6Addr, prefix: u32) -> Vec<String> {
    let nibbles = prefix.div_ceil(4); // zone depth in nibbles
    let zone_bits = nibbles * 4; // aligned prefix
    let count = 1u128 << (zone_bits - prefix); // zones needed to cover a non-nibble prefix
    if count as usize > MAX_ZONES {
        return Vec::new();
    }
    let base = u128::from(net) >> (128 - zone_bits); // the top `zone_bits` as an integer
    (0..count)
        .map(|i| {
            let z = base + i;
            let labels: Vec<String> = (0..nibbles).map(|k| format!("{:x}", (z >> (4 * k)) & 0xf)).collect();
            format!("{}.ip6.arpa", labels.join("."))
        })
        .collect()
}

/// The network address a reverse **zone** covers, so it can be routed to the server that
/// masters that block: `3.87.10.in-addr.arpa` → `10.87.3.0`, and an `…​.ip6.arpa` zone →
/// the IPv6 prefix its nibbles spell out. `None` for names that are not reverse zones.
///
/// How: the labels of an `in-addr.arpa` zone are the network's high octets in reverse, and
/// the labels of an `ip6.arpa` zone are its high nibbles least-significant-first (the exact
/// inverse of how [`reverse_zones_v4`]/[`reverse_zones_v6`] build them); the remaining
/// low bits are zero — the block's network address.
fn zone_network(zone: &str) -> Option<IpAddr> {
    let z = zone.trim_end_matches('.');
    if let Some(labels) = z.strip_suffix(".in-addr.arpa") {
        // Labels are the high octets, most-significant last (e.g. `3.87.10` → 10.87.3.x).
        let octs: Vec<u8> = labels.split('.').map(|p| p.parse().ok()).collect::<Option<_>>()?;
        if octs.is_empty() || octs.len() > 4 {
            return None;
        }
        let mut b = [0u8; 4];
        for (i, o) in octs.iter().rev().enumerate() {
            b[i] = *o; // reverse back to most-significant first; low octets stay 0
        }
        return Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])));
    }
    if let Some(labels) = z.strip_suffix(".ip6.arpa") {
        let nibs: Vec<u8> =
            labels.split('.').map(|p| u8::from_str_radix(p, 16).ok().filter(|n| *n < 16)).collect::<Option<_>>()?;
        if nibs.is_empty() || nibs.len() > 32 {
            return None;
        }
        // Nibble k sits at bit 4k of the zone integer; the zone occupies the address's top
        // `4·len` bits, so shift it up to form the network.
        let zone_val = nibs.iter().enumerate().fold(0u128, |acc, (k, &n)| acc | (u128::from(n) << (4 * k)));
        let net = zone_val << (128 - (nibs.len() as u32) * 4);
        return Some(IpAddr::V6(Ipv6Addr::from(net)));
    }
    None
}

/// Map a reverse-DNS owner name back to its address: `1.3.87.10.in-addr.arpa.` →
/// `10.87.3.1` (four octets reversed), or a full 32-nibble `…​.ip6.arpa.` → its IPv6
/// address (nibbles are least-significant first). Non-host owners (short zone/delegation
/// names) return `None`.
fn ptr_owner_to_ip(owner: &str) -> Option<IpAddr> {
    let o = owner.trim_end_matches('.');
    if let Some(labels) = o.strip_suffix(".in-addr.arpa") {
        let parts: Vec<u8> = labels.split('.').map(|p| p.parse().ok()).collect::<Option<_>>()?;
        return match parts[..] {
            [d, c, b, a] => Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d))),
            _ => None,
        };
    }
    if let Some(labels) = o.strip_suffix(".ip6.arpa") {
        let nibs: Vec<u8> =
            labels.split('.').map(|p| u8::from_str_radix(p, 16).ok().filter(|n| *n < 16)).collect::<Option<_>>()?;
        if nibs.len() != 32 {
            return None; // only a full host PTR maps to an address
        }
        let v = nibs.iter().enumerate().fold(0u128, |acc, (k, &n)| acc | (u128::from(n) << (4 * k)));
        return Some(IpAddr::V6(Ipv6Addr::from(v)));
    }
    None
}

/// Parse `dig +answer` PTR lines from an AXFR into facts, keeping only those in `range`.
///
/// Each PTR line is `<owner> <ttl> <class> PTR <target>`; we map the owner back to its
/// address and keep the target as the name. Non-PTR records (SOA, NS, …) are skipped.
#[must_use]
pub fn parse_axfr(output: &str, range: &Cidr) -> Vec<AddressFacts> {
    let mut out = Vec::new();
    for line in output.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let Some(pi) = f.iter().position(|&t| t == "PTR") else {
            continue;
        };
        let (Some(owner), Some(target)) = (f.first(), f.get(pi + 1)) else {
            continue;
        };
        let Some(addr) = ptr_owner_to_ip(owner) else {
            continue;
        };
        if !range.contains(addr) {
            continue;
        }
        out.push(AddressFacts { addr, netbox: None, ptr: Some((*target).to_string()), live: false });
    }
    out
}

/// The space-separated host list for the remote shell loop.
fn host_list(range: &Cidr) -> String {
    range.hosts().map(|a| a.to_string()).collect::<Vec<_>>().join(" ")
}

/// Parse `"<ip> <ptr>"` lines into `ptr`-only facts.
///
/// How: split each non-empty line into address and name; skip anything that does
/// not parse as an IPv4 address. Only the `ptr` field is set.
#[must_use]
pub fn parse_ptrs(output: &str) -> Vec<AddressFacts> {
    let mut out = Vec::new();
    for line in output.lines() {
        let mut it = line.split_whitespace();
        let (Some(ip), Some(name)) = (it.next(), it.next()) else {
            continue;
        };
        let Ok(addr) = ip.parse() else { continue };
        out.push(AddressFacts {
            addr,
            netbox: None,
            ptr: Some(name.to_string()),
            live: false,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reverse_sweep_output() {
        let sample = "\
10.87.3.68 dop21-ipmi.nfra.nl.
10.87.3.11 iprotect-keyreader.nfra.nl.
garbage line without ip
10.87.3.90";
        let facts = parse_ptrs(sample);
        assert_eq!(facts.len(), 2); // the garbage and the ip-only line are skipped
        assert_eq!(facts[0].addr, std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 87, 3, 68)));
        assert_eq!(facts[0].ptr.as_deref(), Some("dop21-ipmi.nfra.nl."));
        assert!(facts[0].netbox.is_none() && !facts[0].live);
    }

    #[test]
    fn host_list_covers_usable_hosts() {
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let list = host_list(&range);
        assert!(list.starts_with("10.87.3.1 "));
        assert!(list.ends_with(" 10.87.3.254"));
    }

    #[test]
    fn reverse_zones_cover_the_range_by_slash_24() {
        // A /24 is one zone; a /20 spans its 16 /24s; a /26 still maps to its /24.
        assert_eq!(reverse_zones(&Cidr::parse("10.87.3.0/24").unwrap()), vec!["3.87.10.in-addr.arpa"]);
        assert_eq!(reverse_zones(&Cidr::parse("10.87.3.0/26").unwrap()), vec!["3.87.10.in-addr.arpa"]);
        let z20 = reverse_zones(&Cidr::parse("10.87.0.0/20").unwrap());
        assert_eq!(z20.len(), 16);
        assert_eq!(z20[0], "0.87.10.in-addr.arpa");
        assert_eq!(z20[15], "15.87.10.in-addr.arpa");
        // A /8 needs 65 536 zones — over the cap, so AXFR is declined (empty → sweep).
        assert!(reverse_zones(&Cidr::parse("10.0.0.0/8").unwrap()).is_empty());
    }

    #[test]
    fn ptr_owner_maps_back_to_its_address() {
        let ip = ptr_owner_to_ip("1.3.87.10.in-addr.arpa.").unwrap();
        assert_eq!(ip, std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 87, 3, 1)));
        assert!(ptr_owner_to_ip("nonsense.example.com.").is_none());
    }

    #[test]
    fn parses_axfr_answer_lines() {
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let answer = "\
3.87.10.in-addr.arpa.\t3600\tIN\tSOA\tns.nfra.nl. root.nfra.nl. 1 2 3 4 5
68.3.87.10.in-addr.arpa. 3600 IN PTR dop21-ipmi.nfra.nl.
99.3.99.10.in-addr.arpa. 3600 IN PTR elsewhere.nfra.nl.
3.87.10.in-addr.arpa.\t3600\tIN\tNS\tns.nfra.nl.";
        let facts = parse_axfr(answer, &range);
        // SOA/NS skipped; the out-of-range .99 host dropped; only the /24 PTR kept.
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].addr, std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 87, 3, 68)));
        assert_eq!(facts[0].ptr.as_deref(), Some("dop21-ipmi.nfra.nl."));
    }

    #[test]
    fn ipv6_reverse_zone_is_the_nibble_prefix() {
        // 2001:db8:aaaa::/48 → the 12 leading nibbles, least-significant first, + ip6.arpa.
        assert_eq!(
            reverse_zones(&Cidr::parse("2001:db8:aaaa::/48").unwrap()),
            vec!["a.a.a.a.8.b.d.0.1.0.0.2.ip6.arpa"]
        );
        assert_eq!(reverse_zones(&Cidr::parse("2001:db8:0:1::/64").unwrap()).len(), 1); // one 16-nibble zone
        assert_eq!(reverse_zones(&Cidr::parse("2001:db8:aaaa::/47").unwrap()).len(), 2); // non-nibble → 2 zones
    }

    /// The `ip6.arpa` owner name for `2001:db8::<low>`: nibble `low`, then 23 zeros, then
    /// the 8 nibbles of `2001:0db8` least-significant first.
    fn ip6_owner(low: char) -> String {
        format!("{low}.{}8.b.d.0.1.0.0.2.ip6.arpa.", "0.".repeat(23))
    }

    #[test]
    fn ptr_owner_maps_ip6_arpa_back_to_v6() {
        assert_eq!(ptr_owner_to_ip(&ip6_owner('1')).unwrap(), "2001:db8::1".parse::<IpAddr>().unwrap());
        assert!(ptr_owner_to_ip("a.a.a.a.8.b.d.0.1.0.0.2.ip6.arpa.").is_none()); // short zone name, not a host
    }

    #[test]
    fn zone_network_recovers_the_block_a_reverse_zone_covers() {
        // The /24 zone the range produces maps back to its network address.
        assert_eq!(zone_network("3.87.10.in-addr.arpa"), Some("10.87.3.0".parse().unwrap()));
        assert_eq!(zone_network("0.87.10.in-addr.arpa."), Some("10.87.0.0".parse().unwrap()));
        // The v6 nibble zone maps back to its prefix (low bits zero).
        assert_eq!(
            zone_network("a.a.a.a.8.b.d.0.1.0.0.2.ip6.arpa"),
            Some("2001:db8:aaaa::".parse().unwrap())
        );
        // A name that is not a reverse zone has no network.
        assert!(zone_network("host.example.com").is_none());
    }

    #[test]
    fn routing_groups_zones_by_owning_server() {
        use crate::config::DnsServer;
        use crate::sources::estate::DnsEstate;
        // ntserver1 masters all of 10/8 (no own vantage/jump); a tighter server masters
        // 10.87/16 and is reached over its own vantage and jump bastion.
        let estate = DnsEstate::from_config(&[
            DnsServer {
                name: "ntserver1".into(),
                host: "ntserver1.nfra.nl".into(),
                vantage: String::new(),
                forward_zones: vec![],
                reverse_zones: vec!["10.0.0.0/8".into()],
                ..DnsServer::default()
            },
            DnsServer {
                name: "sub16".into(),
                host: "sub16.astron.nl".into(),
                vantage: "jump.astron.nl".into(),
                jump: "portal.lofar.eu".into(),
                manual: false,
                forward_zones: vec![],
                reverse_zones: vec!["10.87.0.0/16".into()],
            },
        ])
        .unwrap();
        // The site's default vantage carries a jump bastion the servers can fall back to.
        let dns = DnsSource {
            vantage: Vantage::with_jump("dns1.astron.nl", "bastion.astron.nl"),
            concurrency: 8,
            axfr_server: String::new(),
            estate,
        };
        // A /20 in 10.87 → all its /24 zones route to sub16, over its own vantage + jump.
        let z20 = reverse_zones(&Cidr::parse("10.87.0.0/20").unwrap());
        let groups = dns.route_reverse_zones(&z20);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].host, "sub16.astron.nl");
        assert_eq!(groups[0].vantage.host, "jump.astron.nl");
        assert_eq!(groups[0].vantage.jump, "portal.lofar.eu"); // its own jump
        assert_eq!(groups[0].zones.len(), 16);

        // A /24 in 10.200 (only inside 10/8) → ntserver1, over the site's default vantage
        // and jump (it sets neither of its own).
        let z24 = reverse_zones(&Cidr::parse("10.200.4.0/24").unwrap());
        let g2 = dns.route_reverse_zones(&z24);
        assert_eq!(g2.len(), 1);
        assert_eq!(g2[0].host, "ntserver1.nfra.nl");
        assert_eq!(g2[0].vantage.host, "dns1.astron.nl"); // fell back to the site vantage
        assert_eq!(g2[0].vantage.jump, "bastion.astron.nl"); // fell back to the site jump
    }

    #[test]
    fn reverse_sweep_skips_a_block_too_large() {
        use crate::sources::estate::DnsEstate;
        // A /8 with no AXFR configured must not sweep: gather returns empty without ever
        // contacting the (bogus) vantage — the guard against the E2BIG crash.
        let d = DnsSource {
            vantage: Vantage::with_jump("nowhere.invalid", ""),
            concurrency: 8,
            axfr_server: String::new(),
            estate: DnsEstate::default(),
        };
        let facts = d.gather(&Cidr::parse("10.0.0.0/8").unwrap()).unwrap();
        assert!(facts.is_empty());
    }

    #[test]
    fn routing_falls_back_to_default_axfr_server_and_drops_unowned_zones() {
        use crate::sources::estate::DnsEstate;
        // No estate servers, but a default axfr_server → every zone routes there.
        let with_default = DnsSource {
            vantage: Vantage::with_jump("dns1.astron.nl", ""),
            concurrency: 8,
            axfr_server: "default-axfr.astron.nl".into(),
            estate: DnsEstate::default(),
        };
        let z = reverse_zones(&Cidr::parse("10.87.3.0/24").unwrap());
        let g = with_default.route_reverse_zones(&z);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].host, "default-axfr.astron.nl");

        // No estate and no default → nothing is routable (the caller sweeps instead).
        let none = DnsSource {
            vantage: Vantage::with_jump("dns1.astron.nl", ""),
            concurrency: 8,
            axfr_server: String::new(),
            estate: DnsEstate::default(),
        };
        assert!(none.route_reverse_zones(&z).is_empty());
    }

    #[test]
    fn parses_ipv6_axfr_answer_lines() {
        let range = Cidr::parse("2001:db8::/48").unwrap();
        let answer = format!(
            "{} 3600 IN PTR host1.nfra.nl.\n{} 3600 IN PTR host2.nfra.nl.",
            ip6_owner('1'),
            ip6_owner('2')
        );
        let facts = parse_axfr(&answer, &range);
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[0].addr, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(facts[0].ptr.as_deref(), Some("host1.nfra.nl."));
    }
}
