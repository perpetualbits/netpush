// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Auto-discovery of the **address space to survey** when no `--range` is given.
//!
//! Instead of making the user name a block, canopy asks its sources what territory
//! exists: NetBox for its **aggregates** (the big v4/v6 allocations it manages) and the
//! DNS estate for the **reverse zones** its servers master. The union of those — deduped
//! and tagged with where each came from — is the set of blocks worth reconciling.
//!
//! Everything here yields **blocks, never address lists**: a huge IPv6 aggregate is one
//! entry, so discovery stays cheap and honours the lazy model
//! ([`Cidr::is_enumerable`](crate::reconcile::Cidr::is_enumerable)). Only [`discover`]
//! touches the network; the inference in [`infer_blocks`] is pure and unit-tested.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::config::Config;
use crate::reconcile::Cidr;
use crate::sources::estate::DnsEstate;
use crate::sources::netbox::NetboxSource;
use crate::sources::{Vantage, SWEEP_CAP};

/// Which source(s) reported a block — so the summary can show why we survey it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSource {
    /// A NetBox aggregate.
    Netbox,
    /// A reverse zone a DNS server masters.
    DnsReverse,
    /// Both a NetBox aggregate and a mastered reverse zone.
    Both,
}

impl BlockSource {
    /// A short tag for the `--list` summary.
    fn label(self) -> &'static str {
        match self {
            BlockSource::Netbox => "netbox",
            BlockSource::DnsReverse => "dns",
            BlockSource::Both => "netbox+dns",
        }
    }

    /// Fold in another sighting: a block seen from *both* sources becomes [`Both`].
    fn merge(self, other: BlockSource) -> BlockSource {
        if self == other {
            self
        } else {
            BlockSource::Both
        }
    }
}

/// One block of address space to survey, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredBlock {
    /// The block, normalized to its network address (e.g. `10.87.0.0/20`).
    pub cidr: Cidr,
    /// Which source(s) reported it.
    pub source: BlockSource,
}

/// The sort/dedupe key for a block: family (IPv4 first), network address, prefix length.
///
/// Keying on the **network** address folds any base (e.g. `10.87.3.5/24`) to its block
/// (`10.87.3.0/24`), so the same block written two ways counts once; keying on the family
/// bit first keeps all IPv4 blocks ahead of IPv6 in the survey order.
fn net_key(c: &Cidr) -> (bool, u128, u8) {
    let n = match c.network() {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    };
    (c.is_v6(), n, c.prefix_len)
}

/// Infer the set of CIDR blocks worth surveying from NetBox aggregates and the DNS
/// estate's reverse zones. **Pure** — no I/O.
///
/// How: union both lists into a map keyed by [`net_key`], so a block reported by both
/// sources becomes one entry tagged [`BlockSource::Both`] and exact repeats collapse; the
/// `BTreeMap` then yields them in survey order (IPv4 before IPv6, then by network, then
/// prefix). Each kept block is normalized to its network address. No enumeration happens,
/// so a huge v6 aggregate is a single block, never a list of addresses.
///
/// Units: `netbox` and `reverse` are CIDR blocks; the result is CIDR blocks.
#[must_use]
pub fn infer_blocks(netbox: &[Cidr], reverse: &[Cidr]) -> Vec<DiscoveredBlock> {
    let mut map: BTreeMap<(bool, u128, u8), (Cidr, BlockSource)> = BTreeMap::new();
    let add = |cidr: &Cidr, src: BlockSource, map: &mut BTreeMap<(bool, u128, u8), (Cidr, BlockSource)>| {
        // Store the network-normalized block so the base is always canonical.
        let normalized = Cidr { base: cidr.network(), prefix_len: cidr.prefix_len };
        map.entry(net_key(cidr)).and_modify(|(_, s)| *s = s.merge(src)).or_insert((normalized, src));
    };
    for c in netbox {
        add(c, BlockSource::Netbox, &mut map);
    }
    for c in reverse {
        add(c, BlockSource::DnsReverse, &mut map);
    }
    map.into_values().map(|(cidr, source)| DiscoveredBlock { cidr, source }).collect()
}

/// Whether `outer` **strictly** contains `inner`: same family, a shorter (coarser)
/// prefix, and it covers `inner`'s network. Used to drop a subnet already inside a bigger
/// one from the survey set.
fn strictly_contains(outer: &Cidr, inner: &Cidr) -> bool {
    outer.is_v6() == inner.is_v6() && outer.prefix_len < inner.prefix_len && outer.contains(inner.network())
}

/// The **coarsest covering subset** of `blocks`: drop any block strictly contained in
/// another. Surveying the survivors still covers every dropped child, so canopy does not
/// reconcile a `/24` and the `/20` that already includes it as two separate blocks. Pure.
///
/// Duplicates (identical blocks) are kept here — the exact-match dedupe in [`infer_blocks`]
/// collapses those later.
#[must_use]
pub fn coarsest(blocks: &[Cidr]) -> Vec<Cidr> {
    blocks.iter().copied().filter(|b| !blocks.iter().any(|o| strictly_contains(o, b))).collect()
}

/// The set of blocks to actually **survey**, drilling any block too big to sweep into the
/// prefixes inside it.
///
/// Coalescing to the coarsest block ([`coarsest`]) can produce one larger than an
/// address-by-address sweep can handle — a `/13`, say — which would then reconcile with
/// NetBox data only, no reverse-DNS or ping. So for any coarsest block over [`SWEEP_CAP`]
/// this surveys the prefixes *strictly inside* it instead, recursively, until each surveyed
/// block is sweepable or has no finer prefix left to drill into. A too-big block with no
/// children is kept as-is (NetBox-only is the best that can be done for it). Pure.
///
/// Net effect: small subnets stay whole, a big supernet is replaced by its real child
/// subnets (which *are* sweepable), so `--live` gets reverse/live data for them too.
#[must_use]
pub fn survey_set(prefixes: &[Cidr]) -> Vec<Cidr> {
    let mut out = Vec::new();
    drill(&coarsest(prefixes), prefixes, &mut out);
    out
}

/// Recursive helper for [`survey_set`]: keep each root that is sweepable, otherwise drill
/// into the coarsest prefixes strictly inside it (or keep it if there are none).
fn drill(roots: &[Cidr], all: &[Cidr], out: &mut Vec<Cidr>) {
    for &r in roots {
        // Keep a block whole if it is already sweepable, or if it is IPv6 — no IPv6 block
        // is ever small enough to sweep address-by-address, so drilling it just fragments
        // NetBox queries and defeats a single whole-zone AXFR; keep v6 coarse.
        if r.is_v6() || r.host_count() <= SWEEP_CAP {
            out.push(r);
            continue;
        }
        let children: Vec<Cidr> = all.iter().copied().filter(|p| strictly_contains(&r, p)).collect();
        if children.is_empty() {
            out.push(r); // too big to sweep and nothing finer to survey — NetBox-only
        } else {
            drill(&coarsest(&children), all, out);
        }
    }
}

/// The block to browse in the TUI while discovering: the first in survey order. The full
/// set is shown by `--list` and named in the TUI status line; multi-block navigation is a
/// later (Phase-3) view. `None` only when nothing was discovered.
#[must_use]
pub fn primary(blocks: &[DiscoveredBlock]) -> Option<&DiscoveredBlock> {
    blocks.first()
}

/// A short human summary of the discovered blocks, for `--list` to print before the rows:
/// a count by family, then one line per block with its family and source.
#[must_use]
pub fn summary(blocks: &[DiscoveredBlock]) -> String {
    let v4 = blocks.iter().filter(|b| !b.cidr.is_v6()).count();
    let v6 = blocks.len() - v4;
    let mut s = format!("discovered {} block(s) — {v4} IPv4, {v6} IPv6:\n", blocks.len());
    for b in blocks {
        s.push_str(&format!(
            "  {}/{}  {}  [{}]\n",
            b.cidr.base,
            b.cidr.prefix_len,
            if b.cidr.is_v6() { "IPv6" } else { "IPv4" },
            b.source.label()
        ));
    }
    s
}

/// Discover the address space **live**: NetBox's survey prefixes (every prefix except the
/// `container` supernets), coalesced to their coarsest covering set, unioned with the
/// estate's reverse zones (via [`infer_blocks`]).
///
/// Why prefixes and not aggregates: many NetBox installs leave the Aggregates table empty
/// and describe the space as prefixes, so relying on aggregates alone finds nothing. And
/// aggregates / container prefixes model the *parent* space (a whole `10.0.0.0/8`) — far
/// too big to reconcile address-by-address — so canopy surveys the real subnets instead.
/// [`survey_set`] coalesces subnets into the coarsest block that is still small enough to
/// sweep, drilling any over-large block back down into its child subnets; the reverse zones
/// are kept separate (a coarse reverse zone must not swallow the prefixes it contains).
///
/// The NetBox calls run on the vantage host (NetBox is internal-only); the reverse zones
/// come straight from the configured estate. A one-line count goes to stderr — including
/// the aggregate count, so an empty Aggregates table is visible — showing what each source
/// contributed.
///
/// # Errors
/// Propagates the NetBox fetch failure, or a bad reverse zone in the config.
pub fn discover(cfg: &Config, token: &str) -> anyhow::Result<Vec<DiscoveredBlock>> {
    let netbox = NetboxSource {
        vantage: Vantage::new(&cfg.vantage),
        base_url: cfg.netbox_url.clone(),
        token: token.to_string(),
    };
    let aggregates = netbox.gather_aggregates()?;
    let prefixes = netbox.gather_survey_prefixes()?;
    let netbox_blocks = survey_set(&prefixes);

    let estate = DnsEstate::from_config(&cfg.dns_servers)?;
    let reverse = estate.reverse_zone_blocks();

    eprintln!(
        "discovery: NetBox {} aggregate(s), {} survey prefix(es) → {} block(s) to survey; {} reverse zone(s)",
        aggregates.len(),
        prefixes.len(),
        netbox_blocks.len(),
        reverse.len()
    );
    Ok(infer_blocks(&netbox_blocks, &reverse))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    #[test]
    fn unions_netbox_and_reverse_with_source_tags_and_survey_order() {
        // NetBox aggregates: a v4 block and a v6 block. Reverse zones: the same v4 block
        // (→ Both) plus a v4 block NetBox doesn't have (→ dns only).
        let netbox = [cidr("10.87.0.0/20"), cidr("2001:db8::/48")];
        let reverse = [cidr("10.87.0.0/20"), cidr("10.99.0.0/16")];
        let blocks = infer_blocks(&netbox, &reverse);

        // Three distinct blocks, IPv4 first (by network), then IPv6.
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].cidr, cidr("10.87.0.0/20"));
        assert_eq!(blocks[0].source, BlockSource::Both); // seen in both sources
        assert_eq!(blocks[1].cidr, cidr("10.99.0.0/16"));
        assert_eq!(blocks[1].source, BlockSource::DnsReverse);
        assert_eq!(blocks[2].cidr, cidr("2001:db8::/48")); // IPv6 sorts last
        assert_eq!(blocks[2].source, BlockSource::Netbox);
    }

    #[test]
    fn a_non_network_base_is_folded_to_its_block() {
        // The same /24 written from a host address collapses to one network-normalized block.
        let blocks = infer_blocks(&[cidr("10.87.3.5/24")], &[cidr("10.87.3.200/24")]);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].cidr, cidr("10.87.3.0/24"));
        assert_eq!(blocks[0].source, BlockSource::Both);
    }

    #[test]
    fn coarsest_drops_subnets_already_inside_a_bigger_block() {
        // The /24 and /26 sit inside the /20 → only the /20 (and the unrelated /16) survive.
        let blocks = [cidr("10.87.0.0/20"), cidr("10.87.3.0/24"), cidr("10.87.3.0/26"), cidr("10.99.0.0/16")];
        let top = coarsest(&blocks);
        assert_eq!(top, vec![cidr("10.87.0.0/20"), cidr("10.99.0.0/16")]);
        // A v4 block never swallows a v6 one, even at a shorter prefix.
        let mixed = [cidr("0.0.0.0/0"), cidr("2001:db8::/48")];
        assert_eq!(coarsest(&mixed), mixed.to_vec());
    }

    #[test]
    fn survey_set_drills_blocks_too_big_to_sweep() {
        // A /13 (over the sweep cap) with two /24 children → survey the /24s, not the /13.
        // A /20 (under the cap) stays whole and absorbs its own /24 child.
        let prefixes = [
            cidr("10.128.0.0/13"),
            cidr("10.128.5.0/24"),
            cidr("10.130.9.0/24"),
            cidr("10.87.0.0/20"),
            cidr("10.87.3.0/24"),
        ];
        let s = survey_set(&prefixes);
        assert!(s.contains(&cidr("10.87.0.0/20"))); // sweepable → kept whole
        assert!(!s.contains(&cidr("10.87.3.0/24"))); // absorbed into the /20
        assert!(!s.contains(&cidr("10.128.0.0/13"))); // too big → drilled away
        assert!(s.contains(&cidr("10.128.5.0/24"))); // its children surveyed instead
        assert!(s.contains(&cidr("10.130.9.0/24")));
    }

    #[test]
    fn survey_set_keeps_a_big_block_with_no_children() {
        // A lone /13 with nothing finer inside it can't be drilled → kept (NetBox-only).
        assert_eq!(survey_set(&[cidr("10.128.0.0/13")]), vec![cidr("10.128.0.0/13")]);
    }

    #[test]
    fn survey_set_never_drills_ipv6() {
        // A /48 is far over the cap, but IPv6 is never swept — keep it whole rather than
        // fragment it into its (still-unsweepable) child prefixes.
        let prefixes = [cidr("2001:db8::/48"), cidr("2001:db8:0:1::/64")];
        assert_eq!(survey_set(&prefixes), vec![cidr("2001:db8::/48")]);
    }

    #[test]
    fn empty_sources_discover_nothing() {
        assert!(infer_blocks(&[], &[]).is_empty());
        assert!(primary(&[]).is_none());
    }

    #[test]
    fn summary_counts_families_and_names_sources() {
        let blocks = infer_blocks(&[cidr("10.0.0.0/8"), cidr("2001:db8::/32")], &[cidr("10.0.0.0/8")]);
        let text = summary(&blocks);
        assert!(text.contains("2 block(s) — 1 IPv4, 1 IPv6"), "{text}");
        assert!(text.contains("10.0.0.0/8  IPv4  [netbox+dns]"), "{text}");
        assert!(text.contains("2001:db8::/32  IPv6  [netbox]"), "{text}");
    }
}
