// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! DNS names as label sequences. This is deliberately the *graph-friendly* core:
//! a name knows its parent (nesting), whether it sits under a zone, and — for the
//! record types that reference another name (CNAME/NS/PTR) — that reference is an
//! edge. When the node-graph view lands, zones are group nodes, names nest by
//! [`DnsName::parent`], and those references become the wires.

use std::fmt;
use std::net::IpAddr;

/// A DNS name held as labels, most-specific first, lower-cased, no trailing dot.
/// e.g. `dop370-ipmi.nfra.nl` → `["dop370-ipmi", "nfra", "nl"]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName {
    labels: Vec<String>,
}

impl DnsName {
    /// Parse a name; a trailing dot and letter case are normalised away.
    #[must_use]
    pub fn parse(s: &str) -> DnsName {
        let labels = s
            .trim()
            .trim_end_matches('.')
            .split('.')
            .filter(|l| !l.is_empty())
            .map(|l| l.to_ascii_lowercase())
            .collect();
        DnsName { labels }
    }

    /// The labels, most-specific first.
    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// Whether this is the empty (root) name.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// The parent name (this name minus its first label), or `None` at the root.
    /// This is the nesting edge the node graph draws.
    #[must_use]
    pub fn parent(&self) -> Option<DnsName> {
        if self.labels.is_empty() {
            None
        } else {
            Some(DnsName { labels: self.labels[1..].to_vec() })
        }
    }

    /// Whether `self` is equal to, or sits under, `zone`.
    #[must_use]
    pub fn is_subdomain_of(&self, zone: &DnsName) -> bool {
        if self.labels.len() < zone.labels.len() {
            return false;
        }
        let tail = &self.labels[self.labels.len() - zone.labels.len()..];
        tail == zone.labels.as_slice()
    }

    /// The owner label(s) of `self` relative to `zone`, e.g. `dop370-ipmi.nfra.nl`
    /// in zone `nfra.nl` → `"dop370-ipmi"`. The zone apex itself becomes `"@"`.
    /// Returns `None` if `self` is not inside `zone`.
    #[must_use]
    pub fn relative_to(&self, zone: &DnsName) -> Option<String> {
        if !self.is_subdomain_of(zone) {
            return None;
        }
        let n = self.labels.len() - zone.labels.len();
        if n == 0 {
            Some("@".to_string())
        } else {
            Some(self.labels[..n].join("."))
        }
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.labels.join("."))
    }
}

/// The reverse-DNS name for an address: `in-addr.arpa` for IPv4 (octets reversed,
/// e.g. `10.87.3.69` → `69.3.87.10.in-addr.arpa`) or `ip6.arpa` for IPv6 (all 32
/// nibbles reversed). The labels run most-significant-last because DNS delegates the
/// reverse tree that way, mirroring how forward names nest.
#[must_use]
pub fn reverse_ptr(addr: IpAddr) -> DnsName {
    match addr {
        IpAddr::V4(a) => {
            let o = a.octets();
            DnsName::parse(&format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]))
        }
        IpAddr::V6(a) => {
            let v = u128::from(a);
            let nibbles: Vec<String> = (0..32).map(|k| format!("{:x}", (v >> (4 * k)) & 0xf)).collect();
            DnsName::parse(&format!("{}.ip6.arpa", nibbles.join(".")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normalises() {
        let n = DnsName::parse("DOP370-ipmi.NFRA.nl.");
        assert_eq!(n.to_string(), "dop370-ipmi.nfra.nl");
        assert_eq!(n.labels(), &["dop370-ipmi", "nfra", "nl"]);
    }

    #[test]
    fn parent_chain_walks_to_root() {
        let n = DnsName::parse("dop370-ipmi.nfra.nl");
        let p = n.parent().unwrap();
        assert_eq!(p.to_string(), "nfra.nl");
        assert_eq!(p.parent().unwrap().to_string(), "nl");
        assert!(p.parent().unwrap().parent().unwrap().is_root());
    }

    #[test]
    fn subdomain_and_relative() {
        let host = DnsName::parse("dop370-ipmi.nfra.nl");
        let zone = DnsName::parse("nfra.nl");
        assert!(host.is_subdomain_of(&zone));
        assert!(!host.is_subdomain_of(&DnsName::parse("astron.nl")));
        assert_eq!(host.relative_to(&zone).as_deref(), Some("dop370-ipmi"));
        assert_eq!(zone.relative_to(&zone).as_deref(), Some("@"));
        assert_eq!(host.relative_to(&DnsName::parse("astron.nl")), None);
    }

    #[test]
    fn reverse_name_reverses_octets() {
        assert_eq!(
            reverse_ptr("10.87.3.69".parse().unwrap()).to_string(),
            "69.3.87.10.in-addr.arpa"
        );
    }

    #[test]
    fn reverse_name_ipv6_is_nibble_reversed_ip6_arpa() {
        let n = reverse_ptr("2001:db8::1".parse().unwrap());
        // 32 nibbles, least-significant first, then ip6.arpa.
        assert!(n.to_string().ends_with(".ip6.arpa"));
        assert_eq!(n.to_string(), format!("1.{}8.b.d.0.1.0.0.2.ip6.arpa", "0.".repeat(23)));
    }
}
