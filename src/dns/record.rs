// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Resource records. The important graph idea lives in [`Record::target_name`]:
//! the record types that point at *another name* (CNAME, NS, PTR) are the edges of
//! the DNS graph, while A/AAAA records are leaves that anchor a name to an address.

use std::fmt;

use super::name::DnsName;

/// The record types canopy handles today. Anything else is kept verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordType {
    /// IPv4 address.
    A,
    /// IPv6 address.
    Aaaa,
    /// Reverse pointer.
    Ptr,
    /// Canonical-name alias (an edge to another name).
    Cname,
    /// Name-server delegation (an edge to another name).
    Ns,
    /// Any other type, kept as its textual token.
    Other(String),
}

impl RecordType {
    /// The zone-file token, e.g. `A`, `PTR`, `CNAME`.
    #[must_use]
    pub fn token(&self) -> &str {
        match self {
            RecordType::A => "A",
            RecordType::Aaaa => "AAAA",
            RecordType::Ptr => "PTR",
            RecordType::Cname => "CNAME",
            RecordType::Ns => "NS",
            RecordType::Other(s) => s,
        }
    }
}

/// One resource record: an owner name, an optional TTL, a type, and its rdata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The name that owns the record.
    pub owner: DnsName,
    /// Explicit TTL, or `None` to inherit the zone default.
    pub ttl: Option<u32>,
    /// The record type.
    pub rtype: RecordType,
    /// The right-hand side, verbatim (an address, a target name, …).
    pub rdata: String,
}

impl Record {
    /// A plain A record.
    #[must_use]
    pub fn a(owner: DnsName, addr: std::net::Ipv4Addr) -> Record {
        Record { owner, ttl: None, rtype: RecordType::A, rdata: addr.to_string() }
    }

    /// A forward address record for either family — `A` for IPv4, `AAAA` for IPv6.
    #[must_use]
    pub fn address(owner: DnsName, addr: std::net::IpAddr) -> Record {
        let rtype = if addr.is_ipv6() { RecordType::Aaaa } else { RecordType::A };
        Record { owner, ttl: None, rtype, rdata: addr.to_string() }
    }

    /// A PTR record pointing at `target`.
    #[must_use]
    pub fn ptr(owner: DnsName, target: &DnsName) -> Record {
        Record { owner, ttl: None, rtype: RecordType::Ptr, rdata: format!("{target}.") }
    }

    /// The name this record *points at*, if any — the graph edge. CNAME/NS/PTR
    /// reference another name; A/AAAA do not (they anchor to an address).
    #[must_use]
    pub fn target_name(&self) -> Option<DnsName> {
        match self.rtype {
            RecordType::Cname | RecordType::Ns | RecordType::Ptr => Some(DnsName::parse(&self.rdata)),
            _ => None,
        }
    }

    /// Render the record as a BIND zone-file line, with the owner written relative
    /// to `zone` (so `dop370-ipmi.nfra.nl` in zone `nfra.nl` becomes `dop370-ipmi`).
    /// Tabs separate the fields, matching the existing hand-edited zones.
    #[must_use]
    pub fn zone_line(&self, zone: &DnsName) -> String {
        let owner = self.owner.relative_to(zone).unwrap_or_else(|| self.owner.to_string());
        let ttl = self.ttl.map(|t| format!("{t}\t")).unwrap_or_default();
        format!("{owner}\t{ttl}IN\t{}\t{}", self.rtype.token(), self.rdata)
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} IN {} {}", self.owner, self.rtype.token(), self.rdata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_line_is_zone_relative() {
        let r = Record::a(DnsName::parse("dop370-ipmi.nfra.nl"), "10.87.3.69".parse().unwrap());
        assert_eq!(r.zone_line(&DnsName::parse("nfra.nl")), "dop370-ipmi\tIN\tA\t10.87.3.69");
        assert_eq!(r.target_name(), None); // A is a leaf, not an edge
    }

    #[test]
    fn ptr_is_an_edge_to_its_target() {
        let owner = super::super::name::reverse_ptr("10.87.3.69".parse().unwrap());
        let r = Record::ptr(owner, &DnsName::parse("dop370-ipmi.nfra.nl"));
        assert_eq!(r.rdata, "dop370-ipmi.nfra.nl.");
        assert_eq!(r.target_name().unwrap().to_string(), "dop370-ipmi.nfra.nl");
    }
}
