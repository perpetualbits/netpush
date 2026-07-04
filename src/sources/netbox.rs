// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! NetBox as a fact source: the intended IP inventory. We `curl` the REST API from
//! the vantage host (NetBox is internal-only), handing the token over stdin so it
//! never lands in any argv. Only the `dns_name` matters for reconciliation today.

use anyhow::Context;

use super::{FactSource, Vantage};
use crate::reconcile::{AddressFacts, Cidr, NetBoxRecord, Subnet};

/// Queries NetBox for the IP objects in a prefix.
#[derive(Debug, Clone)]
pub struct NetboxSource {
    /// Where to run `curl` from (NetBox is not reachable off-site).
    pub vantage: Vantage,
    /// Base URL, e.g. `"https://netbox.astron.nl"`.
    pub base_url: String,
    /// API token (read scope is enough). Fed to the remote `curl` via stdin.
    pub token: String,
}

impl FactSource for NetboxSource {
    fn gather(&self, range: &Cidr) -> anyhow::Result<Vec<AddressFacts>> {
        // `parent=<network>/<len>` returns every IP object inside the prefix.
        let url = format!(
            "{}/api/ipam/ip-addresses/?parent={}/{}&limit=1000",
            self.base_url.trim_end_matches('/'),
            range.network(),
            range.prefix_len
        );
        // `read TOK` pulls the token from stdin so it is never a command argument.
        let remote = format!("read TOK; curl -sS --max-time 25 -H \"Authorization: Token $TOK\" '{url}'");
        let json = self
            .vantage
            .run_with_stdin(&remote, &format!("{}\n", self.token))
            .context("querying NetBox from the vantage host")?;
        parse_ip_addresses(&json, range)
    }
}

impl NetboxSource {
    /// Fetch the NetBox **prefixes** (defined subnets) that fall within `range`, so the
    /// map can tell you which real, variable-length subnet the cursor is in.
    ///
    /// `within_include=<net>/<len>` returns every prefix inside the range (plus the
    /// range itself). Only `prefix` and a label are kept.
    ///
    /// # Errors
    /// Propagates SSH/HTTP failures or a non-JSON body.
    pub fn gather_prefixes(&self, range: &Cidr) -> anyhow::Result<Vec<Subnet>> {
        let url = format!(
            "{}/api/ipam/prefixes/?within_include={}/{}&limit=1000",
            self.base_url.trim_end_matches('/'),
            range.network(),
            range.prefix_len
        );
        let remote = format!("read TOK; curl -sS --max-time 25 -H \"Authorization: Token $TOK\" '{url}'");
        let json = self
            .vantage
            .run_with_stdin(&remote, &format!("{}\n", self.token))
            .context("querying NetBox prefixes from the vantage host")?;
        parse_prefixes(&json)
    }
}

/// Parse a NetBox `prefixes` list response into [`Subnet`]s.
///
/// How: read the `results` array; for each object take `prefix` (a CIDR string) and a
/// label — the `description`, else the `role`/`vlan` display name, else empty. Anything
/// that does not parse as a CIDR is skipped.
///
/// # Errors
/// Fails if the body is not the expected JSON shape.
pub fn parse_prefixes(json: &str) -> anyhow::Result<Vec<Subnet>> {
    let v: serde_json::Value = serde_json::from_str(json).context("NetBox prefixes response was not JSON")?;
    let results = v
        .get("results")
        .and_then(|r| r.as_array())
        .context("NetBox prefixes response had no `results` array")?;

    let mut out = Vec::new();
    for obj in results {
        let Some(cidr_str) = obj.get("prefix").and_then(|p| p.as_str()) else {
            continue;
        };
        let Ok(cidr) = Cidr::parse(cidr_str) else { continue };
        // Prefer the description; fall back to the role or VLAN display name.
        let name = obj
            .get("description")
            .and_then(|d| d.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| obj.get("role").and_then(|r| r.get("name")).and_then(|n| n.as_str()))
            .or_else(|| obj.get("vlan").and_then(|vl| vl.get("display")).and_then(|n| n.as_str()))
            .unwrap_or("")
            .to_string();
        out.push(Subnet { cidr, name });
    }
    Ok(out)
}

/// Parse a NetBox `ip-addresses` list response into per-address facts.
///
/// How: read the `results` array; for each object take `address` (drop the `/mask`)
/// and `dns_name` (empty string ⇒ no name). Only the `netbox` field is set here.
/// Addresses outside `range` are ignored defensively.
///
/// # Errors
/// Fails if the body is not the expected JSON shape.
pub fn parse_ip_addresses(json: &str, range: &Cidr) -> anyhow::Result<Vec<AddressFacts>> {
    let v: serde_json::Value = serde_json::from_str(json).context("NetBox response was not JSON")?;
    let results = v
        .get("results")
        .and_then(|r| r.as_array())
        .context("NetBox response had no `results` array")?;

    let mut out = Vec::new();
    for obj in results {
        let Some(addr_str) = obj.get("address").and_then(|a| a.as_str()) else {
            continue;
        };
        let ip_part = addr_str.split('/').next().unwrap_or(addr_str);
        let Ok(addr) = ip_part.parse() else { continue };
        if !range.contains(addr) {
            continue;
        }
        let dns_name = obj
            .get("dns_name")
            .and_then(|d| d.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        out.push(AddressFacts {
            addr,
            netbox: Some(NetBoxRecord { dns_name }),
            ptr: None,
            live: false,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_addresses_and_names() {
        let json = r#"{
            "count": 3,
            "next": null,
            "results": [
                {"address": "10.87.3.131/20", "dns_name": ""},
                {"address": "10.87.3.68/20",  "dns_name": "dop21-ipmi.nfra.nl"},
                {"address": "10.99.9.9/24",   "dns_name": "elsewhere.nfra.nl"}
            ]
        }"#;
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let facts = parse_ip_addresses(json, &range).unwrap();
        // The out-of-range .99 address is dropped.
        assert_eq!(facts.len(), 2);

        let by = |o: u8| facts.iter().find(|f| f.addr == std::net::Ipv4Addr::new(10, 87, 3, o)).unwrap();
        assert_eq!(by(131).netbox.as_ref().unwrap().dns_name, None); // empty → None
        assert_eq!(by(68).netbox.as_ref().unwrap().dns_name.as_deref(), Some("dop21-ipmi.nfra.nl"));
        assert!(by(68).ptr.is_none() && !by(68).live); // NetBox sets only its field
    }

    #[test]
    fn rejects_non_json() {
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        assert!(parse_ip_addresses("<html>403</html>", &range).is_err());
    }

    #[test]
    fn parses_prefixes_with_labels() {
        let json = r#"{
            "count": 3,
            "results": [
                {"prefix": "10.87.0.0/20", "description": "LOFAR management"},
                {"prefix": "10.87.3.0/24", "description": "", "role": {"name": "IPMI"}},
                {"prefix": "not-a-cidr",   "description": "junk"}
            ]
        }"#;
        let subs = parse_prefixes(json).unwrap();
        assert_eq!(subs.len(), 2); // the junk prefix is skipped
        assert_eq!(subs[0].cidr, Cidr::parse("10.87.0.0/20").unwrap());
        assert_eq!(subs[0].name, "LOFAR management");
        assert_eq!(subs[1].name, "IPMI"); // empty description → role name
    }
}
