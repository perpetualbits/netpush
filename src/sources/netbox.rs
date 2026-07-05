// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! NetBox as a fact source: the intended IP inventory. We `curl` the REST API from
//! the vantage host (NetBox is internal-only), handing the token over stdin so it
//! never lands in any argv. Only the `dns_name` matters for reconciliation today.

use anyhow::Context;

use super::inventory::{self, Inventory};
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

/// Safety cap on how many pages we will follow — 1000 pages × 1000/page = 1M objects,
/// far beyond any real range, so a pagination bug can't loop forever.
const MAX_PAGES: usize = 1000;

impl FactSource for NetboxSource {
    fn gather(&self, range: &Cidr) -> anyhow::Result<Vec<AddressFacts>> {
        // `parent=<network>/<len>` returns every IP object inside the prefix.
        let first = format!(
            "{}/api/ipam/ip-addresses/?parent={}/{}&limit=1000",
            self.base_url.trim_end_matches('/'),
            range.network(),
            range.prefix_len
        );
        let mut out = Vec::new();
        for json in self.paginate(first)? {
            out.extend(parse_ip_addresses(&json, range)?);
        }
        Ok(out)
    }
}

impl NetboxSource {
    /// Gather the **enriched** NetBox inventory for `range`: rich prefixes (role/VLAN/site)
    /// within it, the VLANs and devices of the estate, and the address→device assignments
    /// inside it — the structure later views and the reconciler consume.
    ///
    /// All four fetches paginate through the vantage with the token over stdin, like every
    /// other NetBox call. Prefixes and assignments are scoped to `range`; VLANs and devices
    /// are estate-wide (so a role/rack lookup works for any assigned device).
    ///
    /// # Errors
    /// Propagates SSH/HTTP failures or a non-JSON body from any of the four endpoints.
    pub fn gather_inventory(&self, range: &Cidr) -> anyhow::Result<Inventory> {
        let base = self.base_url.trim_end_matches('/');
        let (net, pl) = (range.network(), range.prefix_len);

        let mut prefixes = Vec::new();
        for json in self.paginate(format!("{base}/api/ipam/prefixes/?within_include={net}/{pl}&limit=1000"))? {
            prefixes.extend(inventory::parse_prefixes_rich(&json)?);
        }
        let mut vlans = Vec::new();
        for json in self.paginate(format!("{base}/api/ipam/vlans/?limit=1000"))? {
            vlans.extend(inventory::parse_vlans(&json)?);
        }
        let mut devices = Vec::new();
        for json in self.paginate(format!("{base}/api/dcim/devices/?limit=1000"))? {
            devices.extend(inventory::parse_devices(&json)?);
        }
        let mut assignments = Vec::new();
        for json in self.paginate(format!("{base}/api/ipam/ip-addresses/?parent={net}/{pl}&limit=1000"))? {
            assignments.extend(inventory::parse_ip_assignments(&json)?);
        }
        Ok(Inventory { prefixes, vlans, devices, assignments })
    }

    /// Fetch the NetBox **prefixes** (defined subnets) that fall within `range`, so the
    /// map can tell you which real, variable-length subnet the cursor is in.
    ///
    /// `within_include=<net>/<len>` returns every prefix inside the range (plus the
    /// range itself). Only `prefix` and a label are kept.
    ///
    /// # Errors
    /// Propagates SSH/HTTP failures or a non-JSON body.
    pub fn gather_prefixes(&self, range: &Cidr) -> anyhow::Result<Vec<Subnet>> {
        let first = format!(
            "{}/api/ipam/prefixes/?within_include={}/{}&limit=1000",
            self.base_url.trim_end_matches('/'),
            range.network(),
            range.prefix_len
        );
        let mut out = Vec::new();
        for json in self.paginate(first)? {
            out.extend(parse_prefixes(&json)?);
        }
        Ok(out)
    }

    /// Fetch NetBox's **aggregates** — the top-level address space it manages (the big
    /// v4 and v6 allocations, e.g. `10.0.0.0/8` and `2001:db8::/32`). Discovery surveys
    /// these when no `--range` is given.
    ///
    /// Aggregates carry the same `prefix` field as prefixes, so this reuses
    /// [`parse_prefixes`] and keeps only the CIDR (labels are not needed for discovery).
    ///
    /// # Errors
    /// Propagates SSH/HTTP failures or a non-JSON body.
    pub fn gather_aggregates(&self) -> anyhow::Result<Vec<Cidr>> {
        let first = format!("{}/api/ipam/aggregates/?limit=1000", self.base_url.trim_end_matches('/'));
        let mut out = Vec::new();
        for json in self.paginate(first)? {
            out.extend(parse_prefixes(&json)?.into_iter().map(|s| s.cidr));
        }
        Ok(out)
    }

    /// Fetch the NetBox prefixes worth **surveying** across the whole IPAM (not filtered to
    /// a range): every prefix **except** those with `status = container`. Discovery uses
    /// these — many NetBox installs carve the space into prefixes and leave the Aggregates
    /// table empty, so prefixes are where the real subnets live; container prefixes (the
    /// supernets that just group other prefixes, like a `10.0.0.0/8` parent) are skipped so
    /// we survey their children, not the whole `/8`.
    ///
    /// # Errors
    /// Propagates SSH/HTTP failures or a non-JSON body.
    pub fn gather_survey_prefixes(&self) -> anyhow::Result<Vec<Cidr>> {
        let first = format!("{}/api/ipam/prefixes/?limit=1000", self.base_url.trim_end_matches('/'));
        let mut out = Vec::new();
        for json in self.paginate(first)? {
            out.extend(parse_survey_prefixes(&json)?);
        }
        Ok(out)
    }

    /// Fetch every registered `dns_name` from NetBox (all ip-addresses, whole IPAM). Used
    /// by DNS-estate discovery to learn which forward domains are in use, so their
    /// authoritative servers can be looked up.
    ///
    /// # Errors
    /// Propagates SSH/HTTP failures or a non-JSON body.
    pub fn gather_dns_names(&self) -> anyhow::Result<Vec<String>> {
        let first = format!("{}/api/ipam/ip-addresses/?limit=1000", self.base_url.trim_end_matches('/'));
        let mut out = Vec::new();
        for json in self.paginate(first)? {
            out.extend(parse_dns_names(&json)?);
        }
        Ok(out)
    }

    /// Follow NetBox's `next` links from `first`, returning every page's raw JSON body.
    ///
    /// NetBox paginates list endpoints (`{count, next, results}`); a single `limit=1000`
    /// page silently drops the overflow, so we walk the `next` URLs until there are none.
    /// Capped at [`MAX_PAGES`] so a malformed `next` can't loop forever.
    ///
    /// # Errors
    /// Propagates SSH/HTTP failures, or bails if the page cap is hit.
    fn paginate(&self, first: String) -> anyhow::Result<Vec<String>> {
        let mut pages = Vec::new();
        let mut url = Some(first);
        while let Some(u) = url {
            anyhow::ensure!(pages.len() < MAX_PAGES, "NetBox returned more than {MAX_PAGES} pages");
            let json = self.curl(&u)?;
            url = next_url(&json);
            pages.push(json);
        }
        Ok(pages)
    }

    /// Run an authenticated `curl` for `url` on the vantage, returning the body. The
    /// token is fed via stdin (`read TOK`) so it is never a command argument.
    ///
    /// # Errors
    /// Propagates SSH failures.
    fn curl(&self, url: &str) -> anyhow::Result<String> {
        let remote = format!("read TOK; curl -sS --max-time 25 -H \"Authorization: Token $TOK\" '{url}'");
        self.vantage
            .run_with_stdin(&remote, &format!("{}\n", self.token))
            .context("querying NetBox from the vantage host")
    }
}

/// The `next` page URL from a NetBox list response, or `None` at the last page (also
/// `None` on a body that doesn't parse — the per-page parser reports that error).
fn next_url(json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| v.get("next").and_then(|n| n.as_str()).map(str::to_string))
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

/// Parse a NetBox `prefixes` response into the CIDRs worth **surveying** — every prefix
/// except those with `status = container`.
///
/// A container prefix models a parent range that merely groups other prefixes (an RFC1918
/// supernet, an RIR-style parent) rather than a subnet that holds hosts, so canopy surveys
/// its children instead of the container itself. A prefix with no `status` is kept
/// (treated as a real subnet).
///
/// # Errors
/// Fails if the body is not the expected JSON shape.
pub fn parse_survey_prefixes(json: &str) -> anyhow::Result<Vec<Cidr>> {
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
        let status = obj.get("status").and_then(|s| s.get("value")).and_then(|x| x.as_str()).unwrap_or("");
        if status == "container" {
            continue; // a supernet grouping other prefixes, not a subnet to survey
        }
        out.push(cidr);
    }
    Ok(out)
}

/// The non-empty `dns_name`s from a NetBox `ip-addresses` response.
///
/// # Errors
/// Fails if the body is not the expected JSON shape.
pub fn parse_dns_names(json: &str) -> anyhow::Result<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(json).context("NetBox response was not JSON")?;
    let results = v
        .get("results")
        .and_then(|r| r.as_array())
        .context("NetBox response had no `results` array")?;
    Ok(results
        .iter()
        .filter_map(|o| o.get("dns_name").and_then(|d| d.as_str()).filter(|s| !s.is_empty()).map(str::to_string))
        .collect())
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
    fn next_url_follows_then_stops() {
        let mid = r#"{"count": 1500, "next": "https://nb/api/ipam/ip-addresses/?limit=1000&offset=1000", "results": []}"#;
        let last = r#"{"count": 1500, "next": null, "results": []}"#;
        assert_eq!(next_url(mid).as_deref(), Some("https://nb/api/ipam/ip-addresses/?limit=1000&offset=1000"));
        assert_eq!(next_url(last), None);
        assert_eq!(next_url("<html>oops</html>"), None); // unparseable → no next (parser reports the error)
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

    #[test]
    fn survey_prefixes_skip_containers() {
        let json = r#"{
            "results": [
                {"prefix": "10.0.0.0/8",    "status": {"value": "container"}},
                {"prefix": "10.87.0.0/20",  "status": {"value": "active"}},
                {"prefix": "10.87.3.0/24"},
                {"prefix": "not-a-cidr",    "status": {"value": "active"}}
            ]
        }"#;
        let cidrs = parse_survey_prefixes(json).unwrap();
        // The /8 container is skipped; the active /20 and the status-less /24 are kept; junk dropped.
        assert_eq!(cidrs, vec![Cidr::parse("10.87.0.0/20").unwrap(), Cidr::parse("10.87.3.0/24").unwrap()]);
    }
}
