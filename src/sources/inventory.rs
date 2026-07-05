// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Richer NetBox facts — prefixes (with role/VLAN/site), VLANs, and the devices that
//! addresses are assigned to — so later views and the reconciler can answer "which
//! device/role/rack is this address on?" and "which addresses share a device?".
//!
//! This module **models and parses**; the gather (paginated REST via the vantage) lives on
//! [`NetboxSource::gather_inventory`](super::netbox::NetboxSource::gather_inventory). The
//! parsing is pure and unit-tested against captured JSON, and none of it feeds
//! [`reconcile`](crate::reconcile) — it is a parallel structure the views consume, so the
//! reconcile statuses are untouched.

use std::net::IpAddr;

use anyhow::Context;
use serde_json::Value;

use crate::reconcile::Cidr;

/// A NetBox prefix with the surrounding context the map/tree want (beyond the plain
/// [`Subnet`](crate::reconcile::Subnet) the reconciler uses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    /// The block, e.g. `10.87.3.0/26`.
    pub cidr: Cidr,
    /// Free-text description (may be empty).
    pub description: String,
    /// The NetBox role (e.g. `mgmt`, `loopbacks`), if set.
    pub role: Option<String>,
    /// The VLAN id this prefix is on, if any (join to [`Vlan`] for its name).
    pub vlan: Option<u16>,
    /// The site name, if set.
    pub site: Option<String>,
}

/// A NetBox VLAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vlan {
    /// The 802.1Q VLAN id (1–4094).
    pub vid: u16,
    /// Human name.
    pub name: String,
    /// The site name, if set.
    pub site: Option<String>,
}

/// A NetBox device (the thing an address ultimately sits on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Device name, e.g. `dop21`.
    pub name: String,
    /// The device role (e.g. `server`, `switch`), if set.
    pub role: Option<String>,
    /// The site name, if set.
    pub site: Option<String>,
    /// The rack name, if set.
    pub rack: Option<String>,
}

/// One address assigned to a device's interface — the link from an IP to its device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The assigned address.
    pub addr: IpAddr,
    /// The device the interface belongs to.
    pub device: String,
    /// The interface name the address is on.
    pub interface: String,
}

/// The enriched NetBox inventory gathered for a range.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    /// Prefixes in the range, with role/VLAN/site.
    pub prefixes: Vec<Prefix>,
    /// VLANs (estate-wide), for joining a prefix's `vlan` id to a name.
    pub vlans: Vec<Vlan>,
    /// Devices (estate-wide), for role/rack of an assigned address.
    pub devices: Vec<Device>,
    /// Address → device/interface assignments.
    pub assignments: Vec<Assignment>,
}

impl Inventory {
    /// The device + interface an address is assigned to, if any. The point-query the
    /// device-aware views (a later roadmap phase) build on; exercised by the tests here.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn assignment_for(&self, addr: IpAddr) -> Option<&Assignment> {
        self.assignments.iter().find(|a| a.addr == addr)
    }

    /// Look up a device by name (for its role/rack).
    #[must_use]
    pub fn device(&self, name: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.name == name)
    }

    /// The VLAN name for a VID, if known.
    #[must_use]
    pub fn vlan_name(&self, vid: u16) -> Option<&str> {
        self.vlans.iter().find(|v| v.vid == vid).map(|v| v.name.as_str())
    }

    /// A formatted, aligned report of the inventory for `range` — the `--inventory` output.
    #[must_use]
    pub fn report(&self, range: &Cidr) -> String {
        let cidr = |c: &Cidr| format!("{}/{}", c.base, c.prefix_len);
        let mut s = format!(
            "NetBox inventory for {}: {} prefix(es), {} VLAN(s), {} device(s), {} assignment(s)\n",
            cidr(range),
            self.prefixes.len(),
            self.vlans.len(),
            self.devices.len(),
            self.assignments.len(),
        );

        if !self.prefixes.is_empty() {
            let w = self.prefixes.iter().map(|p| cidr(&p.cidr).len()).max().unwrap_or(0).max("PREFIX".len());
            s.push('\n');
            s.push_str(format!("  {:<w$}  {:<12}  {:<18}  {}", "PREFIX", "ROLE", "VLAN", "DESCRIPTION").trim_end());
            s.push('\n');
            for p in &self.prefixes {
                let vlan = p
                    .vlan
                    .map(|vid| format!("{vid}{}", self.vlan_name(vid).map(|n| format!(" ({n})")).unwrap_or_default()))
                    .unwrap_or_default();
                let line = format!("  {:<w$}  {:<12}  {:<18}  {}", cidr(&p.cidr), p.role.as_deref().unwrap_or(""), vlan, p.description);
                s.push_str(line.trim_end());
                s.push('\n');
            }
        }

        let mut rows: Vec<&Assignment> = self.assignments.iter().filter(|a| range.contains(a.addr)).collect();
        rows.sort_by_key(|a| a.addr);
        if !rows.is_empty() {
            let aw = rows.iter().map(|a| a.addr.to_string().len()).max().unwrap_or(0).max("ADDRESS".len());
            s.push('\n');
            s.push_str(format!("  {:<aw$}  {:<18}  {:<12}  {:<8}  INTERFACE", "ADDRESS", "DEVICE", "ROLE", "RACK").trim_end());
            s.push('\n');
            for a in rows {
                let dev = self.device(&a.device);
                let role = dev.and_then(|d| d.role.as_deref()).unwrap_or("");
                let rack = dev.and_then(|d| d.rack.as_deref()).unwrap_or("");
                let line = format!("  {:<aw$}  {:<18}  {:<12}  {:<8}  {}", a.addr.to_string(), a.device, role, rack, a.interface);
                s.push_str(line.trim_end());
                s.push('\n');
            }
        }
        s
    }
}

/// A nested string field, e.g. `obj["role"]["name"]`.
fn nested_str(obj: &Value, key: &str, sub: &str) -> Option<String> {
    obj.get(key)?.get(sub)?.as_str().map(str::to_string)
}

/// The `results` array of a NetBox list response.
fn results(json: &str) -> anyhow::Result<Vec<Value>> {
    let v: Value = serde_json::from_str(json).context("NetBox response was not JSON")?;
    Ok(v.get("results").and_then(|r| r.as_array()).context("NetBox response had no `results` array")?.clone())
}

/// Parse a NetBox `prefixes` response into rich [`Prefix`]es (role, VLAN id, site, description).
///
/// # Errors
/// Fails if the body is not the expected JSON shape.
pub fn parse_prefixes_rich(json: &str) -> anyhow::Result<Vec<Prefix>> {
    let mut out = Vec::new();
    for o in results(json)? {
        let Some(cidr) = o.get("prefix").and_then(|p| p.as_str()).and_then(|s| Cidr::parse(s).ok()) else {
            continue;
        };
        out.push(Prefix {
            cidr,
            description: o.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string(),
            role: nested_str(&o, "role", "name"),
            vlan: o.get("vlan").and_then(|vl| vl.get("vid")).and_then(Value::as_u64).map(|n| n as u16),
            site: nested_str(&o, "site", "name"),
        });
    }
    Ok(out)
}

/// Parse a NetBox `vlans` response.
///
/// # Errors
/// Fails if the body is not the expected JSON shape.
pub fn parse_vlans(json: &str) -> anyhow::Result<Vec<Vlan>> {
    let mut out = Vec::new();
    for o in results(json)? {
        let Some(vid) = o.get("vid").and_then(Value::as_u64) else {
            continue;
        };
        out.push(Vlan {
            vid: vid as u16,
            name: o.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
            site: nested_str(&o, "site", "name"),
        });
    }
    Ok(out)
}

/// Parse a NetBox `devices` response. Handles both `role` (NetBox ≥ 3.6) and the older
/// `device_role` key for the device's role.
///
/// # Errors
/// Fails if the body is not the expected JSON shape.
pub fn parse_devices(json: &str) -> anyhow::Result<Vec<Device>> {
    let mut out = Vec::new();
    for o in results(json)? {
        let Some(name) = o.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        out.push(Device {
            name: name.to_string(),
            role: nested_str(&o, "role", "name").or_else(|| nested_str(&o, "device_role", "name")),
            site: nested_str(&o, "site", "name"),
            rack: nested_str(&o, "rack", "name"),
        });
    }
    Ok(out)
}

/// Parse a NetBox `ip-addresses` response into address→device assignments, reading each
/// object's `assigned_object` (the interface, and its `device`). Addresses with no
/// assignment are skipped.
///
/// # Errors
/// Fails if the body is not the expected JSON shape.
pub fn parse_ip_assignments(json: &str) -> anyhow::Result<Vec<Assignment>> {
    let mut out = Vec::new();
    for o in results(json)? {
        let Some(addr) = o.get("address").and_then(|a| a.as_str()) else {
            continue;
        };
        let Ok(addr) = addr.split('/').next().unwrap_or(addr).parse::<IpAddr>() else {
            continue;
        };
        let Some(ao) = o.get("assigned_object") else {
            continue;
        };
        let Some(device) = nested_str(ao, "device", "name") else {
            continue;
        };
        out.push(Assignment {
            addr,
            device,
            interface: ao.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rich_prefixes() {
        let json = r#"{"results":[
            {"prefix":"10.87.3.0/26","description":"IPMI","role":{"name":"mgmt"},"vlan":{"vid":100,"name":"mgmt-vl"},"site":{"name":"core"}},
            {"prefix":"10.87.0.0/20","description":"","role":null,"vlan":null,"site":null},
            {"prefix":"junk"}
        ]}"#;
        let p = parse_prefixes_rich(json).unwrap();
        assert_eq!(p.len(), 2); // junk prefix skipped
        assert_eq!(p[0].cidr, Cidr::parse("10.87.3.0/26").unwrap());
        assert_eq!(p[0].role.as_deref(), Some("mgmt"));
        assert_eq!(p[0].vlan, Some(100));
        assert_eq!(p[0].site.as_deref(), Some("core"));
        assert_eq!(p[1].role, None); // null role → None
    }

    #[test]
    fn parses_vlans() {
        let json = r#"{"results":[{"vid":100,"name":"mgmt-vl","site":{"name":"core"}},{"name":"no-vid"}]}"#;
        let v = parse_vlans(json).unwrap();
        assert_eq!(v.len(), 1); // the entry with no vid is skipped
        assert_eq!(v[0].vid, 100);
        assert_eq!(v[0].name, "mgmt-vl");
    }

    #[test]
    fn parses_devices_with_either_role_key() {
        let json = r#"{"results":[
            {"name":"dop21","role":{"name":"server"},"site":{"name":"core"},"rack":{"name":"A1"}},
            {"name":"sw1","device_role":{"name":"switch"}}
        ]}"#;
        let d = parse_devices(json).unwrap();
        assert_eq!(d[0].role.as_deref(), Some("server"));
        assert_eq!(d[0].rack.as_deref(), Some("A1"));
        assert_eq!(d[1].role.as_deref(), Some("switch")); // legacy device_role key
    }

    #[test]
    fn parses_ip_assignments_and_skips_unassigned() {
        let json = r#"{"results":[
            {"address":"10.87.3.68/20","assigned_object":{"name":"iDRAC","device":{"name":"dop21"}}},
            {"address":"10.87.3.90/20"}
        ]}"#;
        let a = parse_ip_assignments(json).unwrap();
        assert_eq!(a.len(), 1); // the unassigned .90 is skipped
        assert_eq!(a[0].addr, "10.87.3.68".parse::<IpAddr>().unwrap());
        assert_eq!(a[0].device, "dop21");
        assert_eq!(a[0].interface, "iDRAC");
    }

    #[test]
    fn inventory_joins_address_to_device_and_reports() {
        let inv = Inventory {
            prefixes: parse_prefixes_rich(r#"{"results":[{"prefix":"10.87.3.0/26","description":"IPMI","role":{"name":"mgmt"},"vlan":{"vid":100}}]}"#).unwrap(),
            vlans: parse_vlans(r#"{"results":[{"vid":100,"name":"mgmt-vl"}]}"#).unwrap(),
            devices: parse_devices(r#"{"results":[{"name":"dop21","role":{"name":"server"},"rack":{"name":"A1"}}]}"#).unwrap(),
            assignments: parse_ip_assignments(r#"{"results":[{"address":"10.87.3.68/20","assigned_object":{"name":"iDRAC","device":{"name":"dop21"}}}]}"#).unwrap(),
        };
        // Address → device join.
        let a = inv.assignment_for("10.87.3.68".parse().unwrap()).unwrap();
        assert_eq!(inv.device(&a.device).unwrap().role.as_deref(), Some("server"));
        assert_eq!(inv.vlan_name(100), Some("mgmt-vl"));
        // Report mentions the joined facts and carries no trailing whitespace.
        let r = inv.report(&Cidr::parse("10.87.0.0/20").unwrap());
        assert!(r.contains("dop21") && r.contains("server") && r.contains("A1") && r.contains("100 (mgmt-vl)"), "{r}");
        assert!(r.lines().all(|l| l == l.trim_end()));
    }
}
