// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Write a discovered DNS estate back into a site file **without clobbering it**.
//!
//! Uses `toml_edit`, so only the `dns_servers` array is rewritten — every other key,
//! comment and blank line in `conf.d/<site>.toml` is left exactly as the operator wrote
//! it. Discovery can't know transport (which bastion reaches a server), so each existing
//! server's hand-set `vantage`/`jump` is carried over, and any server discovery didn't
//! find is kept rather than dropped. Read-only by default: the caller shows [`diff`] first
//! and only writes on an explicit `--write`.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::DnsServer;

/// Merge the `discovered` servers into `text` (a site TOML), returning the new document.
///
/// Per host: discovery's zones win, but the existing entry's `vantage`/`jump` are kept.
/// Servers present in the file but not discovered are preserved. All other keys and the
/// file's comments/layout are untouched.
///
/// # Errors
/// Fails if `text` is not valid TOML.
pub fn merge_estate(text: &str, discovered: &[DnsServer]) -> anyhow::Result<String> {
    let mut doc = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| anyhow::anyhow!("site file is not valid TOML: {e}"))?;

    // Carry over each existing server's hand-set transport, remember which servers are
    // `manual` (never overwrite those), and keep the section's leading comment.
    let mut transport: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut manual_hosts: BTreeSet<String> = BTreeSet::new();
    let mut section_prefix: Option<String> = None;
    if let Some(arr) = doc.get("dns_servers").and_then(|i| i.as_array_of_tables()) {
        for (idx, t) in arr.iter().enumerate() {
            if idx == 0 {
                section_prefix = t.decor().prefix().and_then(|p| p.as_str()).map(str::to_string);
            }
            if let Some(host) = t.get("host").and_then(|h| h.as_str()) {
                let v = t.get("vantage").and_then(|x| x.as_str()).unwrap_or_default().to_string();
                let j = t.get("jump").and_then(|x| x.as_str()).unwrap_or_default().to_string();
                transport.insert(host.to_string(), (v, j));
                if t.get("manual").and_then(|m| m.as_bool()) == Some(true) {
                    manual_hosts.insert(host.to_string());
                }
            }
        }
    }
    // A discovered entry for a manual host is ignored — the hand-curated one wins.
    let write: Vec<&DnsServer> = discovered.iter().filter(|s| !manual_hosts.contains(&s.host)).collect();
    let found: BTreeSet<&str> = write.iter().map(|s| s.host.as_str()).collect();

    // Build the new tables: discovered first (with preserved transport), then any existing
    // server discovery missed — which includes every `manual` entry, kept verbatim.
    let mut tables: Vec<toml_edit::Table> = write.iter().map(|s| server_table(s, transport.get(&s.host))).collect();
    if let Some(arr) = doc.get("dns_servers").and_then(|i| i.as_array_of_tables()) {
        for t in arr.iter() {
            if t.get("host").and_then(|h| h.as_str()).is_some_and(|h| !found.contains(h)) {
                tables.push(t.clone());
            }
        }
    }

    // Spacing: the section comment (or a marker) before the first table, a blank line
    // before each of the rest.
    let first_prefix =
        section_prefix.unwrap_or_else(|| "\n# DNS estate — updated by `canopy --save-estate`.\n".to_string());
    for (i, t) in tables.iter_mut().enumerate() {
        t.decor_mut().set_prefix(if i == 0 { first_prefix.clone() } else { "\n".to_string() });
    }

    let mut arr = toml_edit::ArrayOfTables::new();
    for t in tables {
        arr.push(t);
    }
    doc["dns_servers"] = toml_edit::Item::ArrayOfTables(arr);
    Ok(doc.to_string())
}

/// One `[[dns_servers]]` table for `s`, carrying over `transport` (existing vantage/jump)
/// when present. Empty fields are omitted.
fn server_table(s: &DnsServer, transport: Option<&(String, String)>) -> toml_edit::Table {
    let str_array = |zs: &[String]| {
        let mut a = toml_edit::Array::new();
        for z in zs {
            a.push(z.as_str());
        }
        a
    };
    let mut t = toml_edit::Table::new();
    t.insert("name", toml_edit::value(s.name.as_str()));
    t.insert("host", toml_edit::value(s.host.as_str()));
    if let Some((v, j)) = transport {
        if !v.is_empty() {
            t.insert("vantage", toml_edit::value(v.as_str()));
        }
        if !j.is_empty() {
            t.insert("jump", toml_edit::value(j.as_str()));
        }
    }
    if !s.forward_zones.is_empty() {
        t.insert("forward_zones", toml_edit::value(str_array(&s.forward_zones)));
    }
    if !s.reverse_zones.is_empty() {
        t.insert("reverse_zones", toml_edit::value(str_array(&s.reverse_zones)));
    }
    t
}

/// A minimal line diff of `old` → `new`, showing only the changed block: the common prefix
/// and suffix are trimmed, removed lines are `-`, added lines `+`. Good enough because
/// writeback changes one localized section, and it keeps the change legible before a save.
#[must_use]
pub fn diff(old: &str, new: &str) -> String {
    if old == new {
        return "(no changes)\n".to_string();
    }
    let o: Vec<&str> = old.lines().collect();
    let n: Vec<&str> = new.lines().collect();
    let mut p = 0;
    while p < o.len() && p < n.len() && o[p] == n[p] {
        p += 1;
    }
    let mut s = 0;
    while s < o.len() - p && s < n.len() - p && o[o.len() - 1 - s] == n[n.len() - 1 - s] {
        s += 1;
    }
    let mut out = String::new();
    for line in &o[p..o.len() - s] {
        out.push_str(&format!("- {line}\n"));
    }
    for line in &n[p..n.len() - s] {
        out.push_str(&format!("+ {line}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(name: &str, host: &str, fwd: &[&str], rev: &[&str]) -> DnsServer {
        DnsServer {
            name: name.into(),
            host: host.into(),
            vantage: String::new(),
            jump: String::new(),
            manual: false,
            forward_zones: fwd.iter().map(|z| z.to_string()).collect(),
            reverse_zones: rev.iter().map(|z| z.to_string()).collect(),
        }
    }

    #[test]
    fn merge_preserves_other_keys_and_transport() {
        let existing = "\
vantage = \"dns1.astron.nl\"   # keep me

# the estate
[[dns_servers]]
name = \"lcs\"
host = \"lcs020.control.lofar\"
jump = \"portal.lofar.eu\"
forward_zones = [\"old.lofar\"]
";
        let out = merge_estate(existing, &[server("lcs020-control", "lcs020.control.lofar", &["control.lofar", "cobalt.lofar"], &[])]).unwrap();
        assert!(out.contains("vantage = \"dns1.astron.nl\"   # keep me")); // top-level key + comment kept
        assert!(out.contains("jump = \"portal.lofar.eu\"")); // hand-set transport carried over
        assert!(out.contains("cobalt.lofar")); // discovered zone in
        assert!(!out.contains("old.lofar")); // stale zone replaced
        let cfg: crate::config::Config = toml::from_str(&out).unwrap();
        assert_eq!(cfg.dns_servers.len(), 1);
        assert_eq!(cfg.dns_servers[0].jump, "portal.lofar.eu");
    }

    #[test]
    fn merge_keeps_servers_discovery_missed() {
        let existing = "[[dns_servers]]\nname = \"keep\"\nhost = \"manual.astron.nl\"\nforward_zones = [\"x.nl\"]\n";
        let out = merge_estate(existing, &[server("dns1", "dns1.astron.nl", &["astron.nl"], &[])]).unwrap();
        let cfg: crate::config::Config = toml::from_str(&out).unwrap();
        let hosts: Vec<&str> = cfg.dns_servers.iter().map(|s| s.host.as_str()).collect();
        assert!(hosts.contains(&"dns1.astron.nl")); // discovered added
        assert!(hosts.contains(&"manual.astron.nl")); // existing-not-discovered kept
    }

    #[test]
    fn merge_never_overwrites_a_manual_server() {
        let existing = "\
[[dns_servers]]
name = \"ntserver1\"
host = \"ntserver1.nfra.nl\"
manual = true
reverse_zones = [\"10.0.0.0/8\"]
";
        // Discovery "found" ntserver1 with a bogus split-horizon shadow — it must be ignored.
        let out = merge_estate(existing, &[server("ntserver1", "ntserver1.nfra.nl", &["apertif"], &[])]).unwrap();
        let cfg: crate::config::Config = toml::from_str(&out).unwrap();
        assert_eq!(cfg.dns_servers.len(), 1);
        let s = &cfg.dns_servers[0];
        assert!(s.manual);
        assert_eq!(s.reverse_zones, vec!["10.0.0.0/8"]); // preserved verbatim
        assert!(s.forward_zones.is_empty()); // the discovered "apertif" was NOT applied
    }

    #[test]
    fn merge_into_empty_file_just_adds_servers() {
        let out = merge_estate("", &[server("dns1", "dns1.astron.nl", &["astron.nl"], &[])]).unwrap();
        let cfg: crate::config::Config = toml::from_str(&out).unwrap();
        assert_eq!(cfg.dns_servers.len(), 1);
    }

    #[test]
    fn diff_shows_only_the_changed_block() {
        let d = diff("a\nb\nc\n", "a\nB\nc\n");
        assert_eq!(d, "- b\n+ B\n");
        assert_eq!(diff("x\n", "x\n"), "(no changes)\n");
    }
}
