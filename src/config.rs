// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Config, layered so canopy can point at one **site** (one organization's network
//! estate) or, later, several. Two layers, both XDG-aware and optional:
//!
//! 1. `~/.config/canopy/config.toml` — personal defaults (token, concurrency…).
//! 2. `~/.config/canopy/conf.d/<site>.toml` — that site's estate (NetBox URL, vantage, jump, DNS servers).
//!
//! The site is chosen with `--site` (default `astron`); its file is merged over the base,
//! and any CLI flag overrides both. Every field has a built-in default, so all files are
//! optional. Secrets are never stored here: the NetBox token comes from `pass` (or
//! `$CANOPY_NETBOX_TOKEN`); `token_pass` just names the `pass` entry.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The resolved settings canopy runs with. Missing keys fall back per field.
#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct Config {
    /// CIDR range to browse. Optional: when unset (and running `--live`) canopy
    /// **discovers** the address space from the sources instead — see `discover`. A
    /// `--range` flag or this key pins a single block for a focused view.
    pub range: Option<String>,
    /// SSH host to run NetBox + DNS queries from (must reach both).
    pub vantage: String,
    /// SSH `ProxyJump` chain used to reach every host canopy SSHes to (the vantage, the
    /// probe host, and each DNS server) — e.g. `"bastion.astron.nl"` or a chain
    /// `"portal.lofar.eu,inner"`. Empty (the default) connects directly. Per-server
    /// overrides live on each `[[dns_servers]]` entry; `~/.ssh/config` is honoured on top.
    pub jump: String,
    /// SSH host on the target L2 for the ARP probe — often a jump/bastion host, which
    /// tends to sit close to the internal networks.
    pub probe_host: String,
    /// SSH `ProxyJump` chain to reach `probe_host`. Empty (the default) connects directly —
    /// the right choice when `probe_host` is itself a bastion (reachable from outside).
    /// Set it only when the probe host sits behind another jump.
    pub probe_jump: String,
    /// NetBox base URL.
    pub netbox_url: String,
    /// The `pass` entry holding the NetBox API token.
    pub token_pass: String,
    /// How many reverse-DNS lookups to run at once during a sweep. Bounds the burst we
    /// put on the resolver (and the authoritative reverse server behind it); a gentler
    /// value is kinder to a shared DNS server at the cost of a slower sweep.
    pub dns_concurrency: usize,
    /// How many ping probes to run at once. Bounds the concurrent processes on the probe
    /// host and the ARP burst on the target L2 — the ping equivalent of `dns_concurrency`.
    pub probe_concurrency: usize,
    /// The forward domains this **site owns** (e.g. `astron.nl`, `lofar.eu`, `control.lofar`).
    /// Two jobs in DNS-estate discovery: they **seed** the SOA probes (so an owned zone is
    /// looked up even when no NetBox host names it), and they **filter** the result — only
    /// servers whose hostname sits under an owned domain are kept, so zones your NetBox
    /// merely *refers* to (a SURFnet-delegated reverse block, a university you peer with)
    /// don't pollute the estate. Empty = no filter (every server found is kept).
    pub domains: Vec<String>,
    /// Authoritative server to attempt reverse-DNS **zone transfers** (AXFR) from, e.g.
    /// the reverse-zone master. When set (and transfer is permitted) one AXFR per `/24`
    /// replaces hundreds of per-address `host` lookups — far lighter on the DNS server.
    /// Empty (the default) keeps the per-address sweep. Acts as the fallback AXFR server
    /// for any reverse zone no listed `dns_servers` entry claims.
    pub reverse_axfr_server: String,
    /// The DNS servers of the estate and the zones each masters. Optional and **empty by
    /// default** — with no entry canopy uses the single `vantage` (plus the global
    /// `reverse_axfr_server`) exactly as before. Listing servers lets canopy route each
    /// reverse-zone transfer to the server that actually masters it (and, later, each
    /// forward write). In TOML these are `[[dns_servers]]` tables.
    pub dns_servers: Vec<DnsServer>,
}

/// One DNS server of the estate and the zones it is authoritative for.
///
/// What: names a server, how to reach it, and which forward domains and reverse CIDR
/// blocks it masters — the routing table canopy uses to send each query (and, later,
/// each edit) to the right box.
///
/// Why: the estate is multi-server (the forward `nfra.nl` zone lives on dns1, the
/// `10.in-addr.arpa` reverse on ntserver1), so "which server owns this zone?" must be
/// **data**, not a hard-coded assumption.
///
/// Units: `forward_zones` are domain suffixes (e.g. `nfra.nl`); `reverse_zones` are CIDR
/// strings (e.g. `10.0.0.0/8`). Every field defaults to empty, so a partial table loads.
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct DnsServer {
    /// Short label for logs and the plan preview (e.g. `dns1`, `ntserver1`).
    pub name: String,
    /// The server's own hostname/IP — the AXFR target passed to `dig … @host`.
    pub host: String,
    /// SSH vantage to reach this server from; empty falls back to the global `vantage`.
    pub vantage: String,
    /// SSH `ProxyJump` chain to reach this server; empty falls back to the global `jump`.
    pub jump: String,
    /// When `true`, this entry is **hand-curated**: `--discover-dns`/`--save-estate` skip it
    /// and never overwrite its zones. Use it to pin a server canopy can't enumerate
    /// reliably — e.g. a Windows/AD box with no `named-checkconf`, whose SOA view is
    /// split-horizon noise.
    pub manual: bool,
    /// Forward zones this server masters, as domain suffixes (e.g. `nfra.nl`).
    pub forward_zones: Vec<String>,
    /// Reverse blocks this server masters, as CIDR strings (e.g. `10.0.0.0/8`).
    pub reverse_zones: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            range: None, // unset → discover the space live; offline falls back to a demo range
            vantage: "dns1.astron.nl".into(),
            jump: String::new(), // direct by default; a site can set a bastion chain
            probe_host: "takkie.astron.nl".into(),
            probe_jump: String::new(), // probe host is reached directly (often a bastion itself)
            netbox_url: "https://netbox.astron.nl".into(),
            token_pass: "astron/netbox.astron.nl/dns_api_token".into(),
            // A moderate default: gentle on a shared reverse-DNS server, still finishing
            // a /20 in ~a minute. Raise it in the config for a faster sweep on a resolver
            // you know can take it.
            dns_concurrency: 64,
            probe_concurrency: 64,
            reverse_axfr_server: String::new(), // off by default; needs allow-transfer
            domains: Vec::new(), // no owned domains → discovery keeps every server it finds
            dns_servers: Vec::new(), // no estate listed → single-vantage behaviour
        }
    }
}

impl Config {
    /// Load the config for `site`, layering `config.toml` then `conf.d/<site>.toml`.
    ///
    /// How: an explicit `--config` path is taken verbatim as the whole config (no
    /// layering) and must exist. Otherwise the base `~/.config/canopy/config.toml` is read
    /// if present, the site file `~/.config/canopy/conf.d/<site>.toml` is deep-merged over
    /// it (site keys win; a whole array like `dns_servers` replaces the base's), and the
    /// result is deserialized — any key none of them set keeps its built-in default. All
    /// files are optional, so canopy still runs with no config at all.
    ///
    /// # Errors
    /// Fails if an explicit config path is missing, or any present file is unreadable or
    /// not valid TOML.
    pub fn load(explicit: Option<&Path>, site: &str) -> anyhow::Result<Config> {
        if let Some(p) = explicit {
            if !p.exists() {
                anyhow::bail!("config file not found: {}", p.display());
            }
            let text = std::fs::read_to_string(p)?;
            return toml::from_str(&text).map_err(|e| anyhow::anyhow!("config parse error in {}: {e}", p.display()));
        }

        let mut merged = toml::value::Table::new();
        if let Some(base) = read_table(&config_path())? {
            merge_table(&mut merged, base);
        }
        if let Some(over) = read_table(&site_path(site))? {
            merge_table(&mut merged, over);
        }
        toml::Value::Table(merged).try_into().map_err(|e| anyhow::anyhow!("config error: {e}"))
    }
}

/// Read a TOML file into a table, or `None` if the file is absent.
///
/// # Errors
/// Fails if the file is unreadable, not valid TOML, or not a table at the top level.
fn read_table(path: &Path) -> anyhow::Result<Option<toml::value::Table>> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)?;
    let value: toml::Value =
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("config parse error in {}: {e}", path.display()))?;
    match value {
        toml::Value::Table(t) => Ok(Some(t)),
        _ => anyhow::bail!("config {} is not a table", path.display()),
    }
}

/// Deep-merge `over` into `base`: nested tables merge key-by-key; anything else (a scalar
/// or an array) replaces wholesale. So a site file overrides just the keys it sets, while
/// a whole `[[dns_servers]]` array replaces the base's — each site defines its own servers.
fn merge_table(base: &mut toml::value::Table, over: toml::value::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(bt)), toml::Value::Table(vt)) => merge_table(bt, vt),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

/// The XDG config directory: `$XDG_CONFIG_HOME`, falling back to `~/.config`.
fn config_dir() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config"))
}

/// `<config-dir>/canopy/config.toml` — the personal base layer.
#[must_use]
pub fn config_path() -> PathBuf {
    config_dir().join("canopy").join("config.toml")
}

/// `<config-dir>/canopy/conf.d/<site>.toml` — one organization's estate.
#[must_use]
pub fn site_path(site: &str) -> PathBuf {
    config_dir().join("canopy").join("conf.d").join(format!("{site}.toml"))
}

/// `<config-dir>/canopy/conf.d/<site>.groups.toml` — the human-asserted group **staging** file
/// for a site: "these hosts/IPs are this cluster", held only until they can be pushed into
/// NetBox. Kept beside the site estate so it is versioned and shared the same way.
#[must_use]
pub fn groups_path(site: &str) -> PathBuf {
    config_dir().join("canopy").join("conf.d").join(format!("{site}.groups.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_yields_defaults() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c.vantage, "dns1.astron.nl");
        assert_eq!(c.token_pass, "astron/netbox.astron.nl/dns_api_token");
        assert!(c.range.is_none()); // no range → discover live (offline uses a demo range)
    }

    #[test]
    fn partial_file_overrides_only_named_keys() {
        let c: Config = toml::from_str("vantage = \"dns2.astron.nl\"\nrange = \"10.87.0.0/20\"\n").unwrap();
        assert_eq!(c.vantage, "dns2.astron.nl"); // overridden
        assert_eq!(c.range.as_deref(), Some("10.87.0.0/20")); // overridden
        assert_eq!(c.probe_host, "takkie.astron.nl"); // still the default
    }

    #[test]
    fn path_lands_under_canopy() {
        assert!(config_path().ends_with("canopy/config.toml"));
    }

    #[test]
    fn site_path_lands_in_conf_d() {
        assert!(site_path("astron").ends_with("canopy/conf.d/astron.toml"));
    }

    #[test]
    fn site_layer_overrides_only_the_keys_it_sets() {
        // Base sets vantage + netbox_url; the site overrides vantage and adds a jump host.
        let mut merged: toml::value::Table =
            toml::from_str("vantage = \"dns1\"\nnetbox_url = \"https://a\"\n").unwrap();
        let over: toml::value::Table = toml::from_str("vantage = \"dns2\"\njump = \"bastion.astron.nl\"\n").unwrap();
        merge_table(&mut merged, over);
        let cfg: Config = toml::Value::Table(merged).try_into().unwrap();
        assert_eq!(cfg.vantage, "dns2"); // site overrode
        assert_eq!(cfg.jump, "bastion.astron.nl"); // site added
        assert_eq!(cfg.netbox_url, "https://a"); // base kept
        assert_eq!(cfg.probe_host, "takkie.astron.nl"); // neither set → default
    }

    #[test]
    fn site_dns_servers_replace_the_base_array() {
        let mut base: toml::value::Table = toml::from_str("[[dns_servers]]\nname = \"old\"\n").unwrap();
        let over: toml::value::Table = toml::from_str("[[dns_servers]]\nname = \"new\"\n").unwrap();
        merge_table(&mut base, over);
        let cfg: Config = toml::Value::Table(base).try_into().unwrap();
        assert_eq!(cfg.dns_servers.len(), 1); // replaced, not appended
        assert_eq!(cfg.dns_servers[0].name, "new");
    }

    #[test]
    fn no_dns_servers_by_default() {
        let c: Config = toml::from_str("").unwrap();
        assert!(c.dns_servers.is_empty()); // empty estate = legacy single-vantage behaviour
    }

    #[test]
    fn dns_servers_table_parses() {
        let c: Config = toml::from_str(
            "\
[[dns_servers]]
name = \"dns1\"
host = \"dns1.astron.nl\"
forward_zones = [\"nfra.nl\", \"astron.nl\"]

[[dns_servers]]
name = \"ntserver1\"
host = \"ntserver1.nfra.nl\"
reverse_zones = [\"10.0.0.0/8\"]
",
        )
        .unwrap();
        assert_eq!(c.dns_servers.len(), 2);
        assert_eq!(c.dns_servers[0].name, "dns1");
        assert_eq!(c.dns_servers[0].forward_zones, vec!["nfra.nl", "astron.nl"]);
        assert!(c.dns_servers[0].vantage.is_empty()); // omitted → empty, falls back to global vantage
        assert!(!c.dns_servers[0].manual); // omitted → not manual
        assert_eq!(c.dns_servers[1].reverse_zones, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn dns_server_manual_flag_parses() {
        let c: Config = toml::from_str("[[dns_servers]]\nname = \"nt\"\nhost = \"nt.nfra.nl\"\nmanual = true\n").unwrap();
        assert!(c.dns_servers[0].manual);
    }
}
