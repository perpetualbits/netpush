// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Optional config file at `~/.config/canopy/config.toml` (XDG-aware), mirroring
//! census's `Config`. Every field has a built-in default, so the file is optional;
//! any CLI flag overrides whatever the file — or the default — provides. Secrets are
//! never stored here: the NetBox token comes from `pass` (or `$CANOPY_NETBOX_TOKEN`),
//! and `token_pass` just names the `pass` entry.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The resolved settings canopy runs with. Missing keys fall back per field.
#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct Config {
    /// Default CIDR range to browse.
    pub range: String,
    /// SSH host to run NetBox + DNS queries from (must reach both).
    pub vantage: String,
    /// SSH host on the target L2 for the ARP probe.
    pub probe_host: String,
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
    /// Authoritative server to attempt reverse-DNS **zone transfers** (AXFR) from, e.g.
    /// the reverse-zone master. When set (and transfer is permitted) one AXFR per `/24`
    /// replaces hundreds of per-address `host` lookups — far lighter on the DNS server.
    /// Empty (the default) keeps the per-address sweep.
    pub reverse_axfr_server: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            range: "10.87.3.0/24".into(),
            vantage: "dns1.astron.nl".into(),
            probe_host: "takkie.astron.nl".into(),
            netbox_url: "https://netbox.astron.nl".into(),
            token_pass: "astron/netbox.astron.nl/dns_api_token".into(),
            // A moderate default: gentle on a shared reverse-DNS server, still finishing
            // a /20 in ~a minute. Raise it in the config for a faster sweep on a resolver
            // you know can take it.
            dns_concurrency: 64,
            probe_concurrency: 64,
            reverse_axfr_server: String::new(), // off by default; needs allow-transfer
        }
    }
}

impl Config {
    /// Load the config.
    ///
    /// With an explicit `path` (from `--config`) the file must exist. Otherwise the
    /// default `~/.config/canopy/config.toml` is used **if present**, and built-in
    /// defaults are returned when it is absent — so canopy works with no config at
    /// all. Any field the file omits keeps its default.
    ///
    /// # Errors
    /// Fails if an explicit config path is missing, or the file is unreadable / not
    /// valid TOML.
    pub fn load(explicit: Option<&Path>) -> anyhow::Result<Config> {
        let (path, required) = match explicit {
            Some(p) => (p.to_path_buf(), true),
            None => (config_path(), false),
        };
        if !path.exists() {
            if required {
                anyhow::bail!("config file not found: {}", path.display());
            }
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(&path)?;
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("config parse error in {}: {e}", path.display()))
    }
}

/// `$XDG_CONFIG_HOME/canopy/config.toml`, falling back to `~/.config/canopy/…`.
#[must_use]
pub fn config_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config")
    });
    base.join("canopy").join("config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_yields_defaults() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c.vantage, "dns1.astron.nl");
        assert_eq!(c.token_pass, "astron/netbox.astron.nl/dns_api_token");
    }

    #[test]
    fn partial_file_overrides_only_named_keys() {
        let c: Config = toml::from_str("vantage = \"dns2.astron.nl\"\nrange = \"10.87.0.0/20\"\n").unwrap();
        assert_eq!(c.vantage, "dns2.astron.nl"); // overridden
        assert_eq!(c.range, "10.87.0.0/20"); // overridden
        assert_eq!(c.probe_host, "takkie.astron.nl"); // still the default
    }

    #[test]
    fn path_lands_under_canopy() {
        assert!(config_path().ends_with("canopy/config.toml"));
    }
}
