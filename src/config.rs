// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Optional config file at `~/.config/netpush/config.toml` (XDG-aware), mirroring
//! census's `Config`. Every field has a built-in default, so the file is optional;
//! any CLI flag overrides whatever the file — or the default — provides. Secrets are
//! never stored here: the NetBox token comes from `pass` (or `$NETPUSH_NETBOX_TOKEN`),
//! and `token_pass` just names the `pass` entry.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The resolved settings netpush runs with. Missing keys fall back per field.
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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            range: "10.87.3.0/24".into(),
            vantage: "dns1.astron.nl".into(),
            probe_host: "takkie.astron.nl".into(),
            netbox_url: "https://netbox.astron.nl".into(),
            token_pass: "astron/netbox.astron.nl/dns_api_token".into(),
        }
    }
}

impl Config {
    /// Load the config.
    ///
    /// With an explicit `path` (from `--config`) the file must exist. Otherwise the
    /// default `~/.config/netpush/config.toml` is used **if present**, and built-in
    /// defaults are returned when it is absent — so netpush works with no config at
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

/// `$XDG_CONFIG_HOME/netpush/config.toml`, falling back to `~/.config/netpush/…`.
#[must_use]
pub fn config_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config")
    });
    base.join("netpush").join("config.toml")
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
    fn path_lands_under_netpush() {
        assert!(config_path().ends_with("netpush/config.toml"));
    }
}
