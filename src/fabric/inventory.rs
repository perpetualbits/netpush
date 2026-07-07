// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The device **inventory**: the `[[device]]` array in a site TOML file, and how
//! each device is reached (per-device `jump`, falling back to the site jump).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

use crate::sources::vantage::Vantage;

/// One network device we can collect from.
#[derive(Debug, Clone, Deserialize)]
pub struct Device {
    /// Stable short name, e.g. `acx-a2-0`. Used as the store directory name.
    pub name: String,
    /// SSH destination — an IP or a name honoured by `~/.ssh/config`.
    pub host: String,
    /// Optional per-device `ProxyJump` chain; empty/absent falls back to the site jump.
    #[serde(default)]
    pub jump: Option<String>,
    /// Optional SSH username; absent means `~/.ssh/config` / current user decides.
    #[serde(default)]
    pub user: Option<String>,
    /// Optional platform id (`junos-evo`, `junos`); auto-detected on first collect if absent.
    #[serde(default)]
    pub os: Option<String>,
    /// Optional per-device SSH identity (private-key) file, passed as `ssh -i`. Absent
    /// falls back to the collector's site-wide key (or `~/.ssh/config`).
    #[serde(default)]
    pub identity_file: Option<String>,
}

impl Device {
    /// The SSH host string, `user@host` when a user is configured, else `host`.
    #[must_use]
    pub fn ssh_host(&self) -> String {
        match &self.user {
            Some(u) => format!("{u}@{}", self.host),
            None => self.host.clone(),
        }
    }

    /// A [`Vantage`] for reaching this device: the per-device `jump` if set, else
    /// `site_jump` (which may itself be empty for a direct connection), and the
    /// per-device `identity_file` (a site-wide fallback key is applied by the caller
    /// when this is `None`).
    #[must_use]
    pub fn vantage(&self, site_jump: &str) -> Vantage {
        let jump = self.jump.clone().unwrap_or_else(|| site_jump.to_string());
        Vantage::with_jump(self.ssh_host(), jump).with_identity(self.identity_file.clone())
    }
}

/// The parsed `[[device]]` inventory from a site TOML file.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Inventory {
    /// All devices, in file order.
    #[serde(default, rename = "device")]
    pub devices: Vec<Device>,
}

impl Inventory {
    /// Parse an inventory from TOML text (the site file, or a fragment).
    ///
    /// # Errors
    /// Fails if the text is not valid TOML or a `[[device]]` entry is malformed.
    pub fn from_toml_str(s: &str) -> Result<Inventory> {
        toml::from_str(s).context("parsing device inventory TOML")
    }

    /// Load an inventory from a site TOML file on disk.
    ///
    /// # Errors
    /// Fails if the file cannot be read or does not parse.
    pub fn load(path: &Path) -> Result<Inventory> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading inventory file {}", path.display()))?;
        Self::from_toml_str(&text)
    }

    /// Find a device by its `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        [[device]]
        name = "acx-a2-0"
        host = "10.155.251.23"

        [[device]]
        name = "lofar-core-router-re0"
        host = "10.155.250.1"
        jump = "bastion.astron.nl"
        user = "nagtegaal"
        os   = "junos-evo"
    "#;

    #[test]
    fn parses_devices_and_optional_fields() {
        let inv = Inventory::from_toml_str(SAMPLE).unwrap();
        assert_eq!(inv.devices.len(), 2);
        let core = inv.get("lofar-core-router-re0").unwrap();
        assert_eq!(core.host, "10.155.250.1");
        assert_eq!(core.jump.as_deref(), Some("bastion.astron.nl"));
        assert_eq!(core.os.as_deref(), Some("junos-evo"));
        assert!(inv.get("acx-a2-0").unwrap().jump.is_none());
    }

    #[test]
    fn per_device_jump_wins_else_site_default() {
        let inv = Inventory::from_toml_str(SAMPLE).unwrap();
        // device with its own jump keeps it
        let core = inv.get("lofar-core-router-re0").unwrap();
        assert_eq!(core.vantage("site-default").jump, "bastion.astron.nl");
        // device without one falls back to the site jump
        let a2 = inv.get("acx-a2-0").unwrap();
        assert_eq!(a2.vantage("site-default").jump, "site-default");
    }

    #[test]
    fn ssh_host_includes_user_when_set() {
        let inv = Inventory::from_toml_str(SAMPLE).unwrap();
        assert_eq!(inv.get("lofar-core-router-re0").unwrap().ssh_host(), "nagtegaal@10.155.250.1");
        assert_eq!(inv.get("acx-a2-0").unwrap().ssh_host(), "10.155.251.23");
    }

    #[test]
    fn vantage_carries_the_devices_identity_file() {
        let inv = Inventory::from_toml_str(
            r#"[[device]]
               name = "d"
               host = "10.0.0.1"
               identity_file = "/keys/id_rsa""#,
        )
        .unwrap();
        assert_eq!(inv.get("d").unwrap().vantage("").identity.as_deref(), Some("/keys/id_rsa"));
        // absent identity_file -> None (falls back to caller's site key / ssh_config)
        assert!(Inventory::from_toml_str(SAMPLE).unwrap().get("acx-a2-0").unwrap().vantage("").identity.is_none());
    }
}
