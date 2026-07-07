// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation

//! Data-driven **vendor profiles**: a TOML file per platform mapping artifact
//! names to the read-only CLI command that collects them, tagged with the
//! export bundles they belong to. Profiles are validated on load so a
//! config-changing command can never enter the collection path.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// One collectable artifact: a named read-only command and its bundle tags.
#[derive(Debug, Clone)]
pub struct Artifact {
    /// Artifact id, e.g. `version`, `config-set`. Becomes the store filename stem.
    pub name: String,
    /// The exact read-only CLI command to run.
    pub cmd: String,
    /// Export bundles this artifact belongs to (`identity`, `config`, `support`, ...).
    pub bundle: Vec<String>,
    /// Optional format hint for later redaction (`junos-set`, `junos`, ...).
    pub format: Option<String>,
    /// Heavy commands (e.g. `request support information`) are opt-in and streamed.
    pub heavy: bool,
}

/// A platform's profile: its os id and all its artifacts.
#[derive(Debug, Clone)]
pub struct Profile {
    /// Platform id, e.g. `junos-evo`.
    pub os: String,
    /// All artifacts, sorted by artifact name (BTreeMap iteration order — deterministic).
    pub artifacts: Vec<Artifact>,
}

/// Raw TOML shape before validation/flattening.
#[derive(Debug, Deserialize)]
struct ProfileFile {
    os: String,
    #[serde(default)]
    artifact: BTreeMap<String, ArtifactSpec>,
}

#[derive(Debug, Deserialize)]
struct ArtifactSpec {
    cmd: String,
    #[serde(default)]
    bundle: Vec<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    heavy: bool,
}

/// Split `cmd` into pipe stages on `|`, but not a `|` that falls inside a
/// double-quoted argument: Junos `match "error|CRC|drop"` uses `|` for regex
/// alternation in a quoted pattern, not as a pipe separator. Returns `None` if the
/// quoting is unbalanced — an ambiguous command is rejected rather than trusted.
fn split_pipe_stages(cmd: &str) -> Option<Vec<&str>> {
    let mut stages = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    for (i, ch) in cmd.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '|' if !in_quotes => {
                stages.push(&cmd[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if in_quotes {
        return None;
    }
    stages.push(&cmd[start..]);
    Some(stages)
}

/// True if `cmd` is a read-only operational command safe to run during collection.
///
/// The BASE command (before any `|`) must be a `show`/`file show`, or a
/// `request … information` (RSI-style, final token exactly `information`). Every
/// pipe stage after it must be a known safe DISPLAY filter — this is an allow-list,
/// so a mutating/exfiltrating pipe such as `| save scp://host/x` is rejected even
/// though the base is a `show`. A `|` inside a quoted argument (e.g. a `match`
/// regex with alternation) is not treated as a pipe boundary. Everything else —
/// `set`, `delete`, `configure`, `commit`, `request system reboot`,
/// `show … | save …` — is rejected.
#[must_use]
pub fn is_read_only(cmd: &str) -> bool {
    /// Junos pipe modifiers that only read/format output (never write a file, etc.).
    const SAFE_PIPE: &[&str] = &[
        "match", "except", "count", "last", "no-more", "trim", "display", "find",
        "begin", "hold", "resolve", "refresh",
    ];
    let Some(stages) = split_pipe_stages(cmd) else {
        return false;
    };
    let mut stages = stages.into_iter();
    let base = stages.next().unwrap_or("").trim();
    let base_ok = base.starts_with("show ")
        || base == "show"
        || base.starts_with("file show ")
        || (base.starts_with("request ") && base.split_whitespace().last() == Some("information"));
    if !base_ok {
        return false;
    }
    stages.all(|stage| {
        let verb = stage.trim().split_whitespace().next().unwrap_or("");
        SAFE_PIPE.contains(&verb)
    })
}

impl Profile {
    /// Parse and validate a profile from TOML text.
    ///
    /// # Errors
    /// Fails if the TOML is malformed or any artifact command is not read-only.
    pub fn from_toml_str(s: &str) -> Result<Profile> {
        let raw: ProfileFile = toml::from_str(s).context("parsing profile TOML")?;
        let mut artifacts = Vec::with_capacity(raw.artifact.len());
        for (name, spec) in raw.artifact {
            if !is_read_only(&spec.cmd) {
                bail!("profile {}: artifact '{name}' has a non-read-only command: {}", raw.os, spec.cmd);
            }
            artifacts.push(Artifact {
                name,
                cmd: spec.cmd,
                bundle: spec.bundle,
                format: spec.format,
                heavy: spec.heavy,
            });
        }
        Ok(Profile { os: raw.os, artifacts })
    }

    /// Load one of the built-in profiles compiled into the binary.
    ///
    /// # Errors
    /// Fails for an unknown os, or if a built-in profile fails validation.
    pub fn builtin(os: &str) -> Result<Profile> {
        let text = match os {
            "junos-evo" => include_str!("../../profiles/junos-evo.toml"),
            "junos" => include_str!("../../profiles/junos.toml"),
            other => bail!("no built-in profile for os '{other}'"),
        };
        Self::from_toml_str(text)
    }

    /// The artifacts belonging to any of `bundles`; an empty `bundles` means **all**.
    #[must_use]
    pub fn select(&self, bundles: &[String]) -> Vec<&Artifact> {
        if bundles.is_empty() {
            return self.artifacts.iter().collect();
        }
        self.artifacts
            .iter()
            .filter(|a| a.bundle.iter().any(|b| bundles.contains(b)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = r#"
        os = "junos-evo"

        [artifact.version]
        cmd = "show version"
        bundle = ["identity", "support", "forensic"]

        [artifact.config-set]
        cmd = "show configuration | display set"
        bundle = ["config"]
        format = "junos-set"

        [artifact.rsi]
        cmd = "request support information"
        bundle = ["support"]
        heavy = true
    "#;

    #[test]
    fn parses_artifacts_with_defaults() {
        let p = Profile::from_toml_str(P).unwrap();
        assert_eq!(p.os, "junos-evo");
        let v = p.artifacts.iter().find(|a| a.name == "version").unwrap();
        assert_eq!(v.cmd, "show version");
        assert!(!v.heavy);
        assert!(v.format.is_none());
        let rsi = p.artifacts.iter().find(|a| a.name == "rsi").unwrap();
        assert!(rsi.heavy);
    }

    #[test]
    fn select_filters_by_bundle_and_empty_means_all() {
        let p = Profile::from_toml_str(P).unwrap();
        let support: Vec<_> = p.select(&["support".into()]).iter().map(|a| a.name.clone()).collect();
        assert!(support.contains(&"version".to_string()));
        assert!(support.contains(&"rsi".to_string()));
        assert!(!support.contains(&"config-set".to_string()));
        assert_eq!(p.select(&[]).len(), 3); // empty selection = all
    }

    #[test]
    fn rejects_a_config_changing_command() {
        let bad = r#"
            os = "junos"
            [artifact.oops]
            cmd = "set interfaces ge-0/0/0 disable"
            bundle = ["config"]
        "#;
        assert!(Profile::from_toml_str(bad).is_err());
        let reboot = r#"
            os = "junos"
            [artifact.oops]
            cmd = "request system reboot"
        "#;
        assert!(Profile::from_toml_str(reboot).is_err());
    }

    #[test]
    fn read_only_predicate() {
        assert!(is_read_only("show version"));
        assert!(is_read_only("show interfaces terse | no-more"));
        assert!(is_read_only("file show /var/log/messages"));
        assert!(is_read_only("request support information"));
        assert!(!is_read_only("request system reboot"));
        assert!(!is_read_only("set interfaces ge-0/0/0 disable"));
        assert!(!is_read_only("configure"));
        // pipe-bypass attempts must be rejected even though the base is `show`
        assert!(!is_read_only("show configuration | save /tmp/x"));
        assert!(!is_read_only("show configuration | save scp://host/x"));
        // chained safe display pipes are allowed
        assert!(is_read_only("show interfaces extensive | match error | count"));
        assert!(is_read_only("show configuration | display set"));
        // request must be an informational request, by final token
        assert!(is_read_only("request support information"));
        assert!(!is_read_only("request system reboot"));
        assert!(!is_read_only("request support information | save /tmp/x"));
        // a `|` inside a quoted match pattern is regex alternation, not a pipe
        assert!(is_read_only(
            "show interfaces extensive | match \"error|CRC|FEC|drop|framing\""
        ));
        // unbalanced quoting is ambiguous and must be rejected
        assert!(!is_read_only("show configuration | match \"unterminated"));
    }

    #[test]
    fn builtin_profiles_load_and_validate() {
        assert_eq!(Profile::builtin("junos-evo").unwrap().os, "junos-evo");
        assert_eq!(Profile::builtin("junos").unwrap().os, "junos");
        assert!(Profile::builtin("nonesuch").is_err());
    }
}
