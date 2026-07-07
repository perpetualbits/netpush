// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation

//! The **collect** orchestrator: run a device's selected read-only artifacts over
//! an injected [`CommandRunner`] and write them as one versioned snapshot. The
//! runner seam keeps the whole pipeline unit-testable with a fake; production uses
//! a [`Vantage`](crate::sources::vantage::Vantage) that shells out to `ssh`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};

use crate::fabric::inventory::Device;
use crate::fabric::profile::Profile;
use crate::fabric::store::{ManifestHead, Store};
use crate::sources::vantage::Vantage;

/// The one I/O seam: run a command on a device and return its stdout.
pub trait CommandRunner {
    /// Run `cmd` and return stdout.
    ///
    /// # Errors
    /// Fails if the command cannot be run or exits non-zero.
    fn exec(&self, cmd: &str) -> Result<String>;
}

impl CommandRunner for Vantage {
    fn exec(&self, cmd: &str) -> Result<String> {
        self.run(cmd)
    }
}

/// Best-effort platform id from `show version`: EVO builds say `-EVO`.
#[must_use]
pub fn detect_os(version_output: &str) -> &'static str {
    if version_output.contains("EVO") {
        "junos-evo"
    } else {
        "junos"
    }
}

/// The device's wall clock from a `show system uptime` (`Current time:`) line, as
/// `YYYY-MM-DD HH:MM:SS` (timezone suffix dropped).
#[must_use]
pub fn parse_device_clock(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("Current time:") {
            let t = rest.trim();
            // keep the leading "YYYY-MM-DD HH:MM:SS", drop any trailing " UTC"
            let cleaned: String = t.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
            if !cleaned.is_empty() {
                return Some(cleaned);
            }
        }
    }
    None
}

/// Skew in seconds between `now` and the parsed device clock (positive = device behind).
fn clock_skew(now: DateTime<Utc>, device_clock: &str) -> Option<i64> {
    let dt = NaiveDateTime::parse_from_str(device_clock, "%Y-%m-%d %H:%M:%S").ok()?;
    Some(now.naive_utc().signed_duration_since(dt).num_seconds())
}

/// Collect `device`'s artifacts in `bundles` into a new snapshot under `site`.
///
/// # Errors
/// Fails if a command errors or the snapshot cannot be written.
#[allow(clippy::too_many_arguments)]
pub fn collect(
    runner: &dyn CommandRunner,
    device: &Device,
    profile: &Profile,
    bundles: &[String],
    store: &Store,
    site: &str,
    site_jump: &str,
    now: DateTime<Utc>,
) -> Result<PathBuf> {
    let selected = profile.select(bundles);
    let mut snap = store.begin(site, &device.name, now)?;

    let mut device_clock: Option<String> = None;
    for art in &selected {
        let body = runner
            .exec(&art.cmd)
            .with_context(|| format!("collecting {} on {}", art.name, device.name))?;
        if device_clock.is_none() {
            device_clock = parse_device_clock(&body);
        }
        snap.write_artifact(&art.name, &art.cmd, &body, 0)?;
    }

    let skew = device_clock.as_deref().and_then(|c| clock_skew(now, c));
    let via = device.vantage(site_jump).jump;
    let head = ManifestHead {
        device: device.name.clone(),
        host: device.host.clone(),
        via,
        user: device.user.clone().unwrap_or_default(),
        device_clock,
        clock_skew_secs: skew,
        collected_at: now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    };
    snap.finish(head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fabric::inventory::Inventory;
    use crate::fabric::profile::Profile;
    use crate::fabric::store::{Manifest, Store};
    use chrono::TimeZone;
    use std::collections::HashMap;

    /// A fake runner returning canned output per command — no ssh, no device.
    struct FakeRunner(HashMap<String, String>);
    impl CommandRunner for FakeRunner {
        fn exec(&self, cmd: &str) -> anyhow::Result<String> {
            self.0
                .get(cmd)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("fake has no output for: {cmd}"))
        }
    }

    fn profile() -> Profile {
        Profile::from_toml_str(
            r#"
            os = "junos-evo"
            [artifact.version]
            cmd = "show version"
            bundle = ["identity"]
            [artifact.uptime]
            cmd = "show system uptime"
            bundle = ["identity"]
            "#,
        )
        .unwrap()
    }

    #[test]
    fn detects_evo_vs_classic() {
        assert_eq!(detect_os("Model: ACX7024\nJunos: 22.3R1.9-EVO\n"), "junos-evo");
        assert_eq!(detect_os("Model: ex4300-48p\nJunos: 18.1R3-S8.3\n"), "junos");
    }

    #[test]
    fn parses_current_time_line() {
        let up = "Current time: 2026-07-07 11:49:07 UTC\nSystem booted: ...\n";
        assert_eq!(parse_device_clock(up).as_deref(), Some("2026-07-07 11:49:07"));
        assert!(parse_device_clock("no time here").is_none());
    }

    #[test]
    fn collect_runs_selected_artifacts_and_writes_snapshot() {
        let inv = Inventory::from_toml_str(
            r#"[[device]]
               name = "acx-a2-0"
               host = "10.155.251.23"
               user = "nagtegaal""#,
        )
        .unwrap();
        let dev = inv.get("acx-a2-0").unwrap();

        let mut outputs = HashMap::new();
        outputs.insert("show version".to_string(), "Model: ACX7024\nJunos: 22.3R1.9-EVO\n".to_string());
        outputs.insert("show system uptime".to_string(), "Current time: 2026-07-07 11:49:07 UTC\n".to_string());
        let runner = FakeRunner(outputs);

        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().to_path_buf());
        let now = chrono::Utc.with_ymd_and_hms(2026, 7, 7, 11, 49, 10).unwrap();

        let dir = collect(&runner, dev, &profile(), &["identity".into()], &store, "astron", "", now).unwrap();

        assert_eq!(std::fs::read_to_string(dir.join("version.txt")).unwrap(), "Model: ACX7024\nJunos: 22.3R1.9-EVO\n");
        let m: Manifest = serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(m.device, "acx-a2-0");
        assert_eq!(m.user, "nagtegaal");
        assert!(m.read_only);
        assert_eq!(m.artifacts.len(), 2);
        // device clock parsed from uptime; skew ~3s behind `now`
        assert_eq!(m.device_clock.as_deref(), Some("2026-07-07 11:49:07"));
        assert_eq!(m.clock_skew_secs, Some(3));
    }
}
