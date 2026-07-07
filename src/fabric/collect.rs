// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation

//! The **collect** orchestrator: run a device's selected read-only artifacts over
//! an injected [`CommandRunner`] and write them as one versioned snapshot. The
//! runner seam keeps the whole pipeline unit-testable with a fake; production uses
//! a [`Vantage`](crate::sources::vantage::Vantage) that shells out to `ssh`.

use std::path::PathBuf;

use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, Utc};

use crate::fabric::inventory::Device;
use crate::fabric::profile::Profile;
use crate::fabric::store::{ManifestHead, Store};
use crate::sources::vantage::Vantage;

/// The stdout of a collected command plus its exit status.
#[derive(Debug, Clone)]
pub struct CmdOutput {
    /// What the device returned on stdout (plus stderr appended on a non-zero exit).
    pub stdout: String,
    /// Exit status: `0` ok, `>0` the device ran the command but returned an error,
    /// `-1` a transport/spawn failure recorded as a failed artifact.
    pub exit: i32,
}

/// The one I/O seam: run a command on a device and return its output + exit status.
pub trait CommandRunner {
    /// Run `cmd` and return its stdout and exit status.
    ///
    /// # Errors
    /// Returns `Err` only for a hard transport failure (cannot reach or authenticate
    /// to the device). A command that runs but exits non-zero is returned as `Ok` with
    /// a non-zero [`CmdOutput::exit`], so the collector records it and carries on.
    fn exec(&self, cmd: &str) -> Result<CmdOutput>;
}

impl CommandRunner for Vantage {
    fn exec(&self, cmd: &str) -> Result<CmdOutput> {
        let (stdout, exit) = self.run_capture(cmd)?;
        Ok(CmdOutput { stdout, exit })
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

/// The outcome of a [`collect`] run: where the snapshot landed and how many of its
/// artifacts were collected vs. failed.
#[derive(Debug, Clone)]
pub struct CollectSummary {
    /// The snapshot directory that was written.
    pub dir: PathBuf,
    /// Total artifacts attempted.
    pub total: usize,
    /// How many artifacts failed (device error or transport failure).
    pub failed: usize,
}

/// Collect `device`'s artifacts in `bundles` into a new snapshot under `site`.
///
/// Resilient: a single artifact that fails — the device returns a non-zero exit, or a
/// transport failure prevents the command from running — is recorded as a failed
/// artifact (`exit` non-zero / `-1`, with the error as its body) and collection
/// continues. The snapshot is always sealed, so even an all-failed run is captured as
/// dated evidence.
///
/// # Errors
/// Fails only if the snapshot itself cannot be written to disk.
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
) -> Result<CollectSummary> {
    let selected = profile.select(bundles);
    let total = selected.len();
    let mut snap = store.begin(site, &device.name, now)?;

    let mut device_clock: Option<String> = None;
    let mut failed = 0usize;
    for art in &selected {
        match runner.exec(&art.cmd) {
            Ok(out) => {
                if device_clock.is_none() {
                    device_clock = parse_device_clock(&out.stdout);
                }
                if out.exit != 0 {
                    failed += 1;
                }
                snap.write_artifact(&art.name, &art.cmd, &out.stdout, out.exit)?;
            }
            Err(e) => {
                failed += 1;
                let body = format!("collection failed: {e:#}\n");
                snap.write_artifact(&art.name, &art.cmd, &body, -1)?;
            }
        }
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
    let dir = snap.finish(head)?;
    Ok(CollectSummary { dir, total, failed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fabric::inventory::Inventory;
    use crate::fabric::profile::Profile;
    use crate::fabric::store::{Manifest, Store};
    use chrono::TimeZone;
    use std::collections::HashMap;

    /// A fake runner returning canned output (exit 0) per known command; an unknown
    /// command returns `Err`, simulating a transport failure — no ssh, no device.
    struct FakeRunner(HashMap<String, String>);
    impl CommandRunner for FakeRunner {
        fn exec(&self, cmd: &str) -> anyhow::Result<CmdOutput> {
            match self.0.get(cmd) {
                Some(out) => Ok(CmdOutput { stdout: out.clone(), exit: 0 }),
                None => Err(anyhow::anyhow!("fake has no output for: {cmd}")),
            }
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

        let summary = collect(&runner, dev, &profile(), &["identity".into()], &store, "astron", "", now).unwrap();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.failed, 0);
        let dir = summary.dir;

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

    #[test]
    fn collect_records_a_failed_artifact_and_continues() {
        let inv = Inventory::from_toml_str(
            r#"[[device]]
               name = "d"
               host = "10.0.0.1""#,
        )
        .unwrap();
        let dev = inv.get("d").unwrap();
        // Three artifacts; only two have fake output — "broken" fails but must not
        // abort the run.
        let prof = Profile::from_toml_str(
            r#"
            os = "junos-evo"
            [artifact.version]
            cmd = "show version"
            bundle = ["identity"]
            [artifact.uptime]
            cmd = "show system uptime"
            bundle = ["identity"]
            [artifact.broken]
            cmd = "show does-not-exist"
            bundle = ["identity"]
            "#,
        )
        .unwrap();
        let mut outputs = HashMap::new();
        outputs.insert("show version".to_string(), "Model: ACX7024\n".to_string());
        outputs.insert("show system uptime".to_string(), "Current time: 2026-07-07 11:49:07 UTC\n".to_string());
        let runner = FakeRunner(outputs);

        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().to_path_buf());
        let now = chrono::Utc.with_ymd_and_hms(2026, 7, 7, 11, 49, 10).unwrap();

        let summary = collect(&runner, dev, &prof, &["identity".into()], &store, "astron", "", now).unwrap();
        assert_eq!(summary.total, 3);
        assert_eq!(summary.failed, 1);

        // All three artifacts are still recorded; the good ones collected fine.
        let m: Manifest = serde_json::from_str(&std::fs::read_to_string(summary.dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(m.artifacts.len(), 3);
        assert!(summary.dir.join("version.txt").exists());
        // The failed one has exit -1 and a failure body.
        let broken = m.artifacts.iter().find(|a| a.name == "broken").unwrap();
        assert_eq!(broken.exit, -1);
        let body = std::fs::read_to_string(summary.dir.join("broken.txt")).unwrap();
        assert!(body.contains("collection failed"));
    }
}
