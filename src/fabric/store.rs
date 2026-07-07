// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The on-disk **snapshot store**: each collection of a device is written to
//! `<root>/<site>/<device>/<UTC-timestamp>/`, with a `manifest.json` recording
//! provenance and a sha256 per artifact, and a `latest` symlink advanced to the
//! newest snapshot. Versioned so degradation can be shown over time.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One artifact's record in a snapshot manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    /// Artifact name, e.g. `version`, `config`. Becomes the snapshot filename stem.
    pub name: String,
    /// The exact read-only CLI command that was run.
    pub command: String,
    /// Lowercase hex checksum of the artifact body.
    pub sha256: String,
    /// Size in bytes of the artifact body.
    pub bytes: u64,
    /// The command's exit status code.
    pub exit: i32,
}

/// Provenance for a snapshot (everything but the per-artifact records, which the
/// writer fills in as it goes).
#[derive(Debug, Clone)]
pub struct ManifestHead {
    /// Device identifier or name, e.g. `acx-a2-0`.
    pub device: String,
    /// IP address or hostname of the device.
    pub host: String,
    /// SSH ProxyJump chain used to reach the device (empty if direct).
    pub via: String,
    /// Username used for collection.
    pub user: String,
    /// Device's own wall-clock string at collection time (may be skewed).
    pub device_clock: Option<String>,
    /// Seconds the device clock is behind real time (positive = behind).
    pub clock_skew_secs: Option<i64>,
    /// Real-clock UTC timestamp when collection was performed.
    pub collected_at: String,
}

/// The full snapshot manifest written as `manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Device identifier or name, e.g. `acx-a2-0`.
    pub device: String,
    /// IP address or hostname of the device.
    pub host: String,
    /// SSH ProxyJump chain used to reach the device (empty if direct).
    pub via: String,
    /// Username used for collection.
    pub user: String,
    /// Canopy version that performed the collection.
    pub canopy_version: String,
    /// Always true; collection only ran read-only commands.
    pub read_only: bool,
    /// Real-clock UTC timestamp when collection was performed.
    pub collected_at: String,
    /// Device's own wall-clock string at collection time (may be skewed).
    pub device_clock: Option<String>,
    /// Seconds the device clock is behind real time (positive = behind).
    pub clock_skew_secs: Option<i64>,
    /// All artifacts collected in this snapshot with their records.
    pub artifacts: Vec<ArtifactRecord>,
}

/// Lowercase hex sha256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A versioned snapshot store rooted at `root`.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// A store rooted at `root` (e.g. `~/.local/share/canopy/fabric`).
    #[must_use]
    pub fn new(root: PathBuf) -> Store {
        Store { root }
    }

    /// The default store root: `$XDG_DATA_HOME/canopy/fabric` or `~/.local/share/...`.
    #[must_use]
    pub fn default_root() -> PathBuf {
        if let Ok(x) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(x).join("canopy").join("fabric");
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".local/share/canopy/fabric")
    }

    /// Start a new snapshot for `device` under `site`, timestamped `at`.
    ///
    /// # Errors
    /// Fails if the snapshot directory cannot be created.
    pub fn begin(&self, site: &str, device: &str, at: DateTime<Utc>) -> Result<SnapshotWriter> {
        let stamp = at.format("%Y-%m-%dT%H-%M-%SZ").to_string();
        let device_dir = self.root.join(site).join(device);
        let dir = device_dir.join(&stamp);
        fs::create_dir_all(&dir).with_context(|| format!("creating snapshot dir {}", dir.display()))?;
        Ok(SnapshotWriter { device_dir, dir, records: Vec::new() })
    }
}

/// An in-progress snapshot: write artifacts, then `finish` to seal the manifest.
#[derive(Debug)]
pub struct SnapshotWriter {
    device_dir: PathBuf,
    dir: PathBuf,
    records: Vec<ArtifactRecord>,
}

impl SnapshotWriter {
    /// Write one artifact's `body` to `<name>.txt` and record its checksum.
    ///
    /// # Errors
    /// Fails if the file cannot be written.
    pub fn write_artifact(&mut self, name: &str, command: &str, body: &str, exit: i32) -> Result<()> {
        let path = self.dir.join(format!("{name}.txt"));
        fs::write(&path, body).with_context(|| format!("writing artifact {}", path.display()))?;
        self.records.push(ArtifactRecord {
            name: name.to_string(),
            command: command.to_string(),
            sha256: sha256_hex(body.as_bytes()),
            bytes: body.as_bytes().len() as u64,
            exit,
        });
        Ok(())
    }

    /// Seal the snapshot: write `manifest.json`, advance `latest`, return the dir.
    ///
    /// # Errors
    /// Fails if the manifest cannot be written or the `latest` link updated.
    pub fn finish(self, head: ManifestHead) -> Result<PathBuf> {
        let manifest = Manifest {
            device: head.device,
            host: head.host,
            via: head.via,
            user: head.user,
            canopy_version: env!("CARGO_PKG_VERSION").to_string(),
            read_only: true,
            collected_at: head.collected_at,
            device_clock: head.device_clock,
            clock_skew_secs: head.clock_skew_secs,
            artifacts: self.records,
        };
        let json = serde_json::to_string_pretty(&manifest).context("serializing manifest")?;
        fs::write(self.dir.join("manifest.json"), json).context("writing manifest.json")?;
        update_latest(&self.device_dir, &self.dir)?;
        Ok(self.dir)
    }
}

/// Point `<device_dir>/latest` at `target` (replacing any existing link).
fn update_latest(device_dir: &Path, target: &Path) -> Result<()> {
    let link = device_dir.join("latest");
    if link.symlink_metadata().is_ok() {
        fs::remove_file(&link).with_context(|| format!("removing old latest link {}", link.display()))?;
    }
    std::os::unix::fs::symlink(target, &link)
        .with_context(|| format!("linking latest -> {}", target.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn head() -> ManifestHead {
        ManifestHead {
            device: "acx-a2-0".into(),
            host: "10.155.251.23".into(),
            via: "".into(),
            user: "nagtegaal".into(),
            device_clock: Some("2026-07-07 11:49:07".into()),
            clock_skew_secs: Some(0),
            collected_at: "2026-07-07T11:49:10Z".into(),
        }
    }

    #[test]
    fn sha256_is_stable_and_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn snapshot_writes_files_manifest_and_latest() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().to_path_buf());
        let at = chrono::Utc.with_ymd_and_hms(2026, 7, 7, 11, 49, 10).unwrap();

        let mut snap = store.begin("astron", "acx-a2-0", at).unwrap();
        snap.write_artifact("version", "show version", "Model: ACX7024\n", 0).unwrap();
        snap.write_artifact("lldp", "show lldp neighbors", "", 0).unwrap();
        let dir = snap.finish(head()).unwrap();

        // artifact files exist with expected content
        assert_eq!(std::fs::read_to_string(dir.join("version.txt")).unwrap(), "Model: ACX7024\n");
        assert!(dir.join("lldp.txt").exists());

        // manifest parses and records both artifacts + checksums
        let mtext = std::fs::read_to_string(dir.join("manifest.json")).unwrap();
        let m: Manifest = serde_json::from_str(&mtext).unwrap();
        assert_eq!(m.device, "acx-a2-0");
        assert!(m.read_only);
        assert_eq!(m.artifacts.len(), 2);
        let v = m.artifacts.iter().find(|a| a.name == "version").unwrap();
        assert_eq!(v.sha256, sha256_hex(b"Model: ACX7024\n"));
        assert_eq!(v.bytes, 15);

        // `latest` points at this snapshot
        let latest = tmp.path().join("astron").join("acx-a2-0").join("latest");
        assert_eq!(std::fs::read_link(&latest).unwrap(), dir);
    }

    #[test]
    fn latest_advances_to_the_newest_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().to_path_buf());
        let t1 = chrono::Utc.with_ymd_and_hms(2026, 7, 7, 10, 0, 0).unwrap();
        let t2 = chrono::Utc.with_ymd_and_hms(2026, 7, 7, 12, 0, 0).unwrap();

        let mut s1 = store.begin("astron", "acx-a2-0", t1).unwrap();
        s1.write_artifact("version", "show version", "one\n", 0).unwrap();
        s1.finish(head()).unwrap();

        let mut s2 = store.begin("astron", "acx-a2-0", t2).unwrap();
        s2.write_artifact("version", "show version", "two\n", 0).unwrap();
        let dir2 = s2.finish(head()).unwrap();

        let latest = tmp.path().join("astron").join("acx-a2-0").join("latest");
        assert_eq!(std::fs::read_link(&latest).unwrap(), dir2);
    }
}
