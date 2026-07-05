// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! A **vantage host**: a machine we can `ssh` into that *can* reach the thing we
//! need (NetBox, internal DNS, or the target L2). canopy itself usually runs off
//! the ASTRON network, so every live query is executed here via SSH, reusing the
//! user's `~/.ssh/config` (bastion jump, keys, etc.).

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

use anyhow::{bail, Context};

/// An SSH-reachable host on (or bridged to) the network we are inspecting.
#[derive(Debug, Clone)]
pub struct Vantage {
    /// The SSH destination, e.g. `"dns1.astron.nl"` — resolved through `~/.ssh/config`.
    pub host: String,
}

impl Vantage {
    /// Make a vantage for `host`.
    #[must_use]
    pub fn new(host: impl Into<String>) -> Self {
        Self { host: host.into() }
    }

    /// Run `remote_cmd` on the vantage and return its stdout.
    ///
    /// # Errors
    /// Fails if ssh cannot be spawned, or the remote command exits non-zero.
    pub fn run(&self, remote_cmd: &str) -> anyhow::Result<String> {
        self.run_inner(remote_cmd, None)
    }

    /// Run `remote_cmd`, feeding `stdin` to it — used to hand a secret (the NetBox
    /// token) to a remote `read VAR` so it never appears in any process's argv.
    ///
    /// # Errors
    /// Fails if ssh cannot be spawned, or the remote command exits non-zero.
    pub fn run_with_stdin(&self, remote_cmd: &str, stdin: &str) -> anyhow::Result<String> {
        self.run_inner(remote_cmd, Some(stdin))
    }

    /// Run `remote_cmd` and call `on_line` for each line of stdout **as it arrives**,
    /// rather than collecting all output at the end. Used to drive a live progress bar:
    /// the remote sweep emits a marker per address, and the caller counts them.
    ///
    /// # Errors
    /// Fails if ssh cannot be spawned, or the remote command exits non-zero.
    pub fn run_streaming(&self, remote_cmd: &str, mut on_line: impl FnMut(&str)) -> anyhow::Result<()> {
        let mut child = Command::new("ssh")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ConnectTimeout=20")
            .arg(&self.host)
            .arg(remote_cmd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning ssh to {}", self.host))?;

        let stdout = child.stdout.take().context("ssh child had no stdout")?;
        for line in BufReader::new(stdout).lines() {
            on_line(&line.context("reading ssh stdout")?);
        }

        let status = child.wait().context("waiting for ssh")?;
        if !status.success() {
            let mut err = String::new();
            if let Some(mut se) = child.stderr.take() {
                let _ = se.read_to_string(&mut err);
            }
            bail!("ssh {} failed: {}", self.host, err.trim());
        }
        Ok(())
    }

    /// Shared implementation: `ssh -o BatchMode=yes <host> <remote_cmd>`, optionally
    /// writing `stdin` to the child. Non-interactive so it never hangs on a prompt.
    fn run_inner(&self, remote_cmd: &str, stdin: Option<&str>) -> anyhow::Result<String> {
        let mut child = Command::new("ssh")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ConnectTimeout=20")
            .arg(&self.host)
            .arg(remote_cmd)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning ssh to {}", self.host))?;

        if let Some(data) = stdin {
            child
                .stdin
                .take()
                .context("ssh child had no stdin")?
                .write_all(data.as_bytes())
                .context("writing to ssh stdin")?;
        }

        let out = child.wait_with_output().context("waiting for ssh")?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!("ssh {} failed: {}", self.host, err.trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}
