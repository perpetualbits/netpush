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
    /// Optional SSH `ProxyJump` chain to reach `host` through a bastion, e.g.
    /// `"bastion.astron.nl"` or a chain `"portal.lofar.eu,inner.host"`. Empty = connect
    /// directly. Passed as `ssh -J <jump>`; `~/.ssh/config` is still honoured on top.
    pub jump: String,
    /// Optional SSH identity (private-key) file, passed as `ssh -i <path>`. `None`
    /// leaves key selection to `~/.ssh/config` / the agent — how the DNS/NetBox
    /// vantages connect; the fabric collector sets it per device (or a site key).
    pub identity: Option<String>,
}

impl Vantage {
    /// Make a vantage for `host`, reached through the `jump` bastion chain — an empty
    /// `jump` means connect directly.
    #[must_use]
    pub fn with_jump(host: impl Into<String>, jump: impl Into<String>) -> Self {
        Self { host: host.into(), jump: jump.into(), identity: None }
    }

    /// Set the SSH identity (private-key) file used to authenticate — `ssh -i <path>`.
    /// Builder-style, so existing call sites (which never set a key) are unaffected;
    /// `None` leaves it unset.
    #[must_use]
    pub fn with_identity(mut self, identity: Option<String>) -> Self {
        self.identity = identity;
        self
    }

    /// The full `ssh` argument list for running `remote_cmd` on this vantage: the fixed
    /// non-interactive options, a `-i <key>` when an identity file is set, a `-J <jump>`
    /// when a jump chain is set, then the host and the command. Pure, so the identity and
    /// jump wiring is unit-testable without spawning ssh.
    #[must_use]
    fn ssh_argv(&self, remote_cmd: &str) -> Vec<String> {
        let mut argv = vec![
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "ConnectTimeout=20".into(),
        ];
        if let Some(id) = &self.identity {
            argv.push("-i".into());
            argv.push(id.clone());
        }
        if !self.jump.is_empty() {
            argv.push("-J".into());
            argv.push(self.jump.clone());
        }
        argv.push(self.host.clone());
        argv.push(remote_cmd.to_string());
        argv
    }

    /// Run `remote_cmd` on the vantage and return its stdout.
    ///
    /// # Errors
    /// Fails if ssh cannot be spawned, or the remote command exits non-zero.
    pub fn run(&self, remote_cmd: &str) -> anyhow::Result<String> {
        self.run_inner(remote_cmd, None)
    }

    /// Run `remote_cmd` and return its stdout together with its exit status, WITHOUT
    /// failing on a non-zero *remote* exit — the fabric collector records per-artifact
    /// failures rather than aborting the whole run. A connection/authentication failure
    /// (ssh exit 255) is still a hard `Err`. On a non-zero remote exit, stderr is
    /// appended to the returned stdout so the stored artifact shows what the device said.
    ///
    /// # Errors
    /// Fails if ssh cannot be spawned, or the connection/auth fails (ssh exit 255).
    pub fn run_capture(&self, remote_cmd: &str) -> anyhow::Result<(String, i32)> {
        let out = Command::new("ssh")
            .args(self.ssh_argv(remote_cmd))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning ssh to {}", self.host))?
            .wait_with_output()
            .context("waiting for ssh")?;
        let code = out.status.code().unwrap_or(-1);
        if code == 255 {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!("ssh {} connection/auth failed: {}", self.host, err.trim());
        }
        let mut body = String::from_utf8_lossy(&out.stdout).into_owned();
        if code != 0 {
            let err = String::from_utf8_lossy(&out.stderr);
            let err = err.trim();
            if !err.is_empty() {
                body.push_str("\n--- stderr ---\n");
                body.push_str(err);
                body.push('\n');
            }
        }
        Ok((body, code))
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
            .args(self.ssh_argv(remote_cmd))
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
            .args(self.ssh_argv(remote_cmd))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_argv_is_direct_without_a_jump() {
        let v = Vantage::with_jump("dns1.astron.nl", "");
        let argv = v.ssh_argv("echo hi");
        assert!(!argv.iter().any(|a| a == "-J")); // no ProxyJump
        // Host and command are the last two arguments.
        assert_eq!(&argv[argv.len() - 2..], &["dns1.astron.nl".to_string(), "echo hi".to_string()]);
    }

    #[test]
    fn ssh_argv_includes_identity_when_set() {
        let v = Vantage::with_jump("10.0.0.1", "").with_identity(Some("/home/u/.ssh/key".into()));
        let argv = v.ssh_argv("show version");
        let i = argv.iter().position(|a| a == "-i").expect("a -i flag");
        assert_eq!(argv[i + 1], "/home/u/.ssh/key");
        // The identity comes before the destination host.
        let h = argv.iter().position(|a| a == "10.0.0.1").unwrap();
        assert!(i < h);
    }

    #[test]
    fn ssh_argv_has_no_identity_flag_by_default() {
        let v = Vantage::with_jump("10.0.0.1", "");
        assert!(!v.ssh_argv("show version").iter().any(|a| a == "-i"));
    }

    #[test]
    fn ssh_argv_inserts_proxyjump_before_the_host() {
        let v = Vantage::with_jump("lcs020.control.lofar", "portal.lofar.eu");
        let argv = v.ssh_argv("dig +short SOA lofar");
        let j = argv.iter().position(|a| a == "-J").expect("a -J flag");
        assert_eq!(argv[j + 1], "portal.lofar.eu"); // the jump chain follows -J
        // -J comes before the destination host, as ssh requires.
        let h = argv.iter().position(|a| a == "lcs020.control.lofar").unwrap();
        assert!(j < h);
    }
}
