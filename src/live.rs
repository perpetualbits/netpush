// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Gathering live facts from the sources, and fetching the NetBox token. Shared by
//! the CLI (`--live`) and the in-TUI live load (which runs this on a background
//! thread so the UI stays responsive during the ~30 s SSH sweep).

use anyhow::Context;

use crate::config::Config;
use crate::reconcile::{AddressFacts, Cidr};
use crate::sources::{self, dns::DnsSource, netbox::NetboxSource, probe::ProbeSource, FactSource, Vantage};

/// Gather NetBox + DNS + probe facts and merge them, fetching the token first.
///
/// Used by the CLI (`--live`), where prompting for the token inline is fine because
/// no TUI owns the terminal yet. The in-TUI path instead fetches the token separately
/// (with the screen suspended so `pinentry` gets a clean tty) and calls
/// [`gather_live_with_token`].
///
/// # Errors
/// Propagates a token failure, or the first source that fails (SSH, HTTP, DNS).
pub fn gather_live(range: &Cidr, cfg: &Config) -> anyhow::Result<Vec<AddressFacts>> {
    let token = get_token(&cfg.token_pass)?;
    gather_live_with_token(range, cfg, token, |_, _| {})
}

/// Gather and merge the sources using an already-fetched NetBox `token`, reporting
/// progress through `on_progress(fraction, label)` as each stage runs.
///
/// NetBox and DNS run on `cfg.vantage` (they need internal reachability); the ping
/// probe runs on `cfg.probe_host`, which must sit on the target L2. This does no
/// interactive prompting, so it is safe to run on a background thread while the TUI
/// holds the terminal. The DNS reverse sweep dominates the wall-clock, so it owns the
/// bulk (5–92 %) of the bar and drives a determinate fraction from its per-address ticks.
///
/// # Errors
/// Propagates the first source that fails (SSH, HTTP, DNS).
pub fn gather_live_with_token(
    range: &Cidr,
    cfg: &Config,
    token: String,
    on_progress: impl Fn(f32, &str),
) -> anyhow::Result<Vec<AddressFacts>> {
    let vantage = Vantage::new(&cfg.vantage);
    let netbox = NetboxSource { vantage: vantage.clone(), base_url: cfg.netbox_url.clone(), token };
    let dns = DnsSource { vantage: vantage.clone() };
    let probe = ProbeSource { vantage: Vantage::new(&cfg.probe_host) };

    on_progress(0.0, "querying NetBox…");
    let nb = netbox.gather(range).context("NetBox source")?;

    // DNS reverse sweep — the long pole. Map its per-address ticks onto 5 %–92 % of the
    // bar, updating only ~every percent so we don't spam a message per address.
    let total = range.host_count().max(1);
    let step = (total / 100).max(1);
    let dns_facts = dns
        .gather_with_progress(range, |done| {
            if done % step == 0 || done == total {
                let frac = 0.05 + 0.87 * (done as f32 / total as f32);
                on_progress(frac, &format!("DNS reverse sweep {done}/{total}"));
            }
        })
        .context("DNS source")?;

    on_progress(0.93, "probing the wire…");
    let live = probe.gather(range).context("probe source")?;

    on_progress(1.0, "merging…");
    Ok(sources::merge(vec![nb, dns_facts, live]))
}

/// Fetch the NetBox token from `$NETPUSH_NETBOX_TOKEN`, else from `pass`.
///
/// Keeping it out of argv and config: the env var wins for CI, otherwise we shell
/// out to `pass <entry>` and take the first line.
///
/// We inherit the terminal for the child's stdin/stderr so GPG's pinentry can prompt
/// for the passphrase (and its own errors are visible) — capturing everything, as a
/// plain `.output()` does, closes stdin and makes pinentry fail even when the same
/// command works when typed. Only stdout is captured, for the token.
///
/// # Errors
/// Fails if neither source yields a non-empty token.
pub fn get_token(pass_entry: &str) -> anyhow::Result<String> {
    use std::process::{Command, Stdio};

    if let Ok(t) = std::env::var("NETPUSH_NETBOX_TOKEN") {
        if !t.trim().is_empty() {
            return Ok(t.trim().to_string());
        }
    }
    let out = Command::new("pass")
        .arg(pass_entry)
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("running `pass {pass_entry}`"))?
        .wait_with_output()
        .with_context(|| format!("waiting for `pass {pass_entry}`"))?;
    if !out.status.success() {
        anyhow::bail!(
            "`pass {pass_entry}` failed (see any GPG output above). Is the key unlocked? \
             Otherwise run:  export NETPUSH_NETBOX_TOKEN=$(pass {pass_entry})"
        );
    }
    let token = String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or("").trim().to_string();
    if token.is_empty() {
        anyhow::bail!("`pass {pass_entry}` returned no token");
    }
    Ok(token)
}
