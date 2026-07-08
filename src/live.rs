// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Gathering live facts from the sources, and fetching the NetBox token. Shared by
//! the CLI (`--live`) and the in-TUI live load (which runs this on a background
//! thread so the UI stays responsive during the ~30 s SSH sweep).

use anyhow::Context;

use crate::cache::{CacheReport, Store};
use crate::config::Config;
use crate::reconcile::{AddressFacts, Cidr, Subnet};
use crate::sources::estate::DnsEstate;
use crate::sources::{self, dns::DnsSource, netbox::NetboxSource, probe::ProbeSource, FactSource, Vantage};

/// One live gather's result: the per-address facts, plus the NetBox-defined subnets
/// (variable-length) covering the range, used to label where the map cursor sits.
#[derive(Debug, Clone, Default)]
pub struct LiveData {
    /// Reconcilable per-address facts from NetBox, DNS and the probe.
    pub facts: Vec<AddressFacts>,
    /// The real subnets (NetBox prefixes) inside the range.
    pub subnets: Vec<Subnet>,
    /// How the DNS reverse cache fared this gather (fresh vs refreshed zones) — for the status line.
    pub cache: CacheReport,
    /// Forward A/AAAA records `(name, addr)` for the hosts we know about — the input to the
    /// host-level completeness reconciler (P5). Empty on the offline/demo path.
    pub forward: Vec<(String, std::net::IpAddr)>,
}

/// Gather NetBox + DNS + probe facts and merge them, fetching the token first.
///
/// Used by the CLI (`--live`), where prompting for the token inline is fine because
/// no TUI owns the terminal yet. The in-TUI path instead fetches the token separately
/// (with the screen suspended so `pinentry` gets a clean tty) and calls
/// [`gather_live_with_token`].
///
/// # Errors
/// Propagates a token failure, or the first source that fails (SSH, HTTP, DNS).
pub fn gather_live(range: &Cidr, cfg: &Config, site: &str, resweep: bool) -> anyhow::Result<LiveData> {
    let token = get_token(&cfg.token_pass)?;
    // A terse one-liner naming the estate, before the sweep runs (not a wall of zones).
    let estate = DnsEstate::from_config(&cfg.dns_servers)?;
    if !estate.is_empty() {
        eprintln!("Using {}", estate.describe());
    }
    // The on-disk mirror for this site; `None` if the cache dir can't be opened (best-effort — a
    // cache failure never blocks a gather, it just means a full sweep).
    let store = Store::open(crate::config::mirror_dir(site)).ok();
    // A live activity indicator on stderr while the (possibly long) gather runs, so the terminal is
    // never a silent freeze — one overwriting line showing the current stage + its own count.
    let data = gather_live_with_token(range, cfg, token, store.as_ref(), resweep, |frac, label| {
        use std::io::Write;
        eprint!("\r  {:3.0}%  {label:<48}", frac * 100.0);
        let _ = std::io::stderr().flush();
    })?;
    eprintln!(); // end the progress line before whatever prints next (the cache line, or the TUI)
    // Commit this sync to the mirror's git history, so `--since` can diff against it (P15).
    // Best-effort: no `git`, or nothing changed, is a silent no-op.
    if store.is_some() {
        let when = chrono::Utc::now().format("%Y-%m-%d %H:%M:%SZ").to_string();
        crate::history::commit_sync(&crate::config::mirror_dir(site), site, &when);
    }
    Ok(data)
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
    cache: Option<&Store>,
    resweep: bool,
    on_progress: impl Fn(f32, &str),
) -> anyhow::Result<LiveData> {
    // Every SSH target is reached through the site's jump bastion chain (empty = direct).
    let vantage = Vantage::with_jump(&cfg.vantage, &cfg.jump);
    let netbox = NetboxSource { vantage: vantage.clone(), base_url: cfg.netbox_url.clone(), token };
    let dns = DnsSource {
        vantage: vantage.clone(),
        concurrency: cfg.dns_concurrency,
        axfr_server: cfg.reverse_axfr_server.clone(),
        estate: DnsEstate::from_config(&cfg.dns_servers)?,
    };
    // The probe host is reached over its own jump (empty = direct); it is often a bastion,
    // so jumping through the site `jump` to reach it would be wrong.
    let probe = ProbeSource { vantage: Vantage::with_jump(&cfg.probe_host, &cfg.probe_jump), concurrency: cfg.probe_concurrency };

    on_progress(0.0, "querying NetBox…");
    let nb = netbox.gather(range).context("NetBox source")?;
    let subnets = netbox.gather_prefixes(range).context("NetBox prefixes")?;

    // DNS reverse resolution — the long pole. It reports its own 0–1 fraction (per
    // address for the sweep, per zone for AXFR); map that onto 5 %–92 % of the bar. With a cache,
    // unchanged zones load from disk and the sweep is skipped entirely (the common case).
    let dns_progress = |frac: f32, label: &str| on_progress(0.05 + 0.87 * frac, label);
    let (dns_facts, cache) = match cache {
        Some(store) => dns.gather_cached(range, store, resweep, dns_progress).context("DNS source")?,
        None => (dns.gather_with_progress(range, dns_progress).context("DNS source")?, CacheReport::default()),
    };

    // The ping probe is best-effort — the probe host may not sit on the target L2, or may
    // block ICMP — so a failure must NOT abort the whole gather (NetBox + DNS are the core).
    // Warn and carry on with no live facts.
    on_progress(0.93, "probing the wire…");
    let live = probe.gather(range).unwrap_or_else(|e| {
        eprintln!("warning: live probe skipped ({e})");
        Vec::new()
    });

    on_progress(1.0, "merging…");
    let facts = sources::merge(vec![nb, dns_facts, live]);

    // Forward resolution: correlate the names we know (from PTRs + NetBox) to their A/AAAA, so the
    // host-level reconciler can see completeness drift (missing AAAA, forward-without-reverse).
    // Best-effort and separate from the reverse cache — an empty result just means no host report.
    let mut names: Vec<String> = Vec::new();
    for f in &facts {
        if let Some(p) = &f.ptr {
            names.push(p.clone());
        }
        if let Some(n) = f.netbox.as_ref().and_then(|n| n.dns_name.clone()) {
            names.push(n);
        }
    }
    names.sort();
    names.dedup();
    let forward = dns.resolve_forward(&names);

    Ok(LiveData { facts, subnets, cache, forward })
}

/// Gather the enriched NetBox inventory (prefixes, VLANs, devices, address→device
/// assignments) for `range`, fetching the token first. Used by the `--inventory` command.
///
/// # Errors
/// Propagates a token failure or the NetBox fetch.
pub fn gather_inventory(range: &Cidr, cfg: &Config) -> anyhow::Result<crate::sources::inventory::Inventory> {
    let token = get_token(&cfg.token_pass)?;
    let netbox = NetboxSource {
        vantage: Vantage::with_jump(&cfg.vantage, &cfg.jump),
        base_url: cfg.netbox_url.clone(),
        token,
    };
    netbox.gather_inventory(range)
}

/// Gather the native NetBox clusters whose members fall in `range`, fetching the token first.
/// Read-only; used by `--list-groups --live` to fold NetBox's own clusters into the grouping.
///
/// # Errors
/// Propagates a token failure or the NetBox fetch.
pub fn gather_native_clusters(range: &Cidr, cfg: &Config) -> anyhow::Result<Vec<crate::group::NativeCluster>> {
    let token = get_token(&cfg.token_pass)?;
    let netbox = NetboxSource {
        vantage: Vantage::with_jump(&cfg.vantage, &cfg.jump),
        base_url: cfg.netbox_url.clone(),
        token,
    };
    netbox.gather_native_clusters(range)
}

/// Gather the current tag slugs on every IP object in `range` (keyed by address), fetching the
/// token first. Read-only; the live state a `--push-group` preview diffs against.
///
/// # Errors
/// Propagates a token failure or the NetBox fetch.
pub fn gather_ip_tags(range: &Cidr, cfg: &Config) -> anyhow::Result<std::collections::HashMap<std::net::IpAddr, Vec<String>>> {
    let token = get_token(&cfg.token_pass)?;
    let netbox = NetboxSource {
        vantage: Vantage::with_jump(&cfg.vantage, &cfg.jump),
        base_url: cfg.netbox_url.clone(),
        token,
    };
    netbox.gather_ip_tags(range)
}

/// Gather the slugs of every tag defined in NetBox, fetching the token first. Read-only; tells a
/// `--push-group` preview whether a group's tag object already exists.
///
/// # Errors
/// Propagates a token failure or the NetBox fetch.
pub fn gather_tag_slugs(cfg: &Config) -> anyhow::Result<std::collections::HashSet<String>> {
    let token = get_token(&cfg.token_pass)?;
    let netbox = NetboxSource {
        vantage: Vantage::with_jump(&cfg.vantage, &cfg.jump),
        base_url: cfg.netbox_url.clone(),
        token,
    };
    netbox.gather_tag_slugs()
}

/// Fetch the NetBox token from `$CANOPY_NETBOX_TOKEN`, else from `pass`.
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

    if let Ok(t) = std::env::var("CANOPY_NETBOX_TOKEN") {
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
             Otherwise run:  export CANOPY_NETBOX_TOKEN=$(pass {pass_entry})"
        );
    }
    let token = String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or("").trim().to_string();
    if token.is_empty() {
        anyhow::bail!("`pass {pass_entry}` returned no token");
    }
    Ok(token)
}
