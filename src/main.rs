// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! `netpush` — a terminal UI that reconciles what NetBox, DNS and the live network
//! each believe about an IP range, then (later) pushes the missing records.
//!
//! For now it runs against a frozen snapshot of the real `10.87.3.0/24` data (see
//! [`fixture`]) so the UI works offline; live NetBox/DNS sources slot in behind the
//! same [`reconcile::AddressFacts`] shape.

mod config;
mod dns;
mod fixture;
mod graph;
mod plan;
mod reconcile;
mod sources;
mod tui;

use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

use config::Config;
use plan::{Allocation, Plan};
use reconcile::{AddressFacts, Cidr};
use sources::{dns::DnsSource, netbox::NetboxSource, probe::ProbeSource, FactSource, Vantage};

/// Command-line options — mirrors census's read-only-by-default posture.
#[derive(Parser, Debug)]
#[command(name = "netpush", about = "Reconcile IP allocation across NetBox, DNS and the live network")]
struct Args {
    /// Config file (default: ~/.config/netpush/config.toml if present).
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// CIDR range to browse. Overrides the config's `range`.
    #[arg(long)]
    range: Option<String>,

    /// Gather facts from the live NetBox/DNS/probe sources instead of the demo data.
    #[arg(long)]
    live: bool,

    /// SSH host to run NetBox + DNS queries from. Overrides the config's `vantage`.
    #[arg(long)]
    vantage: Option<String>,

    /// SSH host on the target L2 for the ARP/ping probe. Overrides `probe_host`.
    #[arg(long)]
    probe_host: Option<String>,

    /// NetBox base URL. Overrides the config's `netbox_url`.
    #[arg(long)]
    netbox_url: Option<String>,

    /// `pass` entry holding the NetBox API token (or set NETPUSH_NETBOX_TOKEN).
    /// Overrides the config's `token_pass`.
    #[arg(long)]
    token_pass: Option<String>,

    /// Allow pushing NetBox/DNS changes (reserved — write path not implemented yet).
    #[arg(long)]
    write: bool,

    /// Walk write flows but send nothing; each push reports what it *would* do.
    #[arg(long)]
    dry_run: bool,

    /// Print the reconciled table to stdout and exit (no TUI). Good for scripts/CI.
    #[arg(long)]
    list: bool,

    /// Plan allocating an address (see --addr) as this FQDN; prints the change plan.
    #[arg(long, value_name = "FQDN")]
    allocate: Option<String>,

    /// The address to allocate (required with --allocate).
    #[arg(long, value_name = "IP")]
    addr: Option<String>,

    /// Network prefix length to record in NetBox for the allocated address. Defaults
    /// to --range's, but the viewing slice (e.g. /24) often differs from the real
    /// network (e.g. 10.87.0.0/20 → pass --alloc-prefix 20).
    #[arg(long, value_name = "LEN")]
    alloc_prefix: Option<u8>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Load the config (optional), then let any CLI flag override it.
    let mut cfg = Config::load(args.config.as_deref())?;
    if let Some(v) = &args.range {
        cfg.range = v.clone();
    }
    if let Some(v) = &args.vantage {
        cfg.vantage = v.clone();
    }
    if let Some(v) = &args.probe_host {
        cfg.probe_host = v.clone();
    }
    if let Some(v) = &args.netbox_url {
        cfg.netbox_url = v.clone();
    }
    if let Some(v) = &args.token_pass {
        cfg.token_pass = v.clone();
    }

    let range = Cidr::parse(&cfg.range).map_err(|e| anyhow::anyhow!(e))?;

    let facts = if args.live {
        gather_live(&range, &cfg)?
    } else {
        demo_facts(&range)
    };

    if let Some(fqdn) = args.allocate.clone() {
        return run_allocation(range, &args, &cfg, &facts, fqdn);
    }

    if args.list {
        list_table(range, &facts);
        return Ok(());
    }

    tui::run(range, facts, args.write, args.dry_run)
}

/// Build and preview (or, with `--write`, apply) a plan to allocate one address.
///
/// The address is checked against the reconciled current state and the plan refuses
/// a non-free target. Without `--live` the free-check runs against offline/demo data,
/// so real allocations should pass `--live`.
fn run_allocation(range: Cidr, args: &Args, cfg: &Config, facts: &[AddressFacts], fqdn: String) -> anyhow::Result<()> {
    let addr: Ipv4Addr = args
        .addr
        .as_deref()
        .context("--allocate requires --addr <IP>")?
        .parse()
        .context("invalid --addr")?;
    anyhow::ensure!(
        range.contains(addr),
        "{addr} is not inside {}/{}",
        range.base,
        range.prefix_len
    );

    let rows = reconcile::reconcile(range, facts);
    let prefix_len = args.alloc_prefix.unwrap_or(range.prefix_len);
    let alloc = Allocation { addr, prefix_len, fqdn };
    let plan = Plan::for_allocation(alloc, &cfg.netbox_url, Some(&rows))?;

    if !args.live {
        eprintln!("note: free-check used offline data; pass --live to check against reality.\n");
    }
    println!("{}", plan.preview());

    if args.write && !args.dry_run {
        eprintln!("--write: applying on {} …", cfg.vantage);
        let token = get_token(&cfg.token_pass)?;
        plan.apply(&Vantage::new(&cfg.vantage), &token)?;
        eprintln!("done.");
    } else {
        println!("(dry-run — pass --write to apply)");
    }
    Ok(())
}

/// The offline demo facts, kept to whatever falls inside `range`.
fn demo_facts(range: &Cidr) -> Vec<AddressFacts> {
    let (demo_range, facts) = fixture::demo();
    if *range == demo_range {
        facts.into_iter().filter(|f| range.contains(f.addr)).collect()
    } else {
        Vec::new()
    }
}

/// Gather NetBox + DNS + probe facts from the live sources and merge them.
///
/// NetBox and DNS run on the `vantage` host (they need internal reachability); the
/// ping probe runs on `probe_host`, which must sit on the target L2.
fn gather_live(range: &Cidr, cfg: &Config) -> anyhow::Result<Vec<AddressFacts>> {
    let vantage = Vantage::new(&cfg.vantage);
    let token = get_token(&cfg.token_pass)?;

    let netbox = NetboxSource {
        vantage: vantage.clone(),
        base_url: cfg.netbox_url.clone(),
        token,
    };
    let dns = DnsSource { vantage: vantage.clone() };
    let probe = ProbeSource { vantage: Vantage::new(&cfg.probe_host) };

    Ok(sources::merge(vec![
        netbox.gather(range).context("NetBox source")?,
        dns.gather(range).context("DNS source")?,
        probe.gather(range).context("probe source")?,
    ]))
}

/// Fetch the NetBox token from `$NETPUSH_NETBOX_TOKEN`, else from `pass`.
///
/// Keeping it out of argv and config: the env var wins for CI, otherwise we shell
/// out to `pass <entry>` and take the first line.
fn get_token(pass_entry: &str) -> anyhow::Result<String> {
    if let Ok(t) = std::env::var("NETPUSH_NETBOX_TOKEN") {
        if !t.trim().is_empty() {
            return Ok(t.trim().to_string());
        }
    }
    let out = std::process::Command::new("pass")
        .arg(pass_entry)
        .output()
        .with_context(|| format!("running `pass {pass_entry}` for the NetBox token"))?;
    if !out.status.success() {
        anyhow::bail!("`pass {pass_entry}` failed; set NETPUSH_NETBOX_TOKEN instead");
    }
    let token = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if token.is_empty() {
        anyhow::bail!("`pass {pass_entry}` returned no token");
    }
    Ok(token)
}

/// Print the reconciled range as plain text: a status tally, then every address
/// that is *not* simply free (the interesting rows). Lets you eyeball the result
/// without a terminal — the counterpart of census's `--ping`.
fn list_table(range: Cidr, facts: &[reconcile::AddressFacts]) {
    let rows = reconcile::reconcile(range, facts);
    let c = reconcile::counts(&rows);
    println!(
        "{}/{} (network {})  free={} allocated={} dns-only={} netbox-only={} live-unreg={} conflict={}",
        range.base, range.prefix_len, range.network(),
        c.free, c.allocated, c.dns_only, c.netbox_only, c.live_unregistered, c.conflict
    );
    for r in rows.iter().filter(|r| !r.status.is_free()) {
        println!(
            "  {:<15} {:<16} {}",
            r.addr.to_string(),
            format!("{:?}", r.status),
            r.name.as_deref().unwrap_or("")
        );
    }
    if let Some(free) = reconcile::first_free(&rows) {
        println!("first free: {free}");
    }
}
