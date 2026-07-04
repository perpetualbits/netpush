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
mod live;
mod map;
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
use sources::Vantage;

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

    let (facts, subnets) = if args.live {
        let data = live::gather_live(&range, &cfg)?;
        (data.facts, data.subnets)
    } else {
        (demo_facts(&range), demo_subnets(&range))
    };

    if let Some(fqdn) = args.allocate.clone() {
        return run_allocation(range, &args, &cfg, &facts, fqdn);
    }

    if args.list {
        list_table(range, &facts);
        return Ok(());
    }

    tui::run(range, facts, subnets, args.write, args.dry_run, args.live, cfg)
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
        let token = live::get_token(&cfg.token_pass)?;
        let log = plan.apply(&Vantage::new(&cfg.vantage), &token)?;
        print!("{log}");
        eprintln!("done.");
    } else {
        println!("(dry-run — pass --write to apply)");
    }
    Ok(())
}

/// A few plausible demo subnets (NetBox prefixes) inside `10.87.3.0/24`, kept to those
/// that overlap `range`, so the map's "which subnet am I in?" works offline. Variable
/// lengths on purpose, to show nested subnets (a /26 inside the /24).
fn demo_subnets(range: &Cidr) -> Vec<reconcile::Subnet> {
    use reconcile::Subnet;
    [
        ("10.87.0.0/20", "LOFAR management"),
        ("10.87.3.0/24", "station control"),
        ("10.87.3.0/26", "IPMI / BMC"),
        ("10.87.3.64/26", "compute nodes"),
    ]
    .into_iter()
    .filter_map(|(c, name)| Cidr::parse(c).ok().map(|cidr| Subnet { cidr, name: name.to_string() }))
    // Keep the ones that overlap the browsed range (contains either endpoint).
    .filter(|s| range.contains(s.cidr.network()) || s.cidr.contains(range.network()))
    .collect()
}

/// The offline demo facts, kept to whatever falls inside `range`.
///
/// The fixture describes `10.87.3.0/24`, but people browse it through a wider slice
/// (e.g. `10.87.0.0/20`), so we keep every demo address that `range` *contains* rather
/// than demanding an exact match — otherwise a wider range would render as all-free and
/// look broken. A range that doesn't overlap the fixture simply yields no demo facts.
fn demo_facts(range: &Cidr) -> Vec<AddressFacts> {
    let (_demo_range, facts) = fixture::demo();
    facts.into_iter().filter(|f| range.contains(f.addr)).collect()
}

/// Print the reconciled range as plain text: a status tally, then every address
/// that is *not* simply free (the interesting rows). Lets you eyeball the result
/// without a terminal — the counterpart of census's `--ping`.
fn list_table(range: Cidr, facts: &[reconcile::AddressFacts]) {
    // Lazy: never materialize the whole range. Counts and the non-free rows come from
    // the bounded facts; the first free address is found by scanning host indices
    // (instant on a mostly-empty range).
    let total = range.host_count();
    let map: std::collections::HashMap<std::net::Ipv4Addr, reconcile::AddressFacts> =
        facts.iter().cloned().map(|f| (f.addr, f)).collect();
    let c = reconcile::counts_from_facts(total, &map);
    println!(
        "{}/{} (network {})  total={total} free={} allocated={} dns-only={} netbox-only={} live-unreg={} conflict={}",
        range.base, range.prefix_len, range.network(),
        c.free, c.allocated, c.dns_only, c.netbox_only, c.live_unregistered, c.conflict
    );
    let mut known: Vec<reconcile::AddressRow> = facts.iter().map(reconcile::row_from_facts).collect();
    known.sort_by_key(|r| r.addr);
    for r in known.iter().filter(|r| !r.status.is_free()) {
        println!(
            "  {:<15} {:<16} {}",
            r.addr.to_string(),
            format!("{:?}", r.status),
            r.name.as_deref().unwrap_or("")
        );
    }
    if let Some(free) = (0..total).map(|i| range.host_at(i)).find(|a| !map.contains_key(a)) {
        println!("first free: {free}");
    }
}
