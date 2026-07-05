// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! `canopy` — a terminal UI that reconciles what NetBox, DNS and the live network
//! each believe about an IP range, then (later) pushes the missing records.
//!
//! For now it runs against a frozen snapshot of the real `10.87.3.0/24` data (see
//! [`fixture`]) so the UI works offline; live NetBox/DNS sources slot in behind the
//! same [`reconcile::AddressFacts`] shape.

mod config;
mod discover;
mod dns;
mod dns_discovery;
mod fixture;
mod graph;
mod live;
mod map;
mod plan;
mod reconcile;
mod site_write;
mod sources;
mod tui;

use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

use config::Config;
use plan::{Allocation, Plan};
use reconcile::{AddressFacts, Cidr};
use sources::Vantage;

/// Command-line options — mirrors census's read-only-by-default posture.
#[derive(Parser, Debug)]
#[command(name = "canopy", about = "Reconcile IP allocation across NetBox, DNS and the live network")]
struct Args {
    /// Config file (default: ~/.config/canopy/config.toml if present). Given, it is used
    /// verbatim and the per-site layer is skipped.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Which site (organization estate) to use — layers ~/.config/canopy/conf.d/<site>.toml
    /// over the base config.
    #[arg(long, value_name = "NAME", default_value = "astron")]
    site: String,

    /// CIDR range to browse. Overrides the config's `range`. When neither is set and
    /// `--live` is given, canopy discovers the address space from the sources instead.
    #[arg(long)]
    range: Option<String>,

    /// Gather facts from the live NetBox/DNS/probe sources instead of the demo data.
    #[arg(long)]
    live: bool,

    /// Discover the DNS estate (which server masters which zones) via SOA lookups on the
    /// vantage, and print it as a [[dns_servers]] block for conf.d/<site>.toml. Read-only.
    #[arg(long)]
    discover_dns: bool,

    /// Discover the DNS estate and merge it into conf.d/<site>.toml (preserving comments and
    /// each server's vantage/jump). Shows a diff; only writes with --write.
    #[arg(long)]
    save_estate: bool,

    /// Print the enriched NetBox inventory for the range — prefixes (role/VLAN/site) and the
    /// devices addresses are assigned to (name/role/rack). Read-only.
    #[arg(long)]
    inventory: bool,

    /// SSH host to run NetBox + DNS queries from. Overrides the config's `vantage`.
    #[arg(long)]
    vantage: Option<String>,

    /// SSH host on the target L2 for the ARP/ping probe. Overrides `probe_host`.
    #[arg(long)]
    probe_host: Option<String>,

    /// NetBox base URL. Overrides the config's `netbox_url`.
    #[arg(long)]
    netbox_url: Option<String>,

    /// `pass` entry holding the NetBox API token (or set CANOPY_NETBOX_TOKEN).
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

    // Load the config for the selected site (optional), then let any CLI flag override it.
    let mut cfg = Config::load(args.config.as_deref(), &args.site)?;
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

    // Discover the DNS estate and print it for the site config (read-only).
    if args.discover_dns {
        return run_discover_dns(&cfg);
    }

    // Discover the DNS estate and merge it into the site file (diff; --write to save).
    if args.save_estate {
        return run_save_estate(&args, &cfg);
    }

    // Print the enriched NetBox inventory for the range (read-only).
    if args.inventory {
        let range = Cidr::parse(args.range.as_deref().or(cfg.range.as_deref()).unwrap_or(DEMO_RANGE)).map_err(|e| anyhow::anyhow!(e))?;
        print!("{}", live::gather_inventory(&range, &cfg)?.report(&range));
        return Ok(());
    }

    // The range to survey: `--range` wins, else the config's `range`. `None` means
    // "not pinned" — live runs then discover the address space from the sources.
    let pinned_range = args.range.clone().or_else(|| cfg.range.clone());

    if args.live && pinned_range.is_none() {
        anyhow::ensure!(
            args.allocate.is_none(),
            "--allocate needs an explicit --range (discovery surveys many blocks, not one address)"
        );
        return run_discovery(&args, &cfg);
    }

    // Offline (or a pinned range): browse a single block. With nothing pinned and no live
    // sources to discover from, fall back to the demo range so canopy still runs offline.
    let range = Cidr::parse(pinned_range.as_deref().unwrap_or(DEMO_RANGE)).map_err(|e| anyhow::anyhow!(e))?;

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

    tui::run(range, facts, subnets, args.write, args.dry_run, args.live, cfg, None)
}

/// Discover the DNS estate (which server masters which zones) and print it as a
/// `[[dns_servers]]` block ready to paste into `conf.d/<site>.toml`. Read-only: it fetches
/// the NetBox forward names and the surveyed blocks, then does SOA lookups on the vantage.
///
/// # Errors
/// Propagates the token fetch, the NetBox/discovery fetch, or a bad reverse zone.
fn run_discover_dns(cfg: &Config) -> anyhow::Result<()> {
    let token = live::get_token(&cfg.token_pass)?;
    let blocks: Vec<Cidr> = discover::discover(cfg, &token)?.into_iter().map(|b| b.cidr).collect();
    eprintln!("Probing SOA for {} block(s) and their forward domains …", blocks.len());
    let servers = dns_discovery::discover_dns_servers(cfg, &token, &blocks)?;
    if servers.is_empty() {
        eprintln!("(no authoritative servers found — check the vantage can `dig`)");
        return Ok(());
    }
    print!("{}", dns_discovery::render_dns_servers(&servers));
    Ok(())
}

/// Discover the DNS estate and merge it into `conf.d/<site>.toml`, preserving the file's
/// comments and each server's hand-set `vantage`/`jump`. Prints the diff; writes only with
/// `--write` (and not `--dry-run`), matching canopy's read-only-by-default posture.
///
/// # Errors
/// Propagates the token/discovery failures, a merge (TOML) error, or a write failure.
fn run_save_estate(args: &Args, cfg: &Config) -> anyhow::Result<()> {
    let path = config::site_path(&args.site);
    let current = std::fs::read_to_string(&path).unwrap_or_default(); // empty ⇒ a fresh file

    let token = live::get_token(&cfg.token_pass)?;
    let blocks: Vec<Cidr> = discover::discover(cfg, &token)?.into_iter().map(|b| b.cidr).collect();
    eprintln!("Probing SOA for {} block(s) and their forward domains …", blocks.len());
    let servers = dns_discovery::discover_dns_servers(cfg, &token, &blocks)?;
    anyhow::ensure!(!servers.is_empty(), "discovered no DNS servers; nothing to save");

    let merged = site_write::merge_estate(&current, &servers)?;
    println!("--- {} (proposed) ---", path.display());
    print!("{}", site_write::diff(&current, &merged));

    if args.write && !args.dry_run {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &merged)?;
        eprintln!("wrote {}", path.display());
    } else {
        eprintln!("(dry-run — pass --write to save to {})", path.display());
    }
    Ok(())
}

/// The block browsed offline when no range is pinned — the fixture's `/24`, so canopy
/// still runs and shows the demo data without a config or live sources.
const DEMO_RANGE: &str = "10.87.3.0/24";

/// Discover the address space live and survey it: NetBox aggregates + the estate's
/// reverse zones (see [`discover`]). With `--list`, print a summary then reconcile every
/// discovered block; otherwise open the TUI on the first block, naming the rest in the
/// status line (multi-block navigation is a later view).
///
/// # Errors
/// Propagates the token fetch, discovery, or per-block gather failures; bails if nothing
/// was discovered (the operator should then pass an explicit `--range`).
fn run_discovery(args: &Args, cfg: &Config) -> anyhow::Result<()> {
    let token = live::get_token(&cfg.token_pass)?;
    let blocks = discover::discover(cfg, &token)?;
    anyhow::ensure!(
        !blocks.is_empty(),
        "discovery found no address space (no NetBox aggregates and no reverse zones); pass --range to survey a specific block"
    );

    if args.list {
        print!("{}", discover::summary(&blocks));
        for b in &blocks {
            let data = live::gather_live_with_token(&b.cidr, cfg, token.clone(), |_, _| {})?;
            println!();
            list_table(b.cidr, &data.facts);
        }
        return Ok(());
    }

    // The TUI is single-block for now: browse the first discovered block and name the set.
    let primary = discover::primary(&blocks).context("no primary block to browse")?;
    let note = format!(
        "discovered {} block(s); browsing {}/{} — see --list for all",
        blocks.len(),
        primary.cidr.base,
        primary.cidr.prefix_len
    );
    let data = live::gather_live_with_token(&primary.cidr, cfg, token, |_, _| {})?;
    tui::run(primary.cidr, data.facts, data.subnets, args.write, args.dry_run, true, cfg.clone(), Some(note))
}

/// Build and preview (or, with `--write`, apply) a plan to allocate one address.
///
/// The address is checked against the reconciled current state and the plan refuses
/// a non-free target. Without `--live` the free-check runs against offline/demo data,
/// so real allocations should pass `--live`.
fn run_allocation(range: Cidr, args: &Args, cfg: &Config, facts: &[AddressFacts], fqdn: String) -> anyhow::Result<()> {
    let addr: IpAddr = args
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

    // The free-check needs only the target address's current row — never materialize the
    // whole range (a v6 /48 is 2^80 addresses). Build that one row from the bounded facts.
    let target = facts
        .iter()
        .find(|f| f.addr == addr)
        .map(reconcile::row_from_facts)
        .unwrap_or(reconcile::AddressRow { addr, status: reconcile::AddressStatus::Free, name: None });
    let prefix_len = args.alloc_prefix.unwrap_or(range.prefix_len);
    let alloc = Allocation { addr, prefix_len, fqdn };
    let plan = Plan::for_allocation(alloc, &cfg.netbox_url, Some(&[target]))?;

    if !args.live {
        eprintln!("note: free-check used offline data; pass --live to check against reality.\n");
    }
    println!("{}", plan.preview());

    if args.write && !args.dry_run {
        eprintln!("--write: applying on {} …", cfg.vantage);
        let token = live::get_token(&cfg.token_pass)?;
        let log = plan.apply(&Vantage::with_jump(&cfg.vantage, &cfg.jump), &token)?;
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
    if range.is_v6() {
        return demo_v6_facts(range);
    }
    let (_demo_range, facts) = fixture::demo();
    facts.into_iter().filter(|f| range.contains(f.addr)).collect()
}

/// Synthetic IPv6 demo hosts — a few clusters spread across `range` — so browsing a v6
/// prefix offline shows the sparse table, tree and relative-density map actually working
/// (the v4 fixture has no v6 addresses). Names mirror the v4 demo's clusters.
fn demo_v6_facts(range: &Cidr) -> Vec<AddressFacts> {
    let IpAddr::V6(base) = range.network() else {
        return Vec::new();
    };
    let net = u128::from(base);
    let hb = range.host_bits();
    let mid = if hb >= 1 { 1u128 << (hb - 1) } else { 0 }; // ~halfway across the space
    let far = if hb >= 2 { 3u128 << (hb - 2) } else { 0 }; // ~three-quarters across
    let mut out = Vec::new();
    let mut push = |off: u128, name: String| {
        if off < range.block_len() {
            out.push(AddressFacts {
                addr: IpAddr::V6(Ipv6Addr::from(net + off)),
                netbox: None,
                ptr: Some(format!("{name}.nfra.nl.")),
                live: false,
            });
        }
    };
    for i in 1..=10u128 {
        push(i, format!("dop{i:02}-mgmt"));
    }
    for i in 0..5u128 {
        push(mid + i, format!("netapp-dw{}", i + 1));
    }
    for i in 0..3u128 {
        push(far + i, format!("iprotect-{}", i + 1));
    }
    out
}

/// Print the reconciled range as plain text: a status tally, then every address
/// that is *not* simply free (the interesting rows). Lets you eyeball the result
/// without a terminal — the counterpart of census's `--ping`.
fn list_table(range: Cidr, facts: &[reconcile::AddressFacts]) {
    // Lazy: never materialize the whole range. Counts and the non-free rows come from
    // the bounded facts; the first free address is found by scanning host indices
    // (instant on a mostly-empty range).
    let total = range.host_count();
    let map: std::collections::HashMap<std::net::IpAddr, reconcile::AddressFacts> =
        facts.iter().cloned().map(|f| (f.addr, f)).collect();
    let c = reconcile::counts_from_facts(total, &map);

    // A two-line block header: the block itself, then one aligned tally.
    println!("{}/{}   network {}   {total} host{}", range.base, range.prefix_len, range.network(), plural(total));
    println!(
        "  free {}  allocated {}  dns-only {}  netbox-only {}  live-unreg {}  conflict {}",
        c.free, c.allocated, c.dns_only, c.netbox_only, c.live_unregistered, c.conflict
    );

    // The interesting rows (everything not simply free) as an aligned ADDRESS/STATUS/NAME
    // table; the address column is sized to its widest value so IPv4 and IPv6 both line up.
    let mut rows: Vec<reconcile::AddressRow> = facts.iter().map(reconcile::row_from_facts).collect();
    rows.sort_by_key(|r| r.addr);
    rows.retain(|r| !r.status.is_free());
    if !rows.is_empty() {
        let addr_w = rows.iter().map(|r| r.addr.to_string().len()).max().unwrap_or(0).max("ADDRESS".len());
        println!();
        print_row(addr_w, "ADDRESS", "STATUS", "NAME");
        for r in &rows {
            print_row(addr_w, &r.addr.to_string(), r.status.label(), r.name.as_deref().unwrap_or(""));
        }
    }
    if let Some(free) = (0..total).map(|i| range.host_at(i)).find(|a| !map.contains_key(a)) {
        println!("  first free: {free}");
    }
}

/// Print one aligned `ADDRESS  STATUS  NAME` row (2-space indent), trimmed so an empty
/// trailing column leaves no trailing whitespace — kinder to copy-paste and to diffs.
fn print_row(addr_w: usize, addr: &str, status: &str, name: &str) {
    // 11 = width of the longest status label ("netbox-only").
    let line = format!("  {addr:<addr_w$}  {status:<11}  {name}");
    println!("{}", line.trim_end());
}

/// `""` for a count of 1, else `"s"` — so headers read "1 host" / "254 hosts".
fn plural(n: u128) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}
