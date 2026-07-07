// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! `canopy` — a terminal UI that reconciles what NetBox, DNS and the live network
//! each believe about an IP range, then (later) pushes the missing records.
//!
//! For now it runs against a frozen snapshot of the real `10.87.3.0/24` data (see
//! [`fixture`]) so the UI works offline; live NetBox/DNS sources slot in behind the
//! same [`reconcile::AddressFacts`] shape.

mod cache;
mod lasso;
mod config;
mod discover;
mod dns;
mod dns_discovery;
mod fabric;
mod fixture;
mod graph;
mod group;
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

    /// Print the reconciled logical groups (clusters, name-families, services) and the NetBox
    /// tag each would be pushed as, then exit. The staging view for "put these in NetBox".
    #[arg(long)]
    list_groups: bool,

    /// Preview the NetBox tag writes that would record one group (by name/slug). Read-only: it
    /// shows the exact per-address diff and writes nothing. Pass `--live` to diff against the
    /// real current tags.
    #[arg(long, value_name = "GROUP")]
    push_group: Option<String>,

    /// Emit the reconciled groups as a `groups.toml` staging file on stdout (redirect it to
    /// `conf.d/<site>.groups.toml`). Read-only; a canopy-side config, never touches NetBox.
    #[arg(long)]
    emit_groups: bool,

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

    /// Collect read-only diagnostics from a fabric device (by inventory name) into a
    /// versioned snapshot, then exit. Read-only.
    #[arg(long, value_name = "DEVICE")]
    fabric_collect: Option<String>,

    /// Artifact bundle(s) to collect with --fabric-collect (repeatable); omitted = all.
    #[arg(long = "bundle", value_name = "BUNDLE")]
    bundles: Vec<String>,

    /// Inventory/site TOML holding the [[device]] array (default: conf.d/<site>.toml).
    #[arg(long, value_name = "FILE")]
    fabric_site_file: Option<PathBuf>,

    /// Site-wide ProxyJump chain for fabric devices that set none.
    #[arg(long, value_name = "CHAIN", default_value = "")]
    fabric_jump: String,
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

    // Collect a fabric device's diagnostics into a versioned snapshot (read-only).
    if let Some(device) = &args.fabric_collect {
        return run_fabric_collect(&args, device);
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

    if args.list_groups {
        // Native NetBox clusters are authoritative but only reachable live; offline we group by
        // inference (and any staging file) alone.
        let native = if args.live { live::gather_native_clusters(&range, &cfg)? } else { Vec::new() };
        list_groups(&facts, &args.site, native);
        return Ok(());
    }

    if let Some(name) = args.push_group.clone() {
        return preview_push_group(&name, range, &args, &cfg, &facts);
    }

    if args.emit_groups {
        let native = if args.live { live::gather_native_clusters(&range, &cfg)? } else { Vec::new() };
        emit_groups(&facts, &args.site, native);
        return Ok(());
    }

    let groups = load_group_sources(&args, &cfg, &range, &facts);
    tui::run(range, facts, subnets, args.write, args.dry_run, args.live, cfg, None, groups)
}

/// Load the group sources for the TUI: the human-asserted staging file
/// (`conf.d/<site>.groups.toml`) and, when `--live`, the native NetBox clusters in `range`.
/// Returns `(asserted, native)` for [`tui::run`]; a missing/unreadable staging file or a native
/// fetch failure degrades to empty (inference still colours the map). Read-only.
fn load_group_sources(args: &Args, cfg: &Config, range: &Cidr, _facts: &[reconcile::AddressFacts]) -> (Vec<group::Group>, Vec<group::Group>) {
    let asserted = std::fs::read_to_string(config::groups_path(&args.site))
        .ok()
        .and_then(|t| toml::from_str::<group::GroupsFile>(&t).ok())
        .map(group::GroupsFile::into_groups)
        .unwrap_or_default();
    let native = if args.live {
        group::from_native(live::gather_native_clusters(range, cfg).unwrap_or_default())
    } else {
        Vec::new()
    };
    (asserted, native)
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

/// Handle `--fabric-collect <DEVICE>`: collect a device's artifacts into a snapshot.
///
/// Resolves the device's profile from its inventory `os`, or — if unset — by running a
/// first `show version` on the device's [`Vantage`] and sniffing the vendor banner. Read-only.
///
/// # Errors
/// Propagates inventory load/lookup failures, an unrecognised OS, or a collection failure.
fn run_fabric_collect(args: &Args, device_name: &str) -> anyhow::Result<()> {
    use fabric::collect::{collect, detect_os, CommandRunner};
    use fabric::inventory::Inventory;
    use fabric::profile::Profile;
    use fabric::store::Store;

    let site_file = args
        .fabric_site_file
        .clone()
        .unwrap_or_else(|| default_site_file(&args.site));
    let inv = Inventory::load(&site_file)?;
    let device = inv.get(device_name).ok_or_else(|| {
        anyhow::anyhow!("device '{device_name}' not in inventory {}", site_file.display())
    })?;

    let vantage = device.vantage(&args.fabric_jump);

    // Resolve the profile: configured os, else detect from a first `show version`.
    let os = match &device.os {
        Some(os) => os.clone(),
        None => detect_os(&vantage.exec("show version")?).to_string(),
    };
    let profile = Profile::builtin(&os)?;

    let store = Store::new(Store::default_root());
    let now = chrono::Utc::now();
    let dir = collect(&vantage, device, &profile, &args.bundles, &store, &args.site, &args.fabric_jump, now)?;

    let n = profile.select(&args.bundles).len();
    println!("collected {n} artifact(s) from {} -> {}", device.name, dir.display());
    Ok(())
}

/// Default inventory path: `$XDG_CONFIG_HOME` (or `~/.config`) + `/canopy/conf.d/<site>.toml`.
fn default_site_file(site: &str) -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config")
    });
    base.join("canopy").join("conf.d").join(format!("{site}.toml"))
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

    // Interim overview until the navigable estate view lands: print every discovered range
    // to stderr (scrolls above the TUI), then open on one. Browse any other with --range.
    eprint!("{}", discover::summary(&blocks));
    let primary = discover::primary(&blocks).context("no primary block to browse")?;
    let note = format!(
        "{} ranges discovered; browsing {}/{}. Others: canopy --live --range <cidr>",
        blocks.len(),
        primary.cidr.base,
        primary.cidr.prefix_len
    );
    let data = live::gather_live_with_token(&primary.cidr, cfg, token, |_, _| {})?;
    let groups = load_group_sources(args, cfg, &primary.cidr, &data.facts);
    tui::run(primary.cidr, data.facts, data.subnets, args.write, args.dry_run, true, cfg.clone(), Some(note), groups)
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
/// Print the reconciled logical groups and, for each, the NetBox tag canopy would push it as —
/// the staging view for "put these groupings into NetBox". Loads the site's group staging file
/// (`conf.d/<site>.groups.toml`) if present for the human-asserted layer, infers the rest from
/// the naming scheme, fuses them ([`group::merge`]), and lists members with their origin.
///
/// Read-only: it only *shows* the tags; nothing is written. The point is to make the pending
/// NetBox work legible before any write path exists.
fn list_groups(facts: &[reconcile::AddressFacts], site: &str, native: Vec<group::NativeCluster>) {
    let map: std::collections::HashMap<std::net::IpAddr, reconcile::AddressFacts> =
        facts.iter().cloned().map(|f| (f.addr, f)).collect();

    // The human-asserted staging layer, if the site has one. A missing or unparseable file just
    // means "no assertions yet" — inference still runs.
    let asserted = match std::fs::read_to_string(config::groups_path(site)) {
        Ok(text) => match toml::from_str::<group::GroupsFile>(&text) {
            Ok(gf) => gf.into_groups(),
            Err(e) => {
                eprintln!("warning: ignoring {}: {e}", config::groups_path(site).display());
                Vec::new()
            }
        },
        Err(_) => Vec::new(),
    };

    let native_groups = group::from_native(native);
    let grouping = group::merge(asserted, native_groups, group::infer(&map));
    if grouping.groups.is_empty() {
        println!("(no groups — no named hosts to infer from and no {} )", config::groups_path(site).display());
        return;
    }

    for g in &grouping.groups {
        let target = match g.netbox_target() {
            group::NetboxTarget::Tag(t) => t.name,
            group::NetboxTarget::Cluster(id) => format!("cluster #{id}"),
        };
        let origin = match &g.origin {
            group::Origin::Asserted => "asserted".to_string(),
            group::Origin::Netbox { .. } => "netbox".to_string(),
            group::Origin::Inferred { confidence, .. } => format!("inferred {:.0}%", confidence * 100.0),
        };
        let push = if g.needs_push() { "  → push" } else { "" };
        println!("\n{:?}  [{}]  {}  ({}){}", g.label, target, origin, g.members.len(), push);
        let mut members = g.members.clone();
        members.sort_by_key(|m| m.addr);
        for m in &members {
            let addr = m.addr.map(|a| a.to_string()).unwrap_or_else(|| "—".into());
            println!("    {:<16} {}", addr, m.host.as_deref().unwrap_or(""));
        }
    }

    let pending = grouping.pending_pushes();
    println!("\n{} group(s); {} not yet in NetBox.", grouping.groups.len(), pending.len());
}

/// Emit the reconciled groups as a `groups.toml` staging file on stdout — a canopy-side config
/// the user can save to `conf.d/<site>.groups.toml` and hand-edit. Read-only; writes nothing to
/// NetBox. Every group (native, inferred or already-asserted) is written as a `[[group]]` block
/// so the file is a complete, editable snapshot the map then colours from.
fn emit_groups(facts: &[reconcile::AddressFacts], site: &str, native: Vec<group::NativeCluster>) {
    let map: std::collections::HashMap<std::net::IpAddr, reconcile::AddressFacts> =
        facts.iter().cloned().map(|f| (f.addr, f)).collect();
    let asserted = std::fs::read_to_string(config::groups_path(site))
        .ok()
        .and_then(|t| toml::from_str::<group::GroupsFile>(&t).ok())
        .map(group::GroupsFile::into_groups)
        .unwrap_or_default();
    let grouping = group::merge(asserted, group::from_native(native), group::infer(&map));

    println!("# canopy group staging file — conf.d/{site}.groups.toml");
    println!("# Generated by `canopy --emit-groups`. canopy owns this; NetBox is untouched.");
    println!("# Each [[group]] asserts membership. kind = cluster | pair | service | singleton.");
    for g in &grouping.groups {
        let kind = match g.kind {
            group::GroupKind::Cluster => "cluster",
            group::GroupKind::Pair => "pair",
            group::GroupKind::Service => "service",
            group::GroupKind::Singleton => "singleton",
        };
        let mut members = g.members.clone();
        members.sort_by_key(|m| m.addr);
        // Each member is written ONCE: by address where it has one (the key the map colours and
        // a NetBox write targets), else by hostname. Hostnames of the addressed members go in a
        // comment so the file stays readable without double-counting on reload.
        let addrs: Vec<String> = members.iter().filter_map(|m| m.addr).map(|a| format!("\"{a}\"")).collect();
        let named: Vec<&str> = members.iter().filter(|m| m.addr.is_some()).filter_map(|m| m.host.as_deref()).collect();
        let host_only: Vec<String> = members.iter().filter(|m| m.addr.is_none()).filter_map(|m| m.host.as_deref()).map(|h| format!("{h:?}")).collect();
        println!("\n[[group]]");
        println!("name = {:?}", g.label);
        println!("kind = {kind:?}");
        if !named.is_empty() {
            println!("# hosts: {}", named.join(", "));
        }
        if !addrs.is_empty() {
            println!("addrs = [{}]", addrs.join(", "));
        }
        if !host_only.is_empty() {
            println!("hosts = [{}]", host_only.join(", "));
        }
    }
}

/// Preview the NetBox tag writes that would record one group — **read-only**. Builds the
/// grouping, finds the named group, and (when `--live`) diffs its intended `cluster:<slug>` tag
/// against each member's current NetBox tags, printing exactly what would change. Nothing is
/// sent; `--write` is deliberately refused until the apply path is built and verified.
///
/// This is the deliberately-cautious first half of the write path: make the change legible and
/// prove it on a single group before any mutation exists.
///
/// # Errors
/// Propagates the live tag/native-cluster fetch when `--live` is set.
fn preview_push_group(name: &str, range: Cidr, args: &Args, cfg: &Config, facts: &[reconcile::AddressFacts]) -> anyhow::Result<()> {
    let map: std::collections::HashMap<std::net::IpAddr, reconcile::AddressFacts> =
        facts.iter().cloned().map(|f| (f.addr, f)).collect();
    let native = if args.live { live::gather_native_clusters(&range, cfg)? } else { Vec::new() };
    let asserted = std::fs::read_to_string(config::groups_path(&args.site))
        .ok()
        .and_then(|t| toml::from_str::<group::GroupsFile>(&t).ok())
        .map(group::GroupsFile::into_groups)
        .unwrap_or_default();
    let grouping = group::merge(asserted, group::from_native(native), group::infer(&map));

    let want = group::GroupId::slug(name);
    let Some(g) = grouping.groups.iter().find(|g| g.id == want || g.label == name) else {
        eprintln!("no group named {name:?}. Try `canopy --list-groups{}`.", if args.live { " --live" } else { "" });
        std::process::exit(1);
    };

    if !g.needs_push() {
        println!("Group {:?} is already in NetBox (native cluster) — nothing to push.", g.label);
        return Ok(());
    }

    // The live state to diff against: the tag objects that exist, and each member IP's current
    // tags. Offline we assume nothing exists yet (so the preview shows the full intended change).
    let existing_tags = if args.live { live::gather_tag_slugs(cfg)? } else { std::collections::HashSet::new() };
    let current = if args.live { live::gather_ip_tags(&range, cfg)? } else { std::collections::HashMap::new() };

    let tag = g.netbox_tag().unwrap_or(group::NetboxTag { name: String::new(), slug: String::new() });
    let writes = g.plan_tag_writes(&current);
    let (to_add, present): (Vec<_>, Vec<_>) = writes.iter().partition(|w| !w.already_present);

    println!("Preview: record group {:?} in NetBox", g.label);
    println!("  tag:  name {:?}  slug {:?}", tag.name, tag.slug);

    // Step 1 — the tag object must exist before it can be assigned.
    match g.tag_needs_creating(&existing_tags) {
        Some(t) if args.live => println!("  step 1: CREATE tag  (name {:?}, slug {:?}) — does not exist yet", t.name, t.slug),
        Some(_) => println!("  step 1: create tag if absent (run --live to check what exists)"),
        None if args.live => println!("  step 1: tag already exists — no create needed"),
        None => println!("  step 1: create tag if absent"),
    }

    // Step 2 — assign the tag to each member IP (skipping any that already carry it).
    println!("  step 2: assign to {} member IP(s) — would add {}, already tagged {}\n", writes.len(), to_add.len(), present.len());
    for w in &writes {
        let mark = if w.already_present { "=" } else { "+" };
        let host = g.host_of(w.addr).unwrap_or("");
        println!("  {mark} {:<16} {host}", w.addr.to_string());
    }
    if !args.live {
        println!("\n(offline — pass --live to diff against the real tags and existing tag objects)");
    }
    println!("\nPREVIEW ONLY — no changes sent to NetBox.");
    if args.write {
        eprintln!("refusing --write: the tag create/apply path is not implemented yet; verify this preview first.");
        std::process::exit(2);
    }
    Ok(())
}

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

#[cfg(test)]
mod fabric_cli_tests {
    use super::*;

    #[test]
    fn default_site_file_uses_xdg_config_home() {
        std::env::set_var("XDG_CONFIG_HOME", "/x/cfg");
        assert_eq!(
            default_site_file("astron"),
            PathBuf::from("/x/cfg/canopy/conf.d/astron.toml")
        );
        std::env::remove_var("XDG_CONFIG_HOME");
    }
}
