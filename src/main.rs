// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! `netpush` — a terminal UI that reconciles what NetBox, DNS and the live network
//! each believe about an IP range, then (later) pushes the missing records.
//!
//! For now it runs against a frozen snapshot of the real `10.87.3.0/24` data (see
//! [`fixture`]) so the UI works offline; live NetBox/DNS sources slot in behind the
//! same [`reconcile::AddressFacts`] shape.

mod fixture;
mod reconcile;
mod tui;

use clap::Parser;

use reconcile::Cidr;

/// Command-line options — mirrors census's read-only-by-default posture.
#[derive(Parser, Debug)]
#[command(name = "netpush", about = "Reconcile IP allocation across NetBox, DNS and the live network")]
struct Args {
    /// CIDR range to browse (the demo data only covers 10.87.3.0/24 for now).
    #[arg(long, default_value = "10.87.3.0/24")]
    range: String,

    /// Allow pushing NetBox/DNS changes (reserved — not wired to live sources yet).
    #[arg(long)]
    write: bool,

    /// Walk write flows but send nothing; each push reports what it *would* do.
    #[arg(long)]
    dry_run: bool,

    /// Print the reconciled table to stdout and exit (no TUI). Good for scripts/CI.
    #[arg(long)]
    list: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let range = Cidr::parse(&args.range).map_err(|e| anyhow::anyhow!(e))?;
    let (demo_range, demo_facts) = fixture::demo();
    // Until live sources land, facts only exist for the demo range; keep just the
    // ones that actually fall inside the range being browsed.
    let facts: Vec<_> = if range == demo_range {
        demo_facts.into_iter().filter(|f| range.contains(f.addr)).collect()
    } else {
        Vec::new()
    };

    if args.list {
        list_table(range, &facts);
        return Ok(());
    }

    tui::run(range, facts, args.write, args.dry_run)
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
