# canopy — house rules

A TUI that builds one **reconciled view of an organization's network** — its IP
address space (IPv4 **and** IPv6), its structure, and its logical host groupings —
from several sources of truth (multiple DNS servers, NetBox), and helps you act on it:
find free addresses, provision hosts, and reconcile DNS against NetBox. Sibling of
`census` (../census); both built on `mullion` (../mullion). When in doubt about
structure or idiom, copy census.

*The metaphor:* trees (DNS/zone hierarchies) nest, and seen from above they merge into
one continuous surface — the **canopy** — the map you read and act on. Its sibling
`census` counts the inhabitants; canopy surveys the territory.

## What canopy does (four pillars)
1. **Sources & discovery** — merge several DNS servers and NetBox; **infer** the v4/v6
   address space automatically instead of being handed a range.
2. **Visualize** — the IP-space map (v4 and v6), the layered structure (routers →
   switches → VLANs → subnets → hosts), and logical host groupings (clusters, name
   families).
3. **Provision** — find a free address in a subnet/VLAN, report netmask/gateway/DNS for
   both families, write the name/A/AAAA to the **owning** DNS server, and create the
   NetBox entry.
4. **Reconcile** — point at a host or group and complete NetBox from DNS (or DNS from
   NetBox); surface incomplete and conflicting records across both.

The sequenced build plan lives in `docs/roadmap-prompts.md` (P1–P12); the long-term
north star in `docs/vision.md`.

## Conventions
- **Rust 2021**, `rust-version = 1.85`. Keep it compiling and warning-free after every change.
- **Licence header on every file:** `// SPDX-License-Identifier: GPL-3.0-or-later`
  then `// Copyright (C) 2026  Epsilon Null Operation`.
- **Doc-comment every public item** (`///`) and every module (`//!`): what it does,
  and for logic, *how/why*. Match mullion/census density.
- **No `unwrap()`/`expect()`** outside tests and `main`/startup. Use `anyhow::Result`.
- Pin dependency majors in `Cargo.toml`; no `"*"`.

## Structure
- `src/reconcile.rs` — **pure** core (no I/O): merges `AddressFacts` → `AddressStatus`,
  and holds the `Cidr` arithmetic + lazy pagination. Keep it dependency-free and
  unit-tested against known real cases. (Growing to a host-level view in P5 — still pure.)
- `src/fixture.rs` — frozen real `10.87.3.0/24` data so the UI runs offline.
- `src/sources/` — one live source per fact field (NetBox → `netbox`, DNS → `ptr`,
  probe → `live`), each behind the `AddressFacts` shape; `merge` unions them before
  reconciling. All live queries run over an SSH `Vantage`.
- `src/dns/` + `src/plan.rs` — the **safe write path**: zones-on-servers, routed
  actions, a diff-before-apply `Plan`.
- `src/tui/` — `app` (state + loop + keys), `draw` (paint), `theme` (palette, census
  colours), `focus` (`ListCursor`), plus `graph`/`tree`/`map` views. Mirrors census's `tui/`.
- Live I/O (NetBox client, DNS reader, ARP probe, DNS/NetBox writers) goes in a module
  behind the `AddressFacts` shape — **never** in `reconcile`.

## Testing
- Every reconcile rule has a `#[test]` tied to a real observation (the `.11` iProtect
  drift, the `.90` squatter, the `.69` free pick, a name conflict).
- The TUI has a **headless** render test (`Buffer::empty` at several sizes) so it is
  verified without a tty — the way mullion tests itself. `cargo test` must stay green.
- `canopy --list` prints the reconciled table with no TUI — use it to eyeball output.

## Safety
- **Read-only by default.** Writes (NetBox allocation, DNS push) require `--write`,
  support `--dry-run`, and must show a diff before sending. DNS is DNSSEC inline-signed
  on `dns1`: edit `db.nfra.nl`, bump serial, `rndc reload` — never hand-edit `.signed`.
  Reverse PTR on the Windows `ntserver1` is a **manual hand-off**, never auto-applied.
- Secrets (NetBox token) come from `pass` (or `$CANOPY_NETBOX_TOKEN`); never hard-code or log them.
