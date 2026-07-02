# netpush — house rules

A TUI to reconcile IP allocation across NetBox, DNS and the live network, then push
the fixes. Sibling of `census` (../census); both built on `mullion` (../mullion).
When in doubt about structure or idiom, copy census.

## Conventions
- **Rust 2021**, `rust-version = 1.85`. Keep it compiling and warning-free after every change.
- **Licence header on every file:** `// SPDX-License-Identifier: GPL-3.0-or-later`
  then `// Copyright (C) 2026  Epsilon Null Operation`.
- **Doc-comment every public item** (`///`) and every module (`//!`): what it does,
  and for logic, *how/why*. Match mullion/census density.
- **No `unwrap()`/`expect()`** outside tests and `main`/startup. Use `anyhow::Result`.
- Pin dependency majors in `Cargo.toml`; no `"*"`.

## Structure
- `src/reconcile.rs` — **pure** core (no I/O): merges `AddressFacts` → `AddressStatus`.
  Keep it dependency-free and unit-tested against known real cases.
- `src/fixture.rs` — frozen real `10.87.3.0/24` data so the UI runs offline.
- `src/tui/` — `app` (state + loop + keys), `draw` (paint), `theme` (palette,
  census colours), `focus` (`ListCursor`). Mirrors census's `tui/`.
- Live I/O (NetBox client, DNS reader, ARP probe, DNS/NetBox writers) goes in new
  modules behind the `AddressFacts` shape — never in `reconcile`.

## Testing
- Every reconcile rule has a `#[test]` tied to a real observation (the `.11` iProtect
  drift, the `.90` squatter, the `.69` free pick, a name conflict).
- The TUI has a **headless** render test (`Buffer::empty` at several sizes) so it is
  verified without a tty — the way mullion tests itself. `cargo test` must stay green.
- `netpush --list` prints the reconciled table with no TUI — use it to eyeball output.

## Safety
- **Read-only by default.** Writes (NetBox allocation, DNS push) require `--write`,
  support `--dry-run`, and must show a diff before sending. DNS is DNSSEC inline-signed
  on `dns1`: edit `db.nfra.nl`, bump serial, `rndc reload` — never hand-edit `.signed`.
- Secrets (NetBox token) come from `pass`; never hard-code or log them.
