<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) 2026  Epsilon Null Operation -->

# <NAME> — Claude Code prompt roadmap

A sequenced set of paste-ready prompts to grow this project from *netpush*
(reconcile + push a single `/24`) into **<NAME>**: an authoritative, reconciled
view of the organization's network territory — its address space, structure, and
groupings — built from many sources of truth (DNS servers, NetBox), that you can
both **read** (visualize) and **act on** (provision, register, reconcile).

> If you pick a different name, replace `<NAME>` throughout — only **P1** actually
> performs the rename; later prompts just reference the chosen name.

**House rules apply to every prompt** (they live in `CLAUDE.md`): Rust 2021,
`rust-version 1.85`, compiles warning-free after every change, SPDX + copyright
header on every file, doc-comment every public item and module, no
`unwrap()`/`expect()` outside tests/`main`, pinned dependency majors, read-only by
default (writes behind `--write` with `--dry-run` + a shown diff), secrets from
`pass` only. `cargo test` must stay green, including a **headless** TUI render test.
Keep `src/reconcile.rs` **pure** (no I/O); all live I/O sits behind the fact shape in
its own module.

The phases build on each other; do them roughly in order. Each prompt is sized to be
one reviewable change (compiles, tests, one capability).

---

## Phase 0 — Rename & re-theme

### P1 — Rename to `<NAME>` and re-theme the docs

> Rename this project from **netpush** to **<NAME>** and re-theme its docs around a
> broadened vision, without changing behavior yet.
>
> 1. Rename the crate and binary to `<NAME>` in `Cargo.toml` (package name, `[[bin]]`
>    name, description). Update `Cargo.lock`.
> 2. Update every in-code reference to the old name (module docs, `--help` text in
>    `main.rs`'s `#[command(name = ...)]`, doc-comments) to `<NAME>`.
> 3. Rewrite `README.md` and `CLAUDE.md` to describe the new theme and four pillars:
>    **(A)** multiple sources of truth (several DNS servers + NetBox) with automatic
>    address-space discovery; **(B)** visualize — IP-space map (v4 **and** v6), layered
>    structure (routers → switches → VLANs → subnets → hosts), and logical host
>    groupings; **(C)** a provisioning assistant (find a free IP, write DNS to the right
>    server, create the NetBox entry, report netmask/gateway/DNS for v4+v6); **(D)**
>    reconcile DNS ↔ NetBox (complete one from the other; surface incomplete/conflicting
>    records). Keep the "sibling of `census`, built on `mullion`" framing and the
>    land-registry metaphor (census surveys inhabitants; <NAME> surveys the territory).
> 4. Keep the existing safety, structure, and testing sections of `CLAUDE.md`; expand
>    them only where the new pillars need it.
>
> Do **not** change any logic in this prompt — it is a rename + docs pass. `cargo test`
> and `cargo build` must stay green; the binary must still run `--list` and the TUI.

---

## Phase 1 — Sources & auto-discovery

### P2 — Multiple DNS servers with forward/reverse zone routing

> Today `src/sources/dns.rs` queries a single vantage resolver and the config has one
> `vantage`. Generalize to **several DNS servers**, each owning specific zones.
>
> - Add a config section listing DNS servers: for each, a name/host, an optional SSH
>   vantage to reach it, the forward zones it is authoritative for (e.g. `nfra.nl`), and
>   the reverse zones (`in-addr.arpa` / `ip6.arpa` blocks) it masters. Keep it optional
>   with sensible defaults so existing configs still load.
> - Route each forward and reverse lookup to the server that owns the relevant zone
>   (longest-suffix match on the name / longest-prefix match on the reverse block),
>   falling back to the default resolver when no owner is known.
> - Prefer AXFR from the owning server where allowed (you already have
>   `reverse_axfr_server`); otherwise per-name lookups as now.
> - Keep parsing pure and unit-tested with captured sample output; only the SSH call is
>   live. Add tests for zone-ownership routing (a name/reverse block picking the right
>   server, and the fallback).
>
> This should not change the reconciled result for the single-server case — it
> generalizes the plumbing. Update `src/live.rs` and `Config` accordingly.

### P3 — Auto-infer the address space (v4 + v6) from NetBox + DNS

> Make `--range` optional. When it is omitted, **discover** the address space to survey
> from the sources instead of requiring the user to name it.
>
> - Add a discovery step (new module, e.g. `src/discover.rs`) that asks NetBox for its
>   prefixes/aggregates (v4 and v6) and the DNS servers for the reverse zones they master,
>   and produces the set of CIDR blocks worth surveying.
> - Reconcile/visualize across that discovered set. Respect the existing lazy model:
>   large v6 blocks stay sparse (`Cidr::is_enumerable`), so discovery yields **blocks**,
>   never materialized address lists.
> - `--range` still overrides discovery for a focused view. `--list` prints a short
>   summary of the discovered blocks (count, family, source) before the per-address rows.
> - Unit-test the inference from captured NetBox/DNS samples (prefixes + reverse zones →
>   expected block set), including a mixed v4/v6 case.
>
> Keep it read-only. Do not enumerate anything larger than `ENUMERATION_CAP`.

### P4 — Enrich the NetBox source: prefixes, VLANs, roles, devices

> Extend `src/sources/netbox.rs` beyond IP-address `dns_name` so later views and the
> reconciler have real structure to work with.
>
> - Fetch and model: prefixes (with role, VLAN, description, site), VLANs, and devices +
>   interfaces + their IPs (enough to know which device/role/rack an address belongs to,
>   and which addresses are on the same device). Put the new types in a NetBox-facing
>   module; keep `reconcile.rs` pure — feed it only the merged fact shape (extend
>   `AddressFacts`/`Subnet` minimally, or add a parallel structure the views consume).
> - All fetches go through the SSH vantage with the token over stdin (never argv), as
>   now. Paginate the REST API.
> - Parsing is pure and unit-tested against captured JSON samples. No behavior change to
>   the existing reconcile statuses in this prompt — this is about *gathering* more.
>
> Read-only. Pin any new dependency majors.

---

## Phase 2 — Richer model & reconciliation

### P5 — Reconcile across forward + reverse and v4 + v6 completeness

> Grow the pure reconciler beyond a single address's three-source verdict so it can drive
> the "incomplete / conflicting" pillar.
>
> - In `src/reconcile.rs`, model a **host** as the correlation of its forward name, its
>   A and AAAA, its PTRs (v4 and v6), and its NetBox object(s). Add statuses/flags for the
>   real drift cases: missing AAAA (has A, no v6), missing PTR (forward without reverse),
>   forward/reverse mismatch, NetBox-missing-but-in-DNS, DNS-missing-but-in-NetBox, and
>   name conflicts across sources.
> - Keep it **pure and dependency-free**. Every new rule gets a `#[test]` tied to a
>   realistic case (mirror the existing `.11`/`.90`/`.69`/conflict style).
> - Preserve the existing per-address `AddressStatus` path and the lazy
>   `reconcile_at`/`counts_from_facts` pagination; add the host-level view alongside it.
> - Extend `--list` to optionally report the incomplete/conflicting hosts.

### P6 — Logical grouping / clustering of hosts

> Add a pure module that groups hosts into **logical clusters** for the groupings view and
> for group operations.
>
> - Group by: shared name pattern (e.g. `dop01..dop40`, common prefix/numeric-suffix
>   families), DNS zone/subdomain structure, and NetBox cluster/role/device where known.
> - Output stable, named groups with their members; make the heuristics explicit and
>   unit-tested against representative names (the `dop*-ipmi`, `iprotect-*`, `netapp-dw*`
>   families from the fixture are good cases).
> - Pure, no I/O; deterministic ordering. This feeds P7 (group actions) and P10 (view).

### P7 — Group reconcile actions: complete DNS ↔ NetBox

> Build on the planner (`src/plan.rs`) so the user can point at a host **or a group** and
> say "complete NetBox from DNS" or "complete DNS from NetBox".
>
> - Given a host/group and a direction, compute the missing/mismatched records and emit a
>   `Plan` of routed actions (NetBox create/update; forward A/AAAA on the owning DNS
>   server; reverse PTR — still a gated/manual hand-off where it can't be automated).
> - Reuse the existing safety model: refuse to overwrite conflicting data without an
>   explicit decision, always `preview()` a diff, apply only non-review actions behind
>   `--write` and not `--dry-run`.
> - Add CLI entry points (e.g. `--complete-netbox <host|group>` /
>   `--complete-dns <host|group>`) that print the plan; wire the same into the TUia later.
> - Unit-test plan generation for both directions on a host missing AAAA and on a
>   DNS-only host missing its NetBox object.

---

## Phase 3 — Visualize

### P8 — IP-space map for v4 **and** v6, at scale

> Realize the IP-map view for both families, following `docs/ip-map-design.md` and
> `docs/vision.md` (square-of-squares over the space, zoom, relative density).
>
> - Render the discovered/selected blocks as a navigable grid of used/free cells; zoom in
>   and out (reuse the `ZoomFrame` scaffolding in `tui/app.rs`); label the subnet/VLAN the
>   cursor sits in via longest-prefix match (`Subnet::most_specific`).
> - Never materialize a sparse v6 block: cells summarize counts from the bounded facts and
>   the arithmetic in `Cidr`, not per-address lists.
> - Add headless render tests (`Buffer::empty` at several sizes) for the v4 and v6 map.

### P9 — Layered network structure view

> Add a view that draws the network **by layers** — routers → switches → VLANs → subnets
> → hosts — from the NetBox structure gathered in P4.
>
> - Use mullion's Sugiyama layout (as the graph view already does) to lay out the layers
>   with connectors and pan. Group hosts under their subnet/VLAN, subnets under their
>   device/router where NetBox records it.
> - Be explicit in the docs and UI that topology is **"as NetBox believes it"**; leave a
>   clean seam for a future live device-polling source (SNMP/LLDP) to supply real L2/L3
>   adjacency. Do not fake links NetBox doesn't assert.
> - Headless render test at a couple of sizes.

### P10 — Groupings / clusters view + inspector

> Add the third visualization: the logical groupings from P6.
>
> - Show clusters as collapsible groups (fit into the existing `Tab` view cycle and the
>   tree view idiom); `Enter` inspects a group or host, showing each source's record and
>   the reconcile verdict (incl. the P5 completeness flags).
> - Offer the group reconcile actions from P7 directly from the inspector, gated by
>   `--write`.
> - Headless render test.

---

## Phase 4 — Provisioning assistant

### P11 — Provisioning cheat-sheet: subnet facts + free-IP pick (v4 + v6)

> Add the fast answers you need when provisioning a box, without a full allocation.
>
> - Given a subnet or VLAN (by CIDR, or by NetBox VLAN id/name), print netmask, network,
>   gateway convention, and the DNS servers/domains to use — for **both** v4 and v6 where
>   the VLAN has both — plus the next free address in each family (reuse the lazy
>   free-scan already in `--list`/`main.rs`).
> - Add a CLI entry point (e.g. `--subnet-info <cidr|vlan>`); surface the same in the map
>   inspector.
> - Unit-test the derived facts for a v4 subnet, a v6 subnet, and a dual-stack VLAN.
>
> Read-only.

### P12 — Guided provisioning flow (write path)

> Tie it together: a guided flow to provision a new host end-to-end.
>
> - Steps: choose subnet/VLAN → pick the next free v4 and v6 → enter the name → build a
>   `Plan` that creates the NetBox object, writes the forward A/AAAA to the owning DNS
>   server, and hands off the reverse PTR(s); then emit a ready-to-paste host network
>   config (netplan/`ip`/interfaces stanza) with the address, prefix, gateway, and DNS.
> - Everything behind `--write` with `--dry-run` and a shown diff; refuse non-free
>   targets; apply only non-review actions. Offer it both as a CLI flow and from the TUI
>   allocate overlay (extend `AllocFlow`).
> - Tests: plan generation for a dual-stack allocation, and the emitted host-config
>   snippet for v4-only and dual-stack.

---

## Cross-cutting (fold into each prompt, not a separate step)

- Keep `cargo build` **warning-free** and `cargo test` green after every prompt.
- Every reconcile/grouping rule ships with a `#[test]` tied to a real observation.
- Every new TUI view ships with a **headless** render test.
- Read-only stays the default; each write is `--dry-run`-able and shows a diff first.
- No secret ever reaches argv, logs, or the config file — token via `pass`/env only.
