<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) 2026  Epsilon Null Operation -->

# canopy — the long vision

Recorded 2026-07-03. This is the north star; the [README roadmap](../README.md)
tracks the near-term steps toward it.

## DNS as a mullion node graph

Work with DNS through **mullion's node graph**. DNS is naturally a good fit:

- It has a **nested structure** (zones, subdomains, records) that maps onto nested
  nodes.
- Real-world groupings — e.g. a **cluster of computers** — are a named grouping, so
  rendering them as a labelled group node gives an instant overview of the estate.

The graph is the interface *and* the model: you see the shape of DNS, not a flat list.

## Layout you can trust

The user must be able to organise the graph **any way they want**:

- **By hand** — place nodes and **hand-route the wires** yourself; or
- **Automatically** — let the engine lay out nodes and route wires.

The automatic layout is the hard, valuable part. Aim for a **wiring algorithm that
eases cognitive complexity** by making node graphs:

- **regular** and **aligned**,
- with **few crossings**,
- **compact**, and
- **flexible**.

Key idea: **forbid certain local minima in wiring-space** so the optimiser is *forced*
toward the layout you actually want, instead of settling into a technically-fine-but-
ugly arrangement. Constrain the search space to shape the result.

## The transition play

1. **Lay out** the *current* DNS nicely as a node graph.
2. **Transform** it — on the graph — into what we want it to become.
3. **Migrate** the backing server to something modern, e.g. **Technitium** or
   **PowerDNS**, and **use canopy to drive the transition** (diff current → target,
   push the changes, verify).

The reconciler built in milestone 1 is the seed of this: it already compares "what is"
across sources. The graph is "what is" and "what we want", side by side.

## Then: roles / personalities, one foundation

Once the migration is done, the **same foundation** grows different faces:

- a **quick DNS editor** (fast, keyboard-driven record edits),
- a **DNS design application** with node graphs (plan estates visually),
- and many more.

All sharing the reconcile core, the source layer, and the mullion UI — different
*personalities* over one engine.

## Live wires: the bitstream

Use mullion's **bitstream feature** to make the wires *carry information*, not just
connect nodes. A wire renders as a stream of little coloured squares — **closed = 1,
open = 0** — so a link visibly shows what flows through it: the route it carries, the
gateway behind it, utilisation, VLAN, whatever we bind to it. The graph stops being a
static diagram and becomes a live view of the network.

## Beyond DNS: switches and routers

Extend the same model to the **switching/routing fabric**:

- Reach **switch and router configs** through the tool.
- **Laying out a line by hand changes the config on the switch** — draw the topology
  you want and the tool pushes it (VLAN assignment, port config, routes) — *only when
  you have explicitly put it in "apply" mode*. Design-only by default.

At that point canopy is a **real network tool**: one node graph over DNS, IPAM, and
the L2/L3 fabric, where the picture and the running config are the same thing.

## AAA & security (non-negotiable for the above)

Pushing config to switches/routers raises the stakes hard. Before the fabric-write
features land we need proper **AAA** (authentication, authorization, accounting) and
security: who may change what, every change attributed and logged, least-privilege
credentials, explicit apply-mode gating, and a full audit trail. The read-only-by-
default, `--dry-run`, diff-before-apply discipline from the DNS side is the seed —
the fabric side must be stricter still.

## Pagination (needed for scale)

canopy must paginate. A `/24` fits on screen, but `10.0.0.0/8` is 16,777,216
addresses; DNS zones and other listings grow unbounded too. Every data path —
reconcile, the table, the tree, the graph — needs **windowed, lazy, paginated** data
and must never materialise a whole `/8` (or a giant zone) at once. This underpins all
the large-scale views below.

## The IP map — a zoomable square-of-squares

Render an address space as a big grid of **little squares** (the same primitive as a
bitstream / mullion's `spiral_stress` demo): a **filled** square = used space, an
**outline** = free.

You can't draw 16M cells, so each cell **aggregates a block**. A `32×32` grid over a
`/8` is 1024 cells, each standing for **16,384 addresses** (a `/18`); fill vs outline
(or a shade in between) shows how used each block is. At the finest zoom one cell = one
address, and it *is* a bitstream.

- **Zoom:** select a cell and zoom in; a few steps take you `/8` → blocks → a subnet
  small enough to resolve into individual IPs (which the table/tree already do).
- **Axis legends need thought** (likely a discussion): what do the x/y axes label at
  each zoom level — nibble/byte boundaries, the CIDR of the visible window, or the
  block each cell covers? The legend must stay meaningful as you zoom *and* let you map
  a screen position back to an address range unambiguously. This is the open design
  question before building it.

## Why this order

We earn the graph by first getting the boring plumbing right (live sources → reconcile
→ push). The plumbing is milestone 2–3. The graph is what makes it a *design* tool
rather than a CRUD tool — but it needs trustworthy data underneath, which is exactly
what the reconciler guarantees. The bitstream wires, the switch/router fabric, and the
AAA that must gate them all come *after* the graph and the DNS write path are solid.
