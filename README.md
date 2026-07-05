# canopy

A terminal UI that builds **one reconciled view of an organization's network** — its
IP address space (IPv4 **and** IPv6), its structure, and its logical host groupings —
from several sources of truth (multiple **DNS** servers and **NetBox**), and helps you
*act* on it: find free addresses, provision hosts, and reconcile DNS against NetBox.
Built on [mullion](../mullion); a sibling of [census](../census) in style and structure.

*The name:* trees — DNS and zone hierarchies — nest, and seen from above they merge into
one continuous surface, the **canopy**: the map you read and act on. Its sibling
`census` counts the inhabitants; canopy surveys the territory.

## Why

Allocating a single iDRAC address in `10.87.3.0/24` showed why no one source can be
trusted:

- **NetBox** listed only 11 of ~40 addresses actually in use (under-populated);
- several addresses had **DNS** PTRs but no NetBox entry (`iprotect-*`, cameras);
- one address answered **ARP** while appearing in neither (a squatter).

The only safe way to answer *"is this address free?"* is to merge all the sources. That
merge is the heart of canopy ([`src/reconcile.rs`](src/reconcile.rs)) — pure and fully
unit-tested against those real cases — and everything else grows from it.

## The four pillars

1. **Sources & discovery** — merge several DNS servers and NetBox, and **infer** the
   v4/v6 address space to survey automatically, rather than being told a range.
2. **Visualize** — the IP-space map (v4 and v6), the layered structure (routers →
   switches → VLANs → subnets → hosts), and logical host groupings (clusters, name
   families).
3. **Provision** — find a free address in a subnet/VLAN, report netmask/gateway/DNS for
   both families, write the name/A/AAAA to the owning DNS server, and create the NetBox
   entry.
4. **Reconcile** — point at a host or group and complete NetBox from DNS (or DNS from
   NetBox); surface incomplete and conflicting records across both.

## Status model

The per-address reconciler classifies every address by merging the sources:

| Status | Meaning | Colour |
|--------|---------|--------|
| `Free` | no source claims it — safe to allocate | green |
| `Allocated` | in NetBox **and** DNS, names agree | dim |
| `NetBoxOnly` | reserved in NetBox, no PTR yet | blue |
| `DnsOnly` | has a PTR but NetBox never recorded it (drift) | amber |
| `LiveUnregistered` | answers ARP, in neither NetBox nor DNS (squatter) | red |
| `Conflict` | NetBox name and PTR disagree | magenta |

(P5 grows this to a host-level view: forward + reverse and v4 + v6 completeness —
missing `AAAA`, missing `PTR`, forward/reverse mismatch, and cross-source conflicts.)

## Usage

```sh
canopy                        # browse the offline demo 10.87.3.0/24 in the TUI
canopy --list                 # print the reconciled table and exit (no TUI)

# live: gather real facts over SSH. NetBox + DNS run on --vantage; the ARP probe
# runs on --probe-host (must sit on the target L2). Token from `pass` (or
# $CANOPY_NETBOX_TOKEN).
canopy --live --range 10.87.3.0/24 \
       --vantage dns1.astron.nl --probe-host takkie.astron.nl
```

Keys: `j/k` move · `g/G` top/bottom · `f` next free · `Tab` cycles Table/Graph/Tree/Map · `q` quit.

Read-only by default; `--write` / `--dry-run` gate the push path and always show a diff first.

### Config

Optional, like census. Settings live in `~/.config/canopy/config.toml`
(XDG-aware; or pass `--config FILE`). Every key defaults, so the file is optional and
any CLI flag overrides it. Copy the template to start:

```sh
cp docs/config.toml.example ~/.config/canopy/config.toml
```

No secrets in the file — the NetBox token comes from `pass` (entry named by
`token_pass`) or `$CANOPY_NETBOX_TOKEN`.

### How live gathering works

canopy usually runs off the ASTRON network, so each source runs its query on an
SSH **vantage** host (reusing `~/.ssh/config`, bastion jump and all):

- **NetBox** — `curl` the REST API on the vantage; the token is fed over stdin so it
  never appears in any argv.
- **DNS** — one reverse lookup per host on the vantage's resolver (or an AXFR where
  the authoritative server permits it).
- **probe** — a parallel `ping` sweep from an on-subnet host (ARP truth).

Each source fills one field of a fact; [`sources::merge`](src/sources/mod.rs) unions
them before reconciling.

## Roadmap

The sequenced build plan is in [docs/roadmap-prompts.md](docs/roadmap-prompts.md)
(P1–P12); the long vision — node graphs, bitstream wires, the zoomable IP map, and the
switch/router fabric — is in [docs/vision.md](docs/vision.md).

- ✅ **Reconciler + TUI** over an offline fixture of the real data.
- ✅ **Live sources** — NetBox + DNS over an SSH vantage, parallel ARP probe, merged
  behind the fact shape. `--live` reconciles a real `/24` in seconds.
- ✅ **Pagination** — the table never materializes the range: `mullion::RangeSource`
  plus a lazy per-index reconcile means `--range 10.0.0.0/8` (16M addresses) browses
  for the cost of a `/24`.
- 🚧 **Sources & discovery** (P2–P4) — several DNS servers with zone routing; automatic
  v4/v6 address-space discovery; a richer NetBox source (prefixes, VLANs, devices).
- 🚧 **Reconcile, deepened** (P5–P7) — host-level completeness across forward/reverse and
  v4/v6; logical host groupings; "complete NetBox from DNS / DNS from NetBox" for a host
  or a group, planned and diffed before any write.
- 🚧 **Visualize** (P8–P10) — the v4/v6 IP map at scale, the layered topology view, and
  the groupings/clusters view with an inspector.
- 🚧 **Provision** (P11–P12) — a subnet/VLAN cheat-sheet (netmask/gateway/DNS + free-IP
  pick, both families) and a guided end-to-end provisioning flow that emits the host's
  network config, all behind `--write`/`--dry-run`.

```sh
# preview the exact changes to give 10.87.3.69 the name dop370-ipmi.nfra.nl
canopy --allocate dop370-ipmi.nfra.nl --addr 10.87.3.69 \
       --range 10.87.3.0/24 --alloc-prefix 20 --live
# add --write to apply (NetBox create runs; DNS steps still need review)
```

## Licence

GPL-3.0-or-later, like census.
