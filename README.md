# netpush

A terminal UI that reconciles what **NetBox**, **DNS**, and the **live network**
each believe about an IP range — then (soon) pushes the missing NetBox/DNS records
so the three stop drifting apart. Built on [mullion](../mullion); a sibling of
[census](../census) in style and structure.

## Why

Allocating a single iDRAC address in `10.87.3.0/24` showed why no one source can be
trusted:

- **NetBox** listed only 11 of ~40 addresses actually in use (under-populated);
- several addresses had **DNS** PTRs but no NetBox entry (`iprotect-*`, cameras);
- one address answered **ARP** while appearing in neither (a squatter).

The only safe way to answer *"is this address free?"* is to merge all three. That
merge is the heart of netpush ([`src/reconcile.rs`](src/reconcile.rs)) — pure and
fully unit-tested against those real cases.

## Status model

| Status | Meaning | Colour |
|--------|---------|--------|
| `Free` | no source claims it — safe to allocate | green |
| `Allocated` | in NetBox **and** DNS, names agree | dim |
| `NetBoxOnly` | reserved in NetBox, no PTR yet | blue |
| `DnsOnly` | has a PTR but NetBox never recorded it (drift) | amber |
| `LiveUnregistered` | answers ARP, in neither NetBox nor DNS (squatter) | red |
| `Conflict` | NetBox name and PTR disagree | magenta |

## Usage

```sh
netpush                       # browse the offline demo 10.87.3.0/24 in the TUI
netpush --list                # print the reconciled table and exit (no TUI)

# live: gather real facts over SSH. NetBox + DNS run on --vantage; the ARP probe
# runs on --probe-host (must sit on the target L2). Token from `pass` (or
# $NETPUSH_NETBOX_TOKEN).
netpush --live --range 10.87.3.0/24 \
        --vantage dns1.astron.nl --probe-host takkie.astron.nl
```

Keys: `j/k` move · `g/G` top/bottom · `f` next free · `q` quit.

Read-only by default; `--write` / `--dry-run` are reserved for when the push path lands.

### How live gathering works

netpush usually runs off the ASTRON network, so each source runs its query on an
SSH **vantage** host (reusing `~/.ssh/config`, bastion jump and all):

- **NetBox** — `curl` the REST API on the vantage; the token is fed over stdin so it
  never appears in any argv.
- **DNS** — one reverse lookup per host on the vantage's resolver.
- **probe** — a parallel `ping` sweep from an on-subnet host (ARP truth).

Each source fills one field of a fact; [`sources::merge`](src/sources/mod.rs) unions
them before reconciling.

## Roadmap

1. ✅ **Reconciler + TUI** over an offline fixture of the real data.
2. ✅ **Live sources** — NetBox + DNS over an SSH vantage, parallel ARP probe, merged
   behind the fact shape. `--live` reconciles a real `/24` in seconds.
3. 🚧 **Writes** — an allocation **planner** with a `--dry-run` diff is done: NetBox
   create + forward `A` + reverse `PTR`, refusing any non-free target. The live
   `--write` apply is wired but gated and unrun; the DNS SOA-serial bump and reverse
   mechanism are flagged `[needs review]` before it can be trusted.
4. **Node-graph DNS** — the long vision in [docs/vision.md](docs/vision.md): DNS as a
   mullion node graph, live **bitstream** wires, and eventually the switch/router
   fabric (with the AAA/security that must gate it).

```sh
# preview the exact changes to give 10.87.3.69 the name dop370-ipmi.nfra.nl
netpush --allocate dop370-ipmi.nfra.nl --addr 10.87.3.69 \
        --range 10.87.3.0/24 --alloc-prefix 20 --live
# add --write to apply (NetBox create runs; DNS steps still need review)
```

## Licence

GPL-3.0-or-later, like census.
