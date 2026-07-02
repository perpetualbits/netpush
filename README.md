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
netpush                 # browse the demo 10.87.3.0/24 in the TUI (read-only)
netpush --list          # print the reconciled table and exit (no TUI)
netpush --range CIDR    # browse another range (live sources: TODO)
```

Keys: `j/k` move · `g/G` top/bottom · `f` next free · `q` quit.

Read-only by default; `--write` / `--dry-run` are reserved for when live pushes land.

## Roadmap

1. ✅ **Reconciler + TUI** over an offline fixture of the real data.
2. **Live sources** — NetBox REST client (token via `pass`), DNS PTR reader, ARP probe
   (run from an on-subnet host over the bastion SSH jump).
3. **Writes** — allocate in NetBox + push forward/reverse DNS to `dns1` (edit
   `db.nfra.nl`, bump serial, `rndc reload`), with a diff preview and `--dry-run`.

## Licence

GPL-3.0-or-later, like census.
