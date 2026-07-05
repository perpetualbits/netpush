<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- Copyright (C) 2026  Epsilon Null Operation -->

# The ASTRON DNS estate (as discovered)

The map canopy's `dns` model encodes — and the topology the future node-graph view
will draw. Recorded 2026-07-03 from live inspection.

## Zones, servers, serial schemes

| Zone | Master server | File | Serial scheme | canopy status |
|------|---------------|------|---------------|----------------|
| `nfra.nl` (forward) | **dns1.astron.nl** | `/etc/bind/master/db.nfra.nl` | `YYYYMMDDnn` (e.g. `2026070300`) | ✅ safe edit proven |
| `astron.nl` (forward) | **dns1.astron.nl** | `/etc/bind/master/db.astron.nl` | `YYYYMMDDnn` | model ready |
| `10.in-addr.arpa` (reverse, all 10.x) | **ntserver1.nfra.nl** | *TBD — confirm on ntserver1* | plain integer (e.g. `3057388`) | 🚧 gated until file path known |
| `*.lofar` + LOFAR reverse | **lcs020.control.lofar** | `/var/lib/named/master/*` | mixed | out of scope (separate estate) |

Secondaries for `10.in-addr.arpa`: ntserver8, ntserver16, ns0.jive.nl, ns1.jive.nl.

## Consequences for the write path

- A host like `dop370-ipmi.nfra.nl` at `10.87.3.69` needs **two edits on two servers**:
  the forward `A` on dns1 and the reverse `PTR` on ntserver1. They have **different
  serial schemes**, so the bump logic is per-zone ([`dns::serial::SerialScheme`]).
- dns1 is **DNSSEC inline-signed**: edit the unsigned `db.nfra.nl`, `rndc reload`, and
  named re-signs. `named-checkzone` on a copy before swap-in catches malformed edits.
- `gen_ptr.py` on dns1 is **IPv6-only** — it does *not* manage the IPv4 reverse. Do
  not use it for `in-addr.arpa`.

## The reverse zone is NOT automatable (Windows, cross-team)

`ntserver1.nfra.nl` is a **Windows DNS server** (the `ntserver*` naming gives it
away), owned by ASTRON's "windows people". There is no SSH/BIND/`rndc` path there,
and — org reality — changing anything on it is **slow, needs a remote-desktop (RDP)
session, and cannot currently be automated** (team territoriality). Things that
would change this (install `sshd` + PowerShell, or WSL) are not on the table now.

**Consequence for canopy:** the reverse `PTR` is a **manual hand-off**, not an SSH
apply. canopy emits the exact record and its destination (the `10.in-addr.arpa`
zone on ntserver1) for a human to add via RDP; it must NOT be modelled as a BIND
file edit. The forward `A` (dns1, Linux/BIND) and the NetBox object stay fully
automatable — only the PTR waits on the windows-people.

## Why this is the node-graph seed

Each row above is a **group node** (a zone) pinned to a **server**; records inside are
child nodes; CNAME/NS/PTR are **edges** to other names (`dns::Record::target_name`).
Draw it and you see the estate — which is the whole point of the node-graph milestone.
