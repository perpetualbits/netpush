#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026  Epsilon Null Operation
"""Populate NetBox Aggregates and mark supernet prefixes as `container`, so canopy's
`--live` discovery surveys the real subnets instead of whole /8s.

Why: canopy discovers the address space from NetBox. Aggregates record *what space is
ours* (the RIR/RFC1918 parents); `container`-status prefixes mark supernets that only
group child prefixes. canopy skips both when choosing what to survey, so getting them
right makes discovery clean.

Reachability: NetBox is internal-only, so — exactly like canopy — this runs its API calls
via `curl` **on the SSH vantage** (default `dns1.astron.nl`), not directly from where you
launch it. Override with $NETBOX_VANTAGE. The token is fed to the remote `curl` over
stdin, so it never appears in any argv.

SAFE BY DEFAULT: prints the planned changes and writes nothing until you pass --apply.
IDEMPOTENT: it checks before creating/patching, so re-running is fine.

Token: taken from $CANOPY_NETBOX_TOKEN, else `pass astron/netbox.astron.nl/dns_api_token`.
       A read-scope token is enough for the dry run; --apply needs WRITE scope.

Usage:
  ./netbox-init-aggregates.py            # dry run — show what would change
  ./netbox-init-aggregates.py --apply    # actually create/patch
  NETBOX_VANTAGE=dns1.astron.nl ./netbox-init-aggregates.py --apply
"""

import json
import os
import subprocess
import sys

NETBOX_URL = os.environ.get("NETBOX_URL", "https://netbox.astron.nl").rstrip("/")
API = NETBOX_URL + "/api"
VANTAGE = os.environ.get("NETBOX_VANTAGE", "dns1.astron.nl")  # SSH host that can reach NetBox

# ---- edit these to match your estate --------------------------------------------------

# RIRs to ensure exist: (slug, display name, is_private).
RIRS = [
    ("rfc1918", "RFC1918", True),
    ("ripe-ncc", "RIPE NCC", False),
]

# Aggregates to ensure exist: (prefix, rir_slug).
#   The RFC1918 parents are universal. 145.124.0.0/16 is ASTRON's RIPE range (the migration
#   target for the 10.x hosts). REPLACE/extend the other RIPE examples with your ACTUAL
#   RIPE-allocated blocks (look them up in the RIPE database) — don't guess: a wrong
#   aggregate is worse than none.
AGGREGATES = [
    ("10.0.0.0/8", "rfc1918"),
    ("172.16.0.0/12", "rfc1918"),
    ("192.168.0.0/16", "rfc1918"),
    ("145.124.0.0/16", "ripe-ncc"),  # the new range the 10.x hosts migrate to
    # --- add your other real RIPE allocations, e.g.: ---
    # ("195.169.0.0/16", "ripe-ncc"),
    # ("2001:610::/32", "ripe-ncc"),
]

# Existing PREFIXES to flip to status=container (supernets that only group child prefixes).
# Only prefixes that ALREADY exist are touched; a missing one is left alone. Add
# 145.124.0.0/16 here too *if* you carve it into child subnets and want canopy to survey
# those children rather than the whole /16.
CONTAINER_PREFIXES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# ---------------------------------------------------------------------------------------

APPLY = "--apply" in sys.argv[1:]


def get_token():
    """The NetBox token: $CANOPY_NETBOX_TOKEN, else the first line of `pass <entry>`."""
    env = os.environ.get("CANOPY_NETBOX_TOKEN")
    if env and env.strip():
        return env.strip()
    out = subprocess.run(
        ["pass", "astron/netbox.astron.nl/dns_api_token"],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0 or not out.stdout.strip():
        sys.exit("no NetBox token (set CANOPY_NETBOX_TOKEN or configure `pass`)")
    return out.stdout.splitlines()[0].strip()


TOKEN = get_token()


def build_remote(method, url, body_json):
    """The remote shell command: read the token from stdin, then curl NetBox. `-w` appends
    the HTTP status on its own line so we can tell a 201 from a 400 (curl exits 0 either
    way). The token is only ever `$TOK`, never a literal — it arrives over stdin."""
    w = '-w "\\nHTTP_STATUS:%{http_code}"'  # literal \n + status marker for curl
    auth = '-H "Authorization: Token $TOK" -H "Accept: application/json"'
    cmd = f"read TOK; curl -sS --max-time 30 {w} {auth}"
    if method == "GET":
        return f"{cmd} '{url}'"
    return f"{cmd} -H \"Content-Type: application/json\" -X {method} '{url}' -d '{body_json}'"


def req(method, path, body=None):
    """One NetBox API call, run via `curl` on the vantage over SSH; returns decoded JSON,
    or exits printing NetBox's error body."""
    body_json = json.dumps(body) if body is not None else None
    remote = build_remote(method, API + path, body_json)
    out = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", VANTAGE, remote],
        input=TOKEN + "\n",
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        sys.exit(f"ssh {VANTAGE} failed for {method} {path}: {out.stderr.strip()}")
    text = out.stdout
    marker = "HTTP_STATUS:"
    idx = text.rfind(marker)
    if idx == -1:
        sys.exit(f"unexpected response for {method} {path}: {text[:400]}")
    code = text[idx + len(marker):].strip()
    body_text = text[:idx].rstrip("\n")
    if not code.isdigit() or int(code) >= 400:
        sys.exit(f"NetBox {method} {path} → HTTP {code}\n{body_text}")
    return json.loads(body_text) if body_text else {}


def find_one(endpoint, **params):
    """The first object matching an exact-match query, or None."""
    from urllib.parse import urlencode

    return next(iter(req("GET", f"{endpoint}?{urlencode(params)}").get("results", [])), None)


def ensure_rir(slug, name, is_private):
    """Create the RIR if missing; return its id (None in a dry run where it'd be created)."""
    existing = find_one("/ipam/rirs/", slug=slug)
    if existing:
        print(f"  rir {slug}: exists (id {existing['id']})")
        return existing["id"]
    if not APPLY:
        print(f"  rir {slug}: WOULD CREATE ({name}, private={is_private})")
        return None
    created = req("POST", "/ipam/rirs/", {"slug": slug, "name": name, "is_private": is_private})
    print(f"  rir {slug}: created (id {created['id']})")
    return created["id"]


def ensure_aggregate(prefix, rir_id):
    """Create the aggregate under its RIR if missing."""
    if find_one("/ipam/aggregates/", prefix=prefix):
        print(f"  aggregate {prefix}: exists")
        return
    if not APPLY or rir_id is None:
        print(f"  aggregate {prefix}: WOULD CREATE (rir id {rir_id})")
        return
    req("POST", "/ipam/aggregates/", {"prefix": prefix, "rir": rir_id})
    print(f"  aggregate {prefix}: created")


def ensure_container(prefix):
    """Flip an existing prefix to status=container; leave a missing prefix untouched."""
    existing = find_one("/ipam/prefixes/", prefix=prefix)
    if not existing:
        print(f"  prefix {prefix}: not present — skipping")
        return
    status = (existing.get("status") or {}).get("value")
    if status == "container":
        print(f"  prefix {prefix}: already container")
        return
    if not APPLY:
        print(f"  prefix {prefix}: WOULD PATCH status {status!r} -> container")
        return
    req("PATCH", f"/ipam/prefixes/{existing['id']}/", {"status": "container"})
    print(f"  prefix {prefix}: status {status!r} -> container")


def main():
    mode = "APPLY" if APPLY else "DRY-RUN — pass --apply to write"
    print(f"NetBox: {NETBOX_URL}  via ssh {VANTAGE}   ({mode})\n")

    print("RIRs:")
    rir_ids = {slug: ensure_rir(slug, name, priv) for slug, name, priv in RIRS}

    print("Aggregates:")
    for prefix, rir_slug in AGGREGATES:
        ensure_aggregate(prefix, rir_ids.get(rir_slug))

    print("Container prefixes:")
    for prefix in CONTAINER_PREFIXES:
        ensure_container(prefix)

    if not APPLY:
        print("\n(dry run — nothing changed. Re-run with --apply to write.)")


if __name__ == "__main__":
    main()
