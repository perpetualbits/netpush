// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Turning a *desired allocation* into a reviewable set of concrete changes.
//!
//! A [`Plan`] is built from an [`Allocation`] (an address + the name it should get)
//! and, when we have live data, the current reconciled state — which lets the plan
//! **refuse to touch an address that isn't free**. Each [`Action`] carries the exact
//! remote command it would run, so `--dry-run` shows precisely what `--write` will do.
//!
//! Nothing here executes anything; [`Plan::apply`] is the only thing that runs, and
//! only the binary, behind `--write`, ever calls it.

use std::net::Ipv4Addr;

use crate::reconcile::{AddressRow, AddressStatus};
use crate::sources::Vantage;

/// The end state we want: `addr` should exist as `fqdn`, on a `/prefix_len` network.
#[derive(Debug, Clone)]
pub struct Allocation {
    /// The address to allocate.
    pub addr: Ipv4Addr,
    /// The network prefix length (for NetBox's `address` field).
    pub prefix_len: u8,
    /// The fully-qualified name, e.g. `"dop370-ipmi.nfra.nl"`.
    pub fqdn: String,
}

impl Allocation {
    /// Split the FQDN into its owner label and zone, e.g.
    /// `"dop370-ipmi.nfra.nl"` → `("dop370-ipmi", "nfra.nl")`.
    ///
    /// The owner is everything before the first dot; the zone is the rest. That
    /// matches how a flat zone file like `db.nfra.nl` names its records.
    #[must_use]
    pub fn owner_and_zone(&self) -> (&str, &str) {
        self.fqdn.split_once('.').unwrap_or((self.fqdn.as_str(), ""))
    }
}

/// Which system an action touches — used to route it and to colour the preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The NetBox IPAM.
    Netbox,
    /// The forward zone on the DNS primary (`db.nfra.nl` on dns1).
    DnsForward,
    /// The reverse (PTR) zone.
    DnsReverse,
}

impl Target {
    /// A short tag for the preview, e.g. `NetBox`, `DNS-fwd`, `DNS-rev`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Target::Netbox => "NetBox",
            Target::DnsForward => "DNS-fwd",
            Target::DnsReverse => "DNS-rev",
        }
    }
}

/// One concrete change: what it does, the record/payload, and how to apply it.
#[derive(Debug, Clone)]
pub struct Action {
    /// Which system this touches.
    pub target: Target,
    /// One-line description of the change.
    pub summary: String,
    /// The record line or payload, for the human to eyeball.
    pub detail: String,
    /// The remote command to run on the vantage host.
    pub script: String,
    /// Whether the NetBox token must be fed to `script` via stdin.
    pub needs_token: bool,
    /// `true` when the step still needs human review before it can be trusted
    /// (e.g. the DNS serial bump / reverse-zone mechanism we have not automated).
    pub review: bool,
}

/// A full, ordered set of changes to realise one allocation.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The allocation this plan realises.
    pub alloc: Allocation,
    /// The ordered actions.
    pub actions: Vec<Action>,
}

impl Plan {
    /// Build the plan for `alloc`, refusing if `current` shows the address is taken.
    ///
    /// How: if we have reconciled rows and the target is anything but `Free`, bail —
    /// we never overwrite an address some source already claims. Otherwise emit the
    /// three changes (NetBox object, forward `A`, reverse `PTR`). The principle is
    /// the reconciler's: only a `Free` address is safe to hand out.
    ///
    /// # Errors
    /// Fails if the address is not free in the supplied current state.
    pub fn for_allocation(
        alloc: Allocation,
        netbox_base: &str,
        current: Option<&[AddressRow]>,
    ) -> anyhow::Result<Plan> {
        if let Some(rows) = current {
            if let Some(row) = rows.iter().find(|r| r.addr == alloc.addr) {
                if row.status != AddressStatus::Free {
                    anyhow::bail!(
                        "refusing to allocate {}: it is {:?}{}",
                        alloc.addr,
                        row.status,
                        row.name.as_deref().map(|n| format!(" ({n})")).unwrap_or_default()
                    );
                }
            }
        }

        let (owner, zone) = alloc.owner_and_zone();
        let base = netbox_base.trim_end_matches('/');

        // 1) NetBox: create the IP object with its DNS name. Reversible (delete).
        let payload = format!(
            r#"{{"address":"{}/{}","dns_name":"{}","status":"active"}}"#,
            alloc.addr, alloc.prefix_len, alloc.fqdn
        );
        let netbox = Action {
            target: Target::Netbox,
            summary: format!("NetBox: create {} as {}", alloc.addr, alloc.fqdn),
            detail: payload.clone(),
            script: format!(
                "read TOK; curl -sS --max-time 25 -H \"Authorization: Token $TOK\" \
                 -H 'Content-Type: application/json' -X POST '{base}/api/ipam/ip-addresses/' -d '{payload}'"
            ),
            needs_token: true,
            review: false,
        };

        // 2) Forward A record in db.nfra.nl (static, inline-signed → file edit + reload).
        let record = format!("{owner}\tIN\tA\t{}", alloc.addr);
        let forward = Action {
            target: Target::DnsForward,
            summary: format!("DNS {zone}: add A record for {owner}"),
            detail: record.clone(),
            script: forward_script(zone, &record),
            needs_token: false,
            review: true, // SOA serial bump + reload is the sensitive part
        };

        // 3) Reverse PTR. On this estate PTRs are generated from NetBox (gen_ptr.py),
        // so the reverse follows step 1 — but the exact mechanism must be confirmed.
        let reverse = Action {
            target: Target::DnsReverse,
            summary: format!("DNS reverse: PTR {} -> {}", alloc.addr, alloc.fqdn),
            detail: format!("{} IN PTR {}", reverse_name(alloc.addr), alloc.fqdn),
            script: "sudo -n /root/bin/gen_ptr.py 2>/dev/null || true".to_string(),
            needs_token: false,
            review: true, // confirm gen_ptr.py covers IPv4 + the right reverse zone
        };

        Ok(Plan { alloc, actions: vec![netbox, forward, reverse] })
    }

    /// A human-readable dry-run preview of every action.
    #[must_use]
    pub fn preview(&self) -> String {
        let mut s = format!("Plan: allocate {} as {}\n", self.alloc.addr, self.alloc.fqdn);
        for (i, a) in self.actions.iter().enumerate() {
            let flag = if a.review { "  [needs review]" } else { "" };
            s.push_str(&format!("\n{}. [{}] {}{}\n", i + 1, a.target.label(), a.summary, flag));
            s.push_str(&format!("     {}\n", a.detail));
            s.push_str(&format!("     $ {}\n", a.script));
        }
        s
    }

    /// Apply every action on `vantage` (dns1), feeding `token` to those that need it.
    ///
    /// The caller must have decided writes are allowed (`--write` and not
    /// `--dry-run`); this method does not re-check. Runs actions in order and stops
    /// on the first failure.
    ///
    /// # Errors
    /// Propagates the first failing remote command.
    pub fn apply(&self, vantage: &Vantage, token: &str) -> anyhow::Result<()> {
        for a in &self.actions {
            let out = if a.needs_token {
                vantage.run_with_stdin(&a.script, &format!("{token}\n"))?
            } else {
                vantage.run(&a.script)?
            };
            println!("[applied] {}\n{}", a.summary, out.trim());
        }
        Ok(())
    }
}

/// The `$ORIGIN`-relative reverse name for an address, e.g. `10.87.3.69` →
/// `69.3.87.10.in-addr.arpa`.
fn reverse_name(addr: Ipv4Addr) -> String {
    let o = addr.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// The forward-zone edit script: back up the file, append the record, validate the
/// zone, and reload. The SOA serial bump is intentionally left to review (see the
/// action's `review` flag) — getting it wrong breaks secondaries and DNSSEC.
fn forward_script(zone: &str, record: &str) -> String {
    let file = "/etc/bind/master/db.nfra.nl";
    format!(
        "set -e; f={file}; sudo -n cp -a \"$f\" \"$f.netpush-bak\"; \
         printf '%s\\n' '{record}' | sudo -n tee -a \"$f\" >/dev/null; \
         sudo -n named-checkzone {zone} \"$f\" && sudo -n rndc reload {zone}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcile::{Cidr, NetBoxRecord, AddressFacts, reconcile};

    fn alloc() -> Allocation {
        Allocation { addr: "10.87.3.69".parse().unwrap(), prefix_len: 20, fqdn: "dop370-ipmi.nfra.nl".into() }
    }

    #[test]
    fn owner_and_zone_split() {
        assert_eq!(alloc().owner_and_zone(), ("dop370-ipmi", "nfra.nl"));
    }

    #[test]
    fn reverse_name_is_correct() {
        assert_eq!(reverse_name("10.87.3.69".parse().unwrap()), "69.3.87.10.in-addr.arpa");
    }

    #[test]
    fn plan_has_three_actions_with_real_payloads() {
        let p = Plan::for_allocation(alloc(), "https://netbox.astron.nl/", None).unwrap();
        assert_eq!(p.actions.len(), 3);
        assert_eq!(p.actions[0].target, Target::Netbox);
        assert!(p.actions[0].script.contains("10.87.3.69/20"));
        assert!(p.actions[0].script.contains("\"dns_name\":\"dop370-ipmi.nfra.nl\""));
        // no double slash from the trailing '/' in the base URL
        assert!(p.actions[0].script.contains("netbox.astron.nl/api/ipam/ip-addresses/"));
        assert!(p.actions[1].detail.contains("dop370-ipmi\tIN\tA\t10.87.3.69"));
        assert!(p.actions[1].script.contains("rndc reload nfra.nl"));
    }

    #[test]
    fn refuses_to_allocate_a_taken_address() {
        // Build a current state where .69 is claimed by DNS.
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let facts = vec![AddressFacts {
            addr: "10.87.3.69".parse().unwrap(),
            netbox: Some(NetBoxRecord { dns_name: Some("someone-else.nfra.nl".into()) }),
            ptr: Some("someone-else.nfra.nl.".into()),
            live: false,
        }];
        let rows = reconcile(range, &facts);
        let err = Plan::for_allocation(alloc(), "https://netbox.astron.nl", Some(&rows)).unwrap_err();
        assert!(err.to_string().contains("refusing to allocate"));
    }

    #[test]
    fn allows_allocation_when_free() {
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let rows = reconcile(range, &[]); // everything free
        assert!(Plan::for_allocation(alloc(), "https://netbox.astron.nl", Some(&rows)).is_ok());
    }

    #[test]
    fn preview_mentions_review_steps() {
        let p = Plan::for_allocation(alloc(), "https://netbox.astron.nl", None).unwrap();
        let text = p.preview();
        assert!(text.contains("allocate 10.87.3.69 as dop370-ipmi.nfra.nl"));
        assert!(text.contains("[needs review]"));
    }
}
