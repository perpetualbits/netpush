// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Turning a *desired allocation* into a reviewable set of concrete changes.
//!
//! A [`Plan`] is built from an [`Allocation`] (an address + the name it should get)
//! and, when we have live data, the current reconciled state — which lets the plan
//! **refuse to touch an address that isn't free**. Each [`Action`] carries the exact
//! remote command it would run *and the host to run it on*, because the estate is
//! multi-server (NetBox + forward DNS via dns1, reverse DNS on ntserver1).
//!
//! Nothing here mutates anything until [`Plan::apply`] is called — and that only
//! happens from the binary, behind `--write`, and it skips any step still flagged
//! for review.

use std::net::IpAddr;

use crate::dns::{reverse_ptr, DnsName, Record, Zone};
use crate::reconcile::{AddressRow, AddressStatus};
use crate::sources::Vantage;

/// The end state we want: `addr` should exist as `fqdn`, on a `/prefix_len` network.
#[derive(Debug, Clone)]
pub struct Allocation {
    /// The address to allocate (IPv4 or IPv6).
    pub addr: IpAddr,
    /// The network prefix length (for NetBox's `address` field).
    pub prefix_len: u8,
    /// The fully-qualified name, e.g. `"dop370-ipmi.nfra.nl"`.
    pub fqdn: String,
}

/// Which system an action touches — used to route it and to colour the preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The NetBox IPAM.
    Netbox,
    /// A forward zone on its DNS primary.
    DnsForward,
    /// A reverse (PTR) zone on its DNS primary.
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

/// One concrete change: what it does, the record/payload, where and how to apply it.
#[derive(Debug, Clone)]
pub struct Action {
    /// Which system this touches.
    pub target: Target,
    /// The SSH host to run on, or `None` to use the default vantage (NetBox).
    pub host: Option<String>,
    /// One-line description of the change.
    pub summary: String,
    /// The record line or payload, for the human to eyeball.
    pub detail: String,
    /// The remote command to run.
    pub script: String,
    /// Whether the NetBox token must be fed to `script` via stdin.
    pub needs_token: bool,
    /// `true` when the step cannot be automated at all and must be done by hand
    /// (e.g. the reverse PTR on the Windows, RDP-only ntserver1). `script` then holds
    /// a human instruction, not a command. Implies `review`.
    pub manual: bool,
    /// `true` when the step is shown but never auto-applied — either it needs review,
    /// or it is `manual`.
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
    /// How: if reconciled rows are supplied and the target is anything but `Free`,
    /// bail — we never overwrite an address some source already claims. Otherwise
    /// emit the three changes: NetBox object, forward `A` on dns1, reverse `PTR` on
    /// ntserver1. The DNS actions use [`Zone`], so they carry the safe edit script
    /// and the correct server.
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

        let fqdn = DnsName::parse(&alloc.fqdn);
        let base = netbox_base.trim_end_matches('/');

        // 1) NetBox: create the IP object with its DNS name. Reversible (delete).
        let payload = format!(
            r#"{{"address":"{}/{}","dns_name":"{}","status":"active"}}"#,
            alloc.addr, alloc.prefix_len, alloc.fqdn
        );
        let netbox = Action {
            target: Target::Netbox,
            host: None, // runs on the default vantage
            summary: format!("create {} as {}", alloc.addr, alloc.fqdn),
            detail: payload.clone(),
            script: format!(
                "read TOK; curl -sS --max-time 25 -H \"Authorization: Token $TOK\" \
                 -H 'Content-Type: application/json' -X POST '{base}/api/ipam/ip-addresses/' -d '{payload}'"
            ),
            needs_token: true,
            manual: false,
            review: false,
        };

        // 2) Forward address record on dns1 — A for IPv4, AAAA for IPv6. Matured safe
        //    edit (validate a copy, then swap).
        let fzone = Zone::nfra_forward();
        let a_rec = Record::address(fqdn.clone(), alloc.addr);
        let forward = Action {
            target: Target::DnsForward,
            host: Some(fzone.server.clone()),
            summary: format!("add {} {} -> {} in {}", a_rec.rtype.token(), fqdn, alloc.addr, fzone.origin),
            detail: a_rec.zone_line(&fzone.origin),
            script: fzone.add_record_script(&a_rec),
            needs_token: false,
            manual: false,
            review: !fzone.is_editable(),
        };

        // 3) Reverse PTR — the IPv4 10.in-addr.arpa zone is mastered on ntserver1, a
        // WINDOWS DNS server owned by another team (no SSH/BIND, RDP-only, not
        // automatable); the IPv6 ip6.arpa zone is likewise mastered elsewhere. Either
        // way this is a MANUAL hand-off — netpush emits the exact record and where it
        // goes, for a human to add. It is never auto-applied.
        let ptr_rec = Record::ptr(reverse_ptr(alloc.addr), &fqdn);
        let (rev_host, rev_zone) = if alloc.addr.is_ipv6() {
            (None, "ip6.arpa")
        } else {
            (Some("ntserver1.nfra.nl".to_string()), "10.in-addr.arpa")
        };
        let reverse = Action {
            target: Target::DnsReverse,
            host: rev_host,
            summary: format!("add PTR {} -> {} (reverse DNS, apply by hand)", alloc.addr, alloc.fqdn),
            detail: format!("{ptr_rec}   (add to the {rev_zone} reverse zone by hand)"),
            script: format!("manual step — add this PTR to the {rev_zone} zone by hand; not automatable from here"),
            needs_token: false,
            manual: true,
            review: true,
        };

        Ok(Plan { alloc, actions: vec![netbox, forward, reverse] })
    }

    /// A human-readable dry-run preview of every action.
    #[must_use]
    pub fn preview(&self) -> String {
        let mut s = format!("Plan: allocate {} as {}\n", self.alloc.addr, self.alloc.fqdn);
        for (i, a) in self.actions.iter().enumerate() {
            let at = a.host.as_deref().map(|h| format!(" @{h}")).unwrap_or_default();
            let flag = if a.manual {
                "  [manual — not automatable]"
            } else if a.review {
                "  [needs review — will NOT auto-apply]"
            } else {
                ""
            };
            s.push_str(&format!("\n{}. [{}{}] {}{}\n", i + 1, a.target.label(), at, a.summary, flag));
            s.push_str(&format!("     record: {}\n", a.detail));
            // A manual step's `script` is an instruction, not a command — show it as such.
            let lead = if a.manual { "→" } else { "$" };
            s.push_str(&format!("     {lead} {}\n", first_line(&a.script)));
        }
        s
    }

    /// Apply every non-review action, each on its own host, feeding `token` to those
    /// that need it. Review-flagged actions are reported and skipped.
    ///
    /// The caller must have decided writes are allowed (`--write` and not
    /// `--dry-run`); this runs actions in order and stops on the first failure.
    ///
    /// # Errors
    /// Propagates the first failing remote command.
    ///
    /// Returns a text log of what was applied/skipped (so a TUI caller can show it
    /// rather than having it printed to a screen it doesn't control).
    pub fn apply(&self, default_vantage: &Vantage, token: &str) -> anyhow::Result<String> {
        let mut log = String::new();
        for a in &self.actions {
            if a.review {
                log.push_str(&format!("[skip: needs review] {} ({})\n", a.summary, a.target.label()));
                continue;
            }
            let host = a.host.clone().unwrap_or_else(|| default_vantage.host.clone());
            let vantage = Vantage::new(host);
            let out = if a.needs_token {
                vantage.run_with_stdin(&a.script, &format!("{token}\n"))?
            } else {
                vantage.run(&a.script)?
            };
            log.push_str(&format!("[applied] {}\n{}\n", a.summary, out.trim()));
        }
        Ok(log)
    }
}

/// The first line of a (possibly multi-line) script, for a compact preview.
fn first_line(script: &str) -> &str {
    script.lines().next().unwrap_or(script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcile::{reconcile, AddressFacts, Cidr, NetBoxRecord};

    fn alloc() -> Allocation {
        Allocation { addr: "10.87.3.69".parse().unwrap(), prefix_len: 20, fqdn: "dop370-ipmi.nfra.nl".into() }
    }

    #[test]
    fn ipv6_allocation_uses_aaaa_and_ip6_arpa() {
        let alloc = Allocation { addr: "2001:db8::100".parse().unwrap(), prefix_len: 48, fqdn: "newhost.nfra.nl".into() };
        let plan = Plan::for_allocation(alloc, "https://netbox.astron.nl", None).unwrap();
        let text = plan.preview();
        // NetBox carries the v6 address + prefix.
        assert!(text.contains(r#""address":"2001:db8::100/48""#), "{text}");
        // Forward record is AAAA, not A.
        assert!(text.contains("AAAA") && text.contains("2001:db8::100"), "{text}");
        // Reverse PTR is an ip6.arpa name, still a manual hand-off.
        assert!(text.contains("ip6.arpa"), "{text}");
        assert!(plan.actions[2].manual);
    }

    #[test]
    fn plan_has_three_routed_actions() {
        let p = Plan::for_allocation(alloc(), "https://netbox.astron.nl/", None).unwrap();
        assert_eq!(p.actions.len(), 3);

        // NetBox: real payload, no double slash, runs on the default vantage.
        let nb = &p.actions[0];
        assert_eq!(nb.target, Target::Netbox);
        assert!(nb.host.is_none());
        assert!(nb.script.contains("10.87.3.69/20"));
        assert!(nb.script.contains("netbox.astron.nl/api/ipam/ip-addresses/"));

        // Forward: safe edit on dns1, ready to run.
        let fwd = &p.actions[1];
        assert_eq!(fwd.host.as_deref(), Some("dns1.astron.nl"));
        assert!(!fwd.review);
        assert!(fwd.script.contains("named-checkzone"));
        assert!(fwd.detail.contains("dop370-ipmi\tIN\tA\t10.87.3.69"));

        // Reverse: on ntserver1, gated until the file path is confirmed.
        let rev = &p.actions[2];
        assert_eq!(rev.host.as_deref(), Some("ntserver1.nfra.nl"));
        assert!(rev.review);
    }

    #[test]
    fn refuses_to_allocate_a_taken_address() {
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
        let rows = reconcile(range, &[]);
        assert!(Plan::for_allocation(alloc(), "https://netbox.astron.nl", Some(&rows)).is_ok());
    }

    #[test]
    fn preview_shows_hosts_and_manual_reverse() {
        let text = Plan::for_allocation(alloc(), "https://netbox.astron.nl", None).unwrap().preview();
        assert!(text.contains("@dns1.astron.nl"));
        assert!(text.contains("@ntserver1.nfra.nl"));
        // The reverse PTR is a manual hand-off (Windows/RDP), not an auto-applied step.
        assert!(text.contains("manual — not automatable"));
    }

    #[test]
    fn reverse_action_is_manual_and_gated() {
        let plan = Plan::for_allocation(alloc(), "https://netbox.astron.nl", None).unwrap();
        let rev = &plan.actions[2];
        assert_eq!(rev.target, Target::DnsReverse);
        assert!(rev.manual && rev.review); // manual implies review → never auto-applied
    }
}
