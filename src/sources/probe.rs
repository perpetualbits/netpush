// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! A live-probe fact source: which addresses answer on the wire. This catches
//! squatters that appear in neither NetBox nor DNS. The probe host must sit on the
//! target L2 (so a `ping` triggers ARP), e.g. takkie for `10.87.0.0/20`.

use super::{FactSource, Vantage};
use crate::reconcile::{AddressFacts, Cidr};

/// Pings every host in a range from an on-subnet vantage.
#[derive(Debug, Clone)]
pub struct ProbeSource {
    /// A host on the same L2 as the target range.
    pub vantage: Vantage,
    /// Max concurrent pings — bounds the processes spawned on the probe host and the
    /// ARP burst on the target L2.
    pub concurrency: usize,
}

impl FactSource for ProbeSource {
    fn gather(&self, range: &Cidr) -> anyhow::Result<Vec<AddressFacts>> {
        // Only sweep blocks small enough to ping one address at a time. A bigger block
        // would be minutes of pings and — embedding every address in one remote command —
        // overflow the OS argument limit; it gets no live facts and relies on NetBox/DNS.
        if !range.is_enumerable() || range.host_count() > super::SWEEP_CAP {
            return Ok(Vec::new());
        }
        let ips = range.hosts().map(|a| a.to_string()).collect::<Vec<_>>().join(" ");
        let par = self.concurrency.max(1);
        // Ping with bounded fan-out (`xargs -P`). An unbounded `for … &` would spawn one
        // process per address at once — thousands for a /20 — and blast that many ARP
        // requests simultaneously; capping the parallelism keeps a big sweep from
        // storming the subnet while still finishing a /24 in ~a second. `$0` is the
        // address xargs handed the shell. Each responder prints its own address.
        let remote = format!(
            "printf '%s\\n' {ips} | xargs -P{par} -n1 sh -c 'ping -c1 -W1 \"$0\" >/dev/null 2>&1 && echo \"$0\"'"
        );
        let out = self.vantage.run(&remote)?;
        Ok(parse_live(&out))
    }
}

/// Parse a list of responding addresses (one IPv4 per line) into `live` facts.
#[must_use]
pub fn parse_live(output: &str) -> Vec<AddressFacts> {
    output
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .map(|addr| AddressFacts {
            addr,
            netbox: None,
            ptr: None,
            live: true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_responders() {
        let sample = "10.87.3.90\n10.87.3.68\n\nnot-an-ip\n";
        let facts = parse_live(sample);
        assert_eq!(facts.len(), 2);
        assert!(facts.iter().all(|f| f.live && f.ptr.is_none() && f.netbox.is_none()));
        assert_eq!(facts[0].addr, std::net::Ipv4Addr::new(10, 87, 3, 90));
    }

    #[test]
    fn skips_a_block_too_large_to_ping() {
        // A /8 must not be swept: gather returns empty without ever contacting the (bogus)
        // vantage — the guard that prevents the E2BIG crash.
        let p = ProbeSource { vantage: Vantage::with_jump("nowhere.invalid", ""), concurrency: 8 };
        let facts = p.gather(&Cidr::parse("10.0.0.0/8").unwrap()).unwrap();
        assert!(facts.is_empty());
    }
}
