// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! DNS as a fact source: the PTR records actually served. This is the most reliable
//! "is it allocated?" signal we found — it caught addresses NetBox never recorded.
//! We reverse-resolve every host on the vantage (its resolver knows the internal
//! zones), in parallel with bounded fan-out, and collect the answers.

use super::{FactSource, Vantage};
use crate::reconcile::{AddressFacts, Cidr};

/// Reverse-resolves every host in a range via the vantage's resolver.
#[derive(Debug, Clone)]
pub struct DnsSource {
    /// A host whose resolver can see the internal reverse zones.
    pub vantage: Vantage,
}

impl FactSource for DnsSource {
    fn gather(&self, range: &Cidr) -> anyhow::Result<Vec<AddressFacts>> {
        self.gather_with_progress(range, |_done| {})
    }
}

impl DnsSource {
    /// Reverse-resolve every host, calling `on_tick(done)` after each address is
    /// processed (so a caller can show a determinate progress bar), and return the PTR
    /// facts found.
    ///
    /// The sweep runs in parallel with bounded fan-out. A serial `for` loop did one
    /// blocking `host` per address — for a /20 that is ~4000 lookups back-to-back, each
    /// waiting out a timeout when there is no PTR, so it took minutes. `xargs -P` runs up
    /// to 128 at once (bounding load on the resolver) and `host -W1` caps each lookup at
    /// ~1 s, so the whole sweep finishes in tens of seconds. Each worker prints `T` when
    /// done (a progress tick, streamed back and counted) and `R <ip> <name>` when a PTR
    /// exists; both lines are short enough to be written atomically to the pipe. `$0`
    /// inside the `sh -c` body is the address xargs handed it.
    ///
    /// # Errors
    /// Propagates SSH failures.
    pub fn gather_with_progress(&self, range: &Cidr, mut on_tick: impl FnMut(u64)) -> anyhow::Result<Vec<AddressFacts>> {
        let ips = host_list(range);
        let remote = format!(
            "printf '%s\\n' {ips} | xargs -P128 -n1 sh -c 'h=$(host -W1 \"$0\" 2>/dev/null | sed -n \"s/.*pointer //p\"); printf \"T\\n\"; [ -n \"$h\" ] && printf \"R %s %s\\n\" \"$0\" \"$h\"'"
        );
        let mut done = 0u64;
        let mut results = String::new();
        self.vantage.run_streaming(&remote, |line| {
            if line == "T" {
                done += 1;
                on_tick(done);
            } else if let Some(rest) = line.strip_prefix("R ") {
                results.push_str(rest);
                results.push('\n');
            }
        })?;
        Ok(parse_ptrs(&results))
    }
}

/// The space-separated host list for the remote shell loop.
fn host_list(range: &Cidr) -> String {
    range.hosts().map(|a| a.to_string()).collect::<Vec<_>>().join(" ")
}

/// Parse `"<ip> <ptr>"` lines into `ptr`-only facts.
///
/// How: split each non-empty line into address and name; skip anything that does
/// not parse as an IPv4 address. Only the `ptr` field is set.
#[must_use]
pub fn parse_ptrs(output: &str) -> Vec<AddressFacts> {
    let mut out = Vec::new();
    for line in output.lines() {
        let mut it = line.split_whitespace();
        let (Some(ip), Some(name)) = (it.next(), it.next()) else {
            continue;
        };
        let Ok(addr) = ip.parse() else { continue };
        out.push(AddressFacts {
            addr,
            netbox: None,
            ptr: Some(name.to_string()),
            live: false,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reverse_sweep_output() {
        let sample = "\
10.87.3.68 dop21-ipmi.nfra.nl.
10.87.3.11 iprotect-keyreader.nfra.nl.
garbage line without ip
10.87.3.90";
        let facts = parse_ptrs(sample);
        assert_eq!(facts.len(), 2); // the garbage and the ip-only line are skipped
        assert_eq!(facts[0].addr, std::net::Ipv4Addr::new(10, 87, 3, 68));
        assert_eq!(facts[0].ptr.as_deref(), Some("dop21-ipmi.nfra.nl."));
        assert!(facts[0].netbox.is_none() && !facts[0].live);
    }

    #[test]
    fn host_list_covers_usable_hosts() {
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let list = host_list(&range);
        assert!(list.starts_with("10.87.3.1 "));
        assert!(list.ends_with(" 10.87.3.254"));
    }
}
