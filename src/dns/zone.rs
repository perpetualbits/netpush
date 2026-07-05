// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! A writable zone: its apex, the server that masters it, the file on that server,
//! and its serial scheme. The estate spreads these across servers (forward zones on
//! dns1, the `10.in-addr.arpa` reverse on ntserver1), so a zone carries *where* it
//! lives — the same data the node-graph view needs to draw "zone on server".
//!
//! [`Zone::add_record_script`] is the matured, **safe** edit: it never mutates the
//! live file until a `named-checkzone` on an edited *copy* passes, and it keeps a
//! backup. That is what makes the write path trustworthy enough to run for real.

use super::name::DnsName;
use super::record::Record;
use super::serial::SerialScheme;

/// A zone canopy can edit, and the box it lives on.
#[derive(Debug, Clone)]
pub struct Zone {
    /// The zone apex, e.g. `nfra.nl` or `10.in-addr.arpa`.
    pub origin: DnsName,
    /// SSH host that masters the zone (reused as a [`Vantage`](crate::sources::Vantage)).
    pub server: String,
    /// Absolute path of the zone file on `server`.
    pub file: String,
    /// How this zone's SOA serial advances.
    pub scheme: SerialScheme,
}

impl Zone {
    /// The forward `nfra.nl` zone as it lives on dns1 (inline-signed, `YYYYMMDDnn`).
    #[must_use]
    pub fn nfra_forward() -> Zone {
        Zone {
            origin: DnsName::parse("nfra.nl"),
            server: "dns1.astron.nl".to_string(),
            file: "/etc/bind/master/db.nfra.nl".to_string(),
            scheme: SerialScheme::DateCounter,
        }
    }

    /// A generic BIND reverse zone with an integer serial — a template kept for a
    /// BIND-mastered reverse zone we might edit in future.
    ///
    /// NOTE: the real `10.in-addr.arpa` master on this estate is **ntserver1, a
    /// Windows DNS server** owned by another team — no SSH/BIND, RDP-only, not
    /// automatable (see `docs/dns-estate.md`). canopy does NOT use this recipe for
    /// that reverse: the PTR is a manual hand-off (see `Plan::for_allocation`). The
    /// `file` here is a placeholder because this template is never applied as-is.
    #[must_use]
    pub fn reverse_10() -> Zone {
        Zone {
            origin: DnsName::parse("10.in-addr.arpa"),
            server: "ntserver1.nfra.nl".to_string(),
            file: "TBD:windows-manual".to_string(),
            scheme: SerialScheme::Counter,
        }
    }

    /// Whether this zone is fully known and safe to edit (file path confirmed).
    #[must_use]
    pub fn is_editable(&self) -> bool {
        !self.file.starts_with("TBD")
    }

    /// A self-contained shell script that safely adds `record` to the zone.
    ///
    /// How, step by step (all on `server`):
    /// 1. read the current serial via `named-checkzone` ("loaded serial N");
    /// 2. compute the next serial for this scheme from the server's own date;
    /// 3. copy the file, bump the serial and append the record **on the copy**;
    /// 4. `named-checkzone` the copy — only if it passes do we back up the original,
    ///    install the copy, and `rndc reload`; otherwise the live zone is untouched.
    ///
    /// The validate-a-copy-then-swap design is why this is safe to run for real: a
    /// malformed edit can never reach the served zone.
    #[must_use]
    pub fn add_record_script(&self, record: &Record) -> String {
        let bump = match self.scheme {
            // YYYYMMDDnn: today·100, or +1 if the file is already at/after that.
            SerialScheme::DateCounter => {
                "cand=$((today*100)); if [ \"$cur\" -ge \"$cand\" ]; then new=$((cur+1)); else new=$cand; fi"
            }
            SerialScheme::Counter => "new=$((cur+1))",
        };
        let record_line = record.zone_line(&self.origin);

        TEMPLATE
            .replace("@FILE@", &self.file)
            .replace("@ORIGIN@", &self.origin.to_string())
            .replace("@BUMP@", bump)
            .replace("@RECORD@", &record_line)
    }
}

/// The safe-edit template. Placeholders (`@FILE@`, `@ORIGIN@`, `@BUMP@`, `@RECORD@`)
/// are substituted by [`Zone::add_record_script`]; kept as a template so the shell
/// quoting stays readable instead of drowning in `format!` brace-escaping.
const TEMPLATE: &str = r#"set -e
f='@FILE@'; origin='@ORIGIN@'
cur=$(sudo -n named-checkzone "$origin" "$f" 2>/dev/null | sed -n 's/.*loaded serial \([0-9]*\).*/\1/p')
[ -n "$cur" ] || { echo "could not read current serial for $origin" >&2; exit 1; }
today=$(date +%Y%m%d)
@BUMP@
tmp=$(mktemp)
sudo -n cp -a "$f" "$tmp"
sudo -n sed -i "s/\b$cur\b/$new/" "$tmp"
printf '%s\n' '@RECORD@' | sudo -n tee -a "$tmp" >/dev/null
if sudo -n named-checkzone "$origin" "$tmp" >/dev/null 2>&1; then
  sudo -n cp -a "$f" "$f.canopy-bak"
  sudo -n install -m 644 -o root -g bind "$tmp" "$f"
  sudo -n rndc reload "$origin"
  echo "APPLIED $origin: serial $cur -> $new; added @RECORD@"
else
  echo "named-checkzone FAILED on the edited copy; $origin left unchanged" >&2
  rm -f "$tmp"; exit 1
fi
rm -f "$tmp""#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_zone_facts() {
        let z = Zone::nfra_forward();
        assert_eq!(z.origin.to_string(), "nfra.nl");
        assert_eq!(z.server, "dns1.astron.nl");
        assert!(z.is_editable());
        assert!(!Zone::reverse_10().is_editable()); // file path still TBD
    }

    #[test]
    fn add_record_script_is_safe_and_correct() {
        let z = Zone::nfra_forward();
        let rec = Record::a(DnsName::parse("dop370-ipmi.nfra.nl"), "10.87.3.69".parse().unwrap());
        let s = z.add_record_script(&rec);

        // Validates a copy before touching the live file, and keeps a backup.
        assert!(s.contains("named-checkzone \"$origin\" \"$tmp\""));
        assert!(s.contains("$f.canopy-bak"));
        assert!(s.contains("rndc reload"));
        // Correct scheme snippet and the zone-relative record.
        assert!(s.contains("cand=$((today*100))"));
        assert!(s.contains("dop370-ipmi\tIN\tA\t10.87.3.69"));
        // The live file is only written after the checkzone passes (install after cp bak).
        let apply_idx = s.find("install -m 644").unwrap();
        let check_idx = s.find("if sudo -n named-checkzone").unwrap();
        assert!(check_idx < apply_idx);
    }

    #[test]
    fn counter_zone_uses_increment_bump() {
        let z = Zone::reverse_10();
        let rec = Record::ptr(
            super::super::name::reverse_ptr("10.87.3.69".parse().unwrap()),
            &DnsName::parse("dop370-ipmi.nfra.nl"),
        );
        let s = z.add_record_script(&rec);
        assert!(s.contains("new=$((cur+1))"));
        assert!(!s.contains("cand=$((today*100))"));
    }
}
