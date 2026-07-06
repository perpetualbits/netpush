// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Logical **groupings** of hosts — clusters, name-families, services, pairs and singletons —
//! reconciled from several signals and shaped, above all, to **migrate into NetBox**.
//!
//! The stance (a deliberate design constraint): grouping truth *belongs in NetBox*. canopy
//! is the tool that puts it there — so this module is a **staging area**, never the permanent
//! home. Every [`Group`] therefore records where its identity came from ([`Origin`]) and the
//! shape it will take as a NetBox mutation ([`NetboxTarget`] — a `cluster:<slug>` tag today,
//! a native `Cluster` object once NetBox grows the mechanism). Nothing here assumes canopy
//! owns the data; the human-asserted [`groups.toml`](GroupsFile) file is explicitly transient,
//! a scratchpad for assertions on their way *into* NetBox.
//!
//! **Pure — no I/O.** The serde types deserialize from `groups.toml`; the inference runs over
//! the reconciled facts a caller already gathered. When two signals claim the same address the
//! priority is **asserted (groups.toml) > native (NetBox cluster) > inferred (naming/role)** —
//! a human override beats NetBox's own record, which beats a guess from the naming scheme.
//!
//! The output ([`Grouping`]) also assigns each group a **stable hue** so the map view can paint
//! identity as colour (cluster = shared palette family) independently of occupancy — see
//! [`Grouping::look`].

use std::collections::HashMap;
use std::net::IpAddr;

use serde::Deserialize;

use crate::reconcile::AddressFacts;

/// A stable, human-readable group identifier — a kebab-case slug like `netapp-dw` or
/// `aether`. It is stable because it seeds both the NetBox tag (`cluster:<id>`) and the
/// map's [hue](group_hue): the same group keeps the same colour across runs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
pub struct GroupId(pub String);

impl GroupId {
    /// Build a slug from an arbitrary string: lower-case, runs of non-alphanumerics collapsed
    /// to a single `-`, trimmed. Deterministic so the same name always yields the same slug.
    #[must_use]
    pub fn slug(s: &str) -> GroupId {
        let mut out = String::with_capacity(s.len());
        let mut prev_dash = true; // leading: suppress a leading dash
        for ch in s.chars() {
            if ch.is_ascii_alphanumeric() {
                out.push(ch.to_ascii_lowercase());
                prev_dash = false;
            } else if !prev_dash {
                out.push('-');
                prev_dash = true;
            }
        }
        while out.ends_with('-') {
            out.pop();
        }
        GroupId(out)
    }
}

/// The **shape** of a group — what kind of thing it is. This drives the visual treatment on
/// the map (a cluster reads differently from a lone server) and the NetBox namespace the group
/// projects into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupKind {
    /// Several hosts that form one coordinated system (a hypervisor cluster, a storage array):
    /// same name-family, three or more members. The headline case — gets a full palette family.
    Cluster,
    /// Exactly two related hosts (an HA pair, primary/secondary).
    Pair,
    /// A named service spread over hosts that share a prefix but not a numbering scheme
    /// (`iprotect-keyreader`, `iprotect-terminal`) — a function, not a cluster.
    Service,
    /// A single host with no siblings — its own tiny group, rendered quietly.
    Singleton,
}

impl GroupKind {
    /// The NetBox tag namespace for this kind, so the written tag reads as, e.g.,
    /// `cluster:aether` or `service:iprotect`. Kept distinct from the raw slug so a future
    /// reader can filter canopy-authored tags by namespace.
    #[must_use]
    pub fn netbox_namespace(self) -> &'static str {
        match self {
            GroupKind::Cluster => "cluster",
            GroupKind::Pair => "pair",
            GroupKind::Service => "service",
            GroupKind::Singleton => "host",
        }
    }

    /// Classify by membership count and naming regularity: a regular numbered family of ≥3 is a
    /// cluster, exactly 2 a pair, a shared-prefix/irregular-suffix set a service, and a lone
    /// host a singleton. `regular` is whether the members share a numbered naming scheme
    /// (`ntserver19/20/…`) rather than only a prefix (`iprotect-*`).
    #[must_use]
    pub fn classify(members: usize, regular: bool) -> GroupKind {
        match members {
            0 | 1 => GroupKind::Singleton,
            2 if regular => GroupKind::Pair,
            _ if regular => GroupKind::Cluster,
            _ => GroupKind::Service,
        }
    }
}

/// Where a group's identity came from — its provenance, which sets both the fusion priority and
/// whether it already lives in NetBox (so canopy knows what still needs pushing).
#[derive(Clone, Debug, PartialEq)]
pub enum Origin {
    /// A human said so in `groups.toml`. Highest priority; a candidate to push to NetBox.
    Asserted,
    /// Read from a native NetBox cluster (its object id). Already in NetBox — nothing to push.
    Netbox { cluster_id: u32 },
    /// Guessed from the naming scheme / role / subdomain. Lowest priority; the weakest evidence
    /// and the strongest candidate for a human to confirm and push.
    Inferred { rule: InferRule, confidence: f32 },
}

impl Origin {
    /// Fusion rank — higher wins when two origins claim the same address.
    fn rank(&self) -> u8 {
        match self {
            Origin::Asserted => 3,
            Origin::Netbox { .. } => 2,
            Origin::Inferred { .. } => 1,
        }
    }

    /// Whether this identity is already recorded in NetBox (so it needs no write-back).
    #[must_use]
    pub fn in_netbox(&self) -> bool {
        matches!(self, Origin::Netbox { .. })
    }
}

/// Which heuristic inferred a group — recorded so the UI can explain *why* a host was grouped
/// and so a weak rule can be surfaced for confirmation before it is written to NetBox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InferRule {
    /// Members share a numbered name-family (`ntserver19`, `ntserver20`, …).
    NameFamily,
    /// Members share a service prefix but not a numbering scheme (`iprotect-*`).
    ServicePrefix,
}

/// One member of a group, identified by address and/or hostname. **Both are optional but at
/// least one is set:** a hostname survives re-addressing and is how a NetBox *device* tag is
/// keyed, while the address is the only handle for an unnamed host and the key for a NetBox
/// *IP-address* tag. Carrying both is exactly what lets a group round-trip into NetBox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The address, if known.
    pub addr: Option<IpAddr>,
    /// The best hostname we have (NetBox `dns_name` else PTR, normalized), if any.
    pub host: Option<String>,
}

/// How a group projects into NetBox — the write target canopy would create to persist it. Tags
/// are the near-term sink (the live instance's tag namespace is empty, so `cluster:<slug>`
/// collides with nothing); the `Cluster` variant is the same identity's long-term home once a
/// native mechanism exists, so callers can migrate the *sink* without reshaping the *model*.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetboxTarget {
    /// Apply this tag to each member's NetBox IP object.
    Tag(NetboxTag),
    /// Assign each member to this native NetBox cluster id (future mechanism).
    Cluster(u32),
}

/// A NetBox tag as canopy would create and assign it. The `name` is the human-readable,
/// namespaced form (`cluster:aether`); the `slug` is the URL-safe identity NetBox actually keys
/// on (`cluster-aether`) — NetBox's `SlugField` is `[-a-zA-Z0-9_]+`, so the namespace joins the
/// group slug with a **hyphen**, never a colon. Assignment and the already-present check go by
/// **slug**; the name is for people and for filtering (`name__isw=cluster:`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetboxTag {
    /// Human-readable, colon-namespaced (`cluster:aether`).
    pub name: String,
    /// URL-safe identity NetBox keys on (`cluster-aether`).
    pub slug: String,
}

/// A reconciled logical group: a stable id, a display label, its kind, its provenance, and its
/// members. The whole point of the [`Origin`]/[`NetboxTarget`] pair is that this struct is
/// already the *plan* for a NetBox mutation, not just a view model.
#[derive(Clone, Debug, PartialEq)]
pub struct Group {
    /// Stable slug — seeds the NetBox tag and the map hue.
    pub id: GroupId,
    /// Human label (the family name as first seen, e.g. `netapp-dw`).
    pub label: String,
    /// What shape of group this is.
    pub kind: GroupKind,
    /// Where the identity came from.
    pub origin: Origin,
    /// The members.
    pub members: Vec<Member>,
}

impl Group {
    /// The tag this group projects into NetBox, namespaced by kind: name `cluster:aether`, slug
    /// `cluster-aether`. Computed unconditionally (used by both the target and the write plan).
    fn make_tag(&self) -> NetboxTag {
        let ns = self.kind.netbox_namespace();
        NetboxTag { name: format!("{ns}:{}", self.id.0), slug: format!("{ns}-{}", self.id.0) }
    }

    /// The NetBox write target that would persist this group: a namespaced [tag](NetboxTag) for
    /// an asserted/inferred group, or the native cluster object it already belongs to.
    #[must_use]
    pub fn netbox_target(&self) -> NetboxTarget {
        match self.origin {
            Origin::Netbox { cluster_id } => NetboxTarget::Cluster(cluster_id),
            _ => NetboxTarget::Tag(self.make_tag()),
        }
    }

    /// Whether this group still needs writing to NetBox (asserted/inferred, not already native).
    #[must_use]
    pub fn needs_push(&self) -> bool {
        !self.origin.in_netbox()
    }

    /// The [tag](NetboxTag) this group would be pushed as, or `None` for a native group whose
    /// target is a cluster object rather than a tag.
    #[must_use]
    pub fn netbox_tag(&self) -> Option<NetboxTag> {
        (!self.origin.in_netbox()).then(|| self.make_tag())
    }

    /// The tag this group would need **created** in NetBox before it could be assigned:
    /// `Some(tag)` when the group's slug is not among the `existing` tag slugs, else `None` (the
    /// tag already exists, or the group is native). Read-model only — creates nothing.
    #[must_use]
    pub fn tag_needs_creating(&self, existing: &std::collections::HashSet<String>) -> Option<NetboxTag> {
        let tag = self.netbox_tag()?;
        (!existing.contains(&tag.slug)).then_some(tag)
    }

    /// The best hostname we hold for `addr` among this group's members, for display.
    #[must_use]
    pub fn host_of(&self, addr: IpAddr) -> Option<&str> {
        self.members.iter().find(|m| m.addr == Some(addr)).and_then(|m| m.host.as_deref())
    }

    /// The tag writes that would record this group in NetBox: the group's tag applied to each
    /// member IP, each marked `already_present` where the member's current tags (keyed by
    /// address in `current`) already carry it. **Pure — computes intent only; nothing is sent.**
    ///
    /// One entry per (address, tag) so a preview lists exactly what would change and an apply can
    /// be gated item-by-item, never in bulk. A native-origin group targets a cluster, not a tag,
    /// so it yields no writes (it is already in NetBox). Members with no address are skipped — a
    /// NetBox IP-tag write is keyed on the address.
    #[must_use]
    pub fn plan_tag_writes(&self, current: &HashMap<IpAddr, Vec<String>>) -> Vec<TagWrite> {
        let Some(tag) = self.netbox_tag() else {
            return Vec::new();
        };
        self.members
            .iter()
            .filter_map(|m| m.addr)
            .map(|addr| {
                // Compare by SLUG — that is what NetBox stores and returns on an IP object.
                let already_present = current.get(&addr).is_some_and(|ts| ts.iter().any(|t| t == &tag.slug));
                TagWrite { addr, slug: tag.slug.clone(), name: tag.name.clone(), already_present }
            })
            .collect()
    }
}

/// One intended NetBox tag write: apply the tag (`name`/`slug`) to the IP object for `addr`,
/// unless it is `already_present`. Deliberately the smallest unit — a single address and a
/// single tag — so a preview enumerates every change and applying can be confirmed per item and
/// never at scale.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagWrite {
    /// The member address whose NetBox IP object would be tagged.
    pub addr: IpAddr,
    /// The tag slug that identifies the change (`cluster-aether`).
    pub slug: String,
    /// The tag's human-readable name (`cluster:aether`), for the preview.
    pub name: String,
    /// `true` when the object already carries the tag — a no-op, shown but never written.
    pub already_present: bool,
}

// ─── groups.toml (the staging file) ───────────────────────────────────────────────────────

/// The on-disk staging file: human assertions of "these hosts/IPs are this group", held only
/// until they can be pushed into NetBox. Deliberately minimal — a name, a kind, and members by
/// hostname and/or IP — mirroring exactly what a NetBox tag write needs, so loading and pushing
/// are the same shape. Parsed elsewhere (this module stays I/O-free); see [`GroupsFile::into_groups`].
#[derive(Clone, Debug, Default, Deserialize)]
pub struct GroupsFile {
    /// Each asserted group.
    #[serde(default)]
    pub group: Vec<AssertedGroup>,
}

/// One `[[group]]` entry in `groups.toml`.
#[derive(Clone, Debug, Deserialize)]
pub struct AssertedGroup {
    /// Display name; the slug is derived from it.
    pub name: String,
    /// Kind, defaulting to a cluster if omitted.
    #[serde(default)]
    pub kind: Option<TomlKind>,
    /// Member hostnames.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Member IP addresses.
    #[serde(default)]
    pub addrs: Vec<IpAddr>,
}

/// The `kind` field as written in TOML (lower-case), kept separate from [`GroupKind`] so the
/// wire format is stable even if the internal enum grows variants.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TomlKind {
    /// → [`GroupKind::Cluster`].
    Cluster,
    /// → [`GroupKind::Pair`].
    Pair,
    /// → [`GroupKind::Service`].
    Service,
    /// → [`GroupKind::Singleton`].
    Singleton,
}

impl From<TomlKind> for GroupKind {
    fn from(k: TomlKind) -> Self {
        match k {
            TomlKind::Cluster => GroupKind::Cluster,
            TomlKind::Pair => GroupKind::Pair,
            TomlKind::Service => GroupKind::Service,
            TomlKind::Singleton => GroupKind::Singleton,
        }
    }
}

impl GroupsFile {
    /// Turn the parsed assertions into [`Group`]s with [`Origin::Asserted`].
    #[must_use]
    pub fn into_groups(self) -> Vec<Group> {
        self.group
            .into_iter()
            .map(|g| {
                let members = g
                    .hosts
                    .iter()
                    .map(|h| Member { addr: None, host: Some(normalize(h)) })
                    .chain(g.addrs.iter().map(|a| Member { addr: Some(*a), host: None }))
                    .collect();
                Group {
                    id: GroupId::slug(&g.name),
                    label: g.name,
                    kind: g.kind.map_or(GroupKind::Cluster, GroupKind::from),
                    origin: Origin::Asserted,
                    members,
                }
            })
            .collect()
    }
}

// ─── name-family inference ─────────────────────────────────────────────────────────────────

/// Normalize a hostname for grouping: strip a trailing dot, lower-case, and keep only the
/// first label (drop the domain) — grouping is by host identity, not zone.
fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase().split('.').next().unwrap_or("").to_string()
}

/// Interface/role suffixes that name a *management interface* of a host, not a distinct host —
/// stripped before family extraction so `dop21-ipmi` and `dop21` land in the same family.
const IFACE_SUFFIXES: &[&str] = &["-ipmi", "-bmc", "-mgmt", "-drac", "-ilo", "-con", "-console"];

/// The name-family of a host label: strip a management-interface suffix, then split the leading
/// **alphabetic** prefix from a trailing number (`ntserver19` → `ntserver`, `netapp-dw2` →
/// `netapp-dw`). Returns `(family, had_number)`; `had_number` distinguishes a numbered family
/// (a cluster/pair candidate) from a bare prefix (a service candidate). `None` for an empty
/// label.
///
/// The rule is intentionally simple and explicit (per the roadmap's "make the heuristics
/// explicit") — the real ASTRON estate names hosts very regularly (`cs###`, `dop###`,
/// `lcs###`, `ntserver##`), so a prefix/number split recovers most families without guessing.
fn name_family(host: &str) -> Option<(String, bool)> {
    let h = normalize(host);
    if h.is_empty() {
        return None;
    }
    let stem = IFACE_SUFFIXES.iter().find_map(|s| h.strip_suffix(s)).unwrap_or(&h);
    // Trim a trailing run of digits (and any '-'/'_' joining them to the prefix).
    let trimmed = stem.trim_end_matches(|c: char| c.is_ascii_digit());
    let had_number = trimmed.len() != stem.len();
    if had_number {
        // A numbered family keeps its full prefix: `netapp-dw2` → `netapp-dw`, `ntserver19` →
        // `ntserver`. The number is the member index, so members with the same prefix are siblings.
        let family = trimmed.trim_end_matches(['-', '_']);
        let family = if family.is_empty() { stem } else { family };
        Some((family.to_string(), true))
    } else {
        // No number: a service named by function (`iprotect-keyreader`, `iprotect-terminal`).
        // Collapse to the first token so the shared prefix groups them; a single-token name
        // (`jivecam`) is its own family.
        let head = stem.split(['-', '_']).next().unwrap_or(stem);
        Some((head.to_string(), false))
    }
}

/// Infer groups from the reconciled facts by name-family. Hosts with no name contribute no
/// inferred group (they can still be grouped by an explicit assertion). Each resulting group is
/// [`Origin::Inferred`]; the [kind](GroupKind::classify) and [rule](InferRule) follow from the
/// family's size and whether it is numbered.
///
/// Deterministic: families are emitted in sorted slug order, members in address order, so the
/// output (and thus the map colours) are stable across runs.
#[must_use]
pub fn infer(facts: &HashMap<IpAddr, AddressFacts>) -> Vec<Group> {
    // family label -> (had_number seen, members)
    let mut fams: HashMap<String, (bool, Vec<Member>)> = HashMap::new();
    for (addr, f) in facts {
        let Some(host) = best_host(f) else { continue };
        let Some((family, numbered)) = name_family(&host) else { continue };
        let entry = fams.entry(family).or_insert((false, Vec::new()));
        entry.0 |= numbered;
        entry.1.push(Member { addr: Some(*addr), host: Some(host) });
    }
    let mut groups: Vec<Group> = fams
        .into_iter()
        .map(|(label, (numbered, mut members))| {
            members.sort_by_key(|m| m.addr);
            let confidence = confidence_of(members.len(), numbered);
            let rule = if numbered { InferRule::NameFamily } else { InferRule::ServicePrefix };
            Group {
                id: GroupId::slug(&label),
                kind: GroupKind::classify(members.len(), numbered),
                origin: Origin::Inferred { rule, confidence },
                label,
                members,
            }
        })
        .collect();
    groups.sort_by(|a, b| a.id.cmp(&b.id));
    groups
}

/// A rough confidence for an inferred family: a larger, numbered family is stronger evidence
/// than a lone prefix match. Bounded to `[0.3, 0.95]` — inference is never certain.
fn confidence_of(members: usize, numbered: bool) -> f32 {
    let base = if numbered { 0.6 } else { 0.4 };
    let size_bonus = (members.saturating_sub(1) as f32 * 0.12).min(0.35);
    (base + size_bonus).clamp(0.3, 0.95)
}

/// The best hostname for a fact: NetBox `dns_name` if present, else the PTR — normalized to the
/// first label. `None` if neither is set.
fn best_host(f: &AddressFacts) -> Option<String> {
    let nb = f.netbox.as_ref().and_then(|r| r.dns_name.as_deref());
    nb.or(f.ptr.as_deref()).map(normalize).filter(|s| !s.is_empty())
}

// ─── native NetBox clusters ────────────────────────────────────────────────────────────────

/// A native NetBox cluster, reduced to what grouping needs: its object id, display name, and the
/// members (IP + hostname) resolved from the cluster's VMs. The live fetch (`sources::netbox`)
/// builds these by joining clusters → VMs → VM-interface IPs; this module stays I/O-free and
/// only turns them into groups.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeCluster {
    /// The NetBox cluster object id (the durable handle, and what [`Origin::Netbox`] records).
    pub id: u32,
    /// The cluster's display name (e.g. `aether`).
    pub name: String,
    /// Its members, resolved from the cluster's VM IP addresses.
    pub members: Vec<Member>,
}

/// Turn fetched native clusters into [`Origin::Netbox`] groups — the authoritative middle tier
/// of the fusion (above inference, below a human assertion). A cluster with no resolved members
/// is dropped (nothing to place). Members are sorted by address and the groups by slug, so the
/// result is deterministic.
///
/// These are the real thing NetBox already records, so they need no write-back — [`needs_push`]
/// is false for every group produced here.
#[must_use]
pub fn from_native(clusters: Vec<NativeCluster>) -> Vec<Group> {
    let mut groups: Vec<Group> = clusters
        .into_iter()
        .filter(|c| !c.members.is_empty())
        .map(|c| {
            let mut members = c.members;
            members.sort_by_key(|m| m.addr);
            Group {
                id: GroupId::slug(&c.name),
                label: c.name,
                kind: GroupKind::Cluster,
                origin: Origin::Netbox { cluster_id: c.id },
                members,
            }
        })
        .collect();
    groups.sort_by(|a, b| a.id.cmp(&b.id));
    groups
}

// ─── fusion ────────────────────────────────────────────────────────────────────────────────

/// Fuse asserted, native and inferred groups into one [`Grouping`], resolving overlaps by
/// [`Origin`] priority: an address claimed by a higher-priority group is not re-claimed by a
/// lower one. Groups are kept whole (a group whose every member was out-ranked drops out).
///
/// `native` is NetBox's own clusters (empty until we fetch them); `inferred` comes from
/// [`infer`]; `asserted` from [`GroupsFile::into_groups`]. Order of the inputs does not matter —
/// priority is by origin, not argument position.
#[must_use]
pub fn merge(asserted: Vec<Group>, native: Vec<Group>, inferred: Vec<Group>) -> Grouping {
    // Highest priority first so the index records the winner and later tiers skip claimed IPs.
    let mut all = asserted;
    all.extend(native);
    all.extend(inferred);
    all.sort_by(|a, b| b.origin.rank().cmp(&a.origin.rank()));

    let mut index: HashMap<IpAddr, GroupId> = HashMap::new();
    let mut kept: Vec<Group> = Vec::new();
    for mut g in all {
        g.members.retain(|m| match m.addr {
            Some(a) => !index.contains_key(&a), // an address only belongs to its top-priority group
            None => true,                       // host-only members can't be de-duped by IP; keep
        });
        if g.members.is_empty() {
            continue;
        }
        for m in &g.members {
            if let Some(a) = m.addr {
                index.entry(a).or_insert_with(|| g.id.clone());
            }
        }
        kept.push(g);
    }
    kept.sort_by(|a, b| a.id.cmp(&b.id));
    Grouping { groups: kept, index }
}

/// The reconciled set of all groups plus an address→group index, with a stable hue and visual
/// treatment per group for the map view.
#[derive(Clone, Debug, Default)]
pub struct Grouping {
    /// Every kept group, in stable slug order.
    pub groups: Vec<Group>,
    /// Which group (if any) owns an address — the fused, priority-resolved answer.
    pub index: HashMap<IpAddr, GroupId>,
}

impl Grouping {
    /// The group that owns `addr`, if any.
    #[must_use]
    pub fn group_of(&self, addr: IpAddr) -> Option<&Group> {
        let id = self.index.get(&addr)?;
        self.groups.iter().find(|g| &g.id == id)
    }

    /// The visual treatment for a group: a stable hue (degrees) plus a saturation and whether it
    /// should animate — so the map can render *identity* as colour. A cluster gets a full,
    /// saturated hue (the "shared palette family"); a service a distinct hue at slightly lower
    /// saturation; a pair a muted hue; a singleton a near-grey so lone hosts stay quiet.
    #[must_use]
    pub fn look(&self, id: &GroupId) -> Look {
        let hue = group_hue(id);
        // The `band` is the group's index among the (sorted) groups — mullion's [`FlowStyle`]
        // spaces bands by the golden angle, so sequential bands give maximally distinct hues for
        // the animated flow gradient. Falls back to a slug hash if the id is not in this grouping.
        let band = self.groups.iter().position(|g| &g.id == id).unwrap_or_else(|| group_hue(id) as usize);
        let (sat, animate) = match self.groups.iter().find(|g| &g.id == id).map(|g| g.kind) {
            Some(GroupKind::Cluster) => (0.85, true),
            Some(GroupKind::Service) => (0.70, true),
            Some(GroupKind::Pair) => (0.55, false),
            Some(GroupKind::Singleton) | None => (0.20, false),
        };
        Look { band, hue, sat, animate }
    }

    /// Every group that still needs writing to NetBox (not already native) — the push work-list.
    #[must_use]
    pub fn pending_pushes(&self) -> Vec<&Group> {
        self.groups.iter().filter(|g| g.needs_push()).collect()
    }
}

/// A group's map treatment. The animated flow uses [`band`](Look::band) (a mullion
/// [`FlowStyle`](mullion::FlowStyle) hue family); the quiet static tint uses [`hue`](Look::hue).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Look {
    /// Golden-angle hue **band** for the animated flow gradient — maximally distinct per group.
    pub band: usize,
    /// Static hue in degrees `[0,360)` (used for non-animated groups' background tint).
    pub hue: f32,
    /// Saturation `[0,1]`.
    pub sat: f32,
    /// Whether the group's cells animate (a cluster/service flows; a pair/singleton stays quiet).
    pub animate: bool,
}

/// A stable hue in `[0,360)` for a group id, from an FNV-1a hash of its slug. Deterministic and
/// spread across the wheel, so distinct groups get distinct, repeatable colours without a
/// palette table to maintain.
#[must_use]
pub fn group_hue(id: &GroupId) -> f32 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in id.0.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    // FNV already avalanches well; take a fine modulus and scale to the hue wheel for a
    // uniform, repeatable spread across `[0,360)`.
    (h % 360_000) as f32 / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(o: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 87, 3, o))
    }

    fn ptr(o: u8, name: &str) -> (IpAddr, AddressFacts) {
        (v4(o), AddressFacts { addr: v4(o), netbox: None, ptr: Some(format!("{name}.")), live: true })
    }

    /// The name-family rule strips management suffixes and splits prefix from number.
    #[test]
    fn name_family_strips_iface_and_number() {
        assert_eq!(name_family("ntserver19-ipmi.nfra.nl"), Some(("ntserver".into(), true)));
        assert_eq!(name_family("netapp-dw2-bmc"), Some(("netapp-dw".into(), true)));
        assert_eq!(name_family("dop75-ipmi"), Some(("dop".into(), true)));
        assert_eq!(name_family("iprotect-keyreader"), Some(("iprotect".into(), false)));
        assert_eq!(name_family("iprotect-terminal-dw"), Some(("iprotect".into(), false)));
        assert_eq!(name_family("jivecam"), Some(("jivecam".into(), false)));
        assert_eq!(name_family(""), None);
    }

    /// Inference over the real fixture families: netapp-dw is a cluster, ntserver a cluster,
    /// dop a pair, the iprotect hosts split into their own (prefix-only) singleton services,
    /// and jivecam/instrum4 are singletons.
    #[test]
    fn infers_fixture_families() {
        let facts: HashMap<IpAddr, AddressFacts> = [
            ptr(52, "netapp-dw1-bmc.nfra.nl"),
            ptr(54, "netapp-dw2-bmc.nfra.nl"),
            ptr(62, "netapp-dw3-bmc.nfra.nl"),
            ptr(63, "netapp-dw4-bmc.nfra.nl"),
            ptr(68, "dop21-ipmi.nfra.nl"),
            ptr(76, "dop75-ipmi.nfra.nl"),
            ptr(71, "ntserver56-ipmi.nfra.nl"),
            ptr(73, "ntserver20-ipmi.nfra.nl"),
            ptr(77, "ntserver19-ipmi.nfra.nl"),
            ptr(14, "jivecam.nfra.nl"),
        ]
        .into_iter()
        .collect();

        let groups = infer(&facts);
        let by = |slug: &str| groups.iter().find(|g| g.id.0 == slug).cloned();

        let netapp = by("netapp-dw").expect("netapp-dw family");
        assert_eq!(netapp.kind, GroupKind::Cluster);
        assert_eq!(netapp.members.len(), 4);

        assert_eq!(by("dop").unwrap().kind, GroupKind::Pair);
        assert_eq!(by("ntserver").unwrap().kind, GroupKind::Cluster);
        assert_eq!(by("jivecam").unwrap().kind, GroupKind::Singleton);
    }

    /// A group's NetBox target is a namespaced tag; a native-origin group keeps its cluster id.
    #[test]
    fn netbox_target_is_a_namespaced_tag() {
        let g = Group {
            id: GroupId::slug("Aether"),
            label: "Aether".into(),
            kind: GroupKind::Cluster,
            origin: Origin::Inferred { rule: InferRule::NameFamily, confidence: 0.8 },
            members: vec![Member { addr: Some(v4(1)), host: None }],
        };
        let tag = g.netbox_tag().unwrap();
        assert_eq!(tag.name, "cluster:aether"); // colon in the human name
        assert_eq!(tag.slug, "cluster-aether"); // hyphen in the NetBox slug (no ':')
        assert_eq!(g.netbox_target(), NetboxTarget::Tag(tag));
        assert!(g.needs_push());

        let native = Group { origin: Origin::Netbox { cluster_id: 7 }, ..g };
        assert_eq!(native.netbox_target(), NetboxTarget::Cluster(7));
        assert!(native.netbox_tag().is_none());
        assert!(!native.needs_push());
    }

    /// A native cluster becomes an `Origin::Netbox` group that needs no push, and out-ranks an
    /// inferred family for a shared address.
    #[test]
    fn native_cluster_becomes_netbox_group_and_wins() {
        let native = from_native(vec![NativeCluster {
            id: 42,
            name: "aether".into(),
            members: vec![Member { addr: Some(v4(20)), host: Some("vm-a".into()) }],
        }]);
        assert_eq!(native.len(), 1);
        assert_eq!(native[0].origin, Origin::Netbox { cluster_id: 42 });
        assert!(!native[0].needs_push()); // already in NetBox

        // .20 is also seen by inference as some family; native must win.
        let inferred = infer(&[ptr(20, "aether-node1.astron.nl"), ptr(21, "aether-node2.astron.nl")].into_iter().collect());
        let g = merge(Vec::new(), native, inferred);
        assert_eq!(g.group_of(v4(20)).unwrap().origin, Origin::Netbox { cluster_id: 42 });
    }

    /// Fusion: an asserted group out-ranks an inferred one for a shared address.
    #[test]
    fn assertion_beats_inference_on_overlap() {
        let asserted = vec![Group {
            id: GroupId::slug("special"),
            label: "special".into(),
            kind: GroupKind::Cluster,
            origin: Origin::Asserted,
            members: vec![Member { addr: Some(v4(52)), host: None }],
        }];
        let inferred = infer(&[ptr(52, "netapp-dw1-bmc.nfra.nl"), ptr(54, "netapp-dw2-bmc.nfra.nl")].into_iter().collect());

        let g = merge(asserted, Vec::new(), inferred);
        // .52 is claimed by the assertion, not netapp-dw.
        assert_eq!(g.group_of(v4(52)).unwrap().id.0, "special");
        // .54 was not asserted, so it stays with the inferred family.
        assert_eq!(g.group_of(v4(54)).unwrap().id.0, "netapp-dw");
    }

    /// The tag-write plan marks an already-tagged member as a no-op and a native group as nothing
    /// to write.
    #[test]
    fn plan_tag_writes_is_idempotent_and_native_free() {
        let g = Group {
            id: GroupId::slug("aether"),
            label: "aether".into(),
            kind: GroupKind::Cluster,
            origin: Origin::Inferred { rule: InferRule::NameFamily, confidence: 0.9 },
            members: vec![
                Member { addr: Some(v4(20)), host: None },
                Member { addr: Some(v4(21)), host: None },
                Member { addr: None, host: Some("noaddr".into()) }, // skipped: no address
            ],
        };
        let mut current = std::collections::HashMap::new();
        current.insert(v4(20), vec!["cluster-aether".to_string()]); // already tagged (by SLUG)
        let writes = g.plan_tag_writes(&current);
        assert_eq!(writes.len(), 2); // the host-only member is skipped
        assert!(writes.iter().find(|w| w.addr == v4(20)).unwrap().already_present);
        assert!(!writes.iter().find(|w| w.addr == v4(21)).unwrap().already_present);

        // A native cluster is already in NetBox → no tag writes at all.
        let native = Group { origin: Origin::Netbox { cluster_id: 1 }, ..g };
        assert!(native.plan_tag_writes(&current).is_empty());
    }

    /// A group's tag needs creating only when its slug is absent from NetBox's existing tags; a
    /// native group never needs one.
    #[test]
    fn tag_needs_creating_checks_slug_presence() {
        let g = Group {
            id: GroupId::slug("aether"),
            label: "aether".into(),
            kind: GroupKind::Cluster,
            origin: Origin::Inferred { rule: InferRule::NameFamily, confidence: 0.9 },
            members: vec![Member { addr: Some(v4(20)), host: None }],
        };
        let mut existing = std::collections::HashSet::new();
        assert_eq!(g.tag_needs_creating(&existing).unwrap().slug, "cluster-aether"); // absent → create
        existing.insert("cluster-aether".to_string());
        assert!(g.tag_needs_creating(&existing).is_none()); // now present → no create

        let native = Group { origin: Origin::Netbox { cluster_id: 1 }, ..g };
        assert!(native.tag_needs_creating(&std::collections::HashSet::new()).is_none());
    }

    /// Hue is stable and differs between distinct slugs.
    #[test]
    fn hue_is_stable_and_distinct() {
        assert_eq!(group_hue(&GroupId::slug("aether")), group_hue(&GroupId::slug("aether")));
        assert_ne!(group_hue(&GroupId::slug("aether")), group_hue(&GroupId::slug("deimos")));
        for id in ["a", "b", "cluster-x", "netapp-dw"] {
            let h = group_hue(&GroupId(id.into()));
            assert!((0.0..360.0).contains(&h), "hue in range: {h}");
        }
    }
}
