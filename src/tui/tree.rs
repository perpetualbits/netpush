// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The tree view: walk a network like a tree — the range at the root, expandable
//! **groups** (name clusters such as `ntserver`/`netapp`, plus `(free)` and
//! `(unregistered)` so every address is reachable), and **hosts** as leaves. Enter
//! on a group expands/collapses it; Enter on a host opens the inspect panel.
//!
//! Larger address spaces will need pagination (see `docs/vision.md`); for a single
//! browsed range the whole tree is built each frame, which is cheap.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use mullion::{Buffer, Rect};

use super::app::App;
use super::draw::{btxt, detail_overlay, fill_row, keyhints};
use super::theme::{s_accent, s_dim, s_head, s_normal, s_ok, s_sel, s_title, status_style};
use crate::graph::cluster_of;
use crate::reconcile::{AddressRow, AddressStatus};

/// One visible line of the tree.
pub struct TreeRowView {
    /// Indentation level (0 = root, 1 = group, 2 = host).
    pub depth: u16,
    /// Left label (CIDR / group name / address).
    pub label: String,
    /// Dim right-hand detail (counts / hostname).
    pub detail: String,
    /// `true` for the root and group rows (expandable).
    pub is_group: bool,
    /// Whether an expandable row is currently expanded.
    pub expanded: bool,
    /// The group key this row acts on: its own for a group, its parent's for a host.
    pub key: Option<String>,
    /// The address, for host rows (drives inspect + colour).
    pub addr: Option<Ipv4Addr>,
    /// The verdict, for host rows.
    pub status: Option<AddressStatus>,
}

/// The group an address belongs to: its name's cluster, or a bucket for the nameless.
fn group_key(row: &AddressRow) -> String {
    match &row.name {
        Some(n) => cluster_of(n),
        None if row.status == AddressStatus::Free => "(free)".to_string(),
        None => "(unregistered)".to_string(),
    }
}

/// Build the currently-visible tree rows from the app's data and the expanded set.
///
/// Only the **known** addresses (bounded by facts) are grouped into expandable
/// clusters; empty space is shown as a single `(free)` count leaf, never enumerated —
/// so this is safe over a `/8`. Groups are alphabetical (via `BTreeMap`); the root is
/// always expanded.
#[must_use]
pub fn rows(app: &App) -> Vec<TreeRowView> {
    let mut groups: BTreeMap<String, Vec<AddressRow>> = BTreeMap::new();
    for r in app.known_rows() {
        let key = group_key(&r);
        if key == "(free)" {
            continue; // free space is a count, not a per-address list
        }
        groups.entry(key).or_default().push(r);
    }

    let mut out = Vec::new();
    out.push(TreeRowView {
        depth: 0,
        label: format!("{}/{}", app.range.base, app.range.prefix_len),
        detail: format!("{} free / {} total", app.counts.free, app.total),
        is_group: true,
        expanded: true,
        key: None,
        addr: None,
        status: None,
    });

    // Free space: one non-expandable count leaf (could be millions of addresses).
    if app.counts.free > 0 {
        out.push(TreeRowView {
            depth: 1,
            label: "(free)".to_string(),
            detail: format!("({})", app.counts.free),
            is_group: false,
            expanded: false,
            key: None,
            addr: None,
            status: Some(AddressStatus::Free),
        });
    }

    for (key, members) in &groups {
        let expanded = app.tree_expanded.contains(key);
        out.push(TreeRowView {
            depth: 1,
            label: key.clone(),
            detail: format!("({})", members.len()),
            is_group: true,
            expanded,
            key: Some(key.clone()),
            addr: None,
            status: None,
        });
        if expanded {
            for r in members {
                out.push(TreeRowView {
                    depth: 2,
                    label: r.addr.to_string(),
                    detail: r.name.clone().unwrap_or_default(),
                    is_group: false,
                    expanded: false,
                    key: Some(key.clone()),
                    addr: Some(r.addr),
                    status: Some(r.status),
                });
            }
        }
    }
    out
}

/// Paint the tree view for the current [`App`] state.
pub fn screen(buf: &mut Buffer, app: &mut App) {
    let full = buf.area;
    if full.width < 26 || full.height < 8 {
        return;
    }
    let rows = rows(app);
    if !rows.is_empty() {
        app.tree_cur = app.tree_cur.min(rows.len() - 1);
    }

    // ── frame + header ──
    let title = format!("netpush — tree: {}/{}", app.range.base, app.range.prefix_len);
    let prog = app.progress.as_ref().map(|(f, l)| (*f, l.as_str()));
    let area = super::draw::frame(buf, full, &title, s_title(), Some(super::draw::data_badge(app)), prog);
    btxt(buf, area.x, area.y, "network → cluster → host", s_dim());

    // ── body: the visible slice of the tree ──
    let body = Rect::new(area.x, area.y + 1, area.width, area.height.saturating_sub(2));
    let vis = body.height as usize;
    // Keep the cursor in view with a simple top offset.
    let top = app.tree_cur.saturating_sub(vis.saturating_sub(1)).min(app.tree_cur);
    for (i, row) in rows.iter().enumerate().skip(top).take(vis) {
        let y = body.y + (i - top) as u16;
        let selected = i == app.tree_cur;
        if selected {
            fill_row(buf, body.x, y, body.width, s_sel());
        }
        draw_row(buf, body.x, y, body.width, row, selected);
    }

    // ── footer ──
    keyhints(
        buf,
        area.x,
        area.y + area.height - 1,
        area.width,
        &[
            ("j/k", "move"),
            ("Enter/→", "expand/inspect"),
            ("←", "collapse"),
            ("Tab", "map"),
            ("q", "quit"),
        ],
    );

    // Inspect panel (opened by Enter on a host) reuses the table's overlay.
    if app.detail {
        detail_overlay(buf, area, app);
    }
}

/// Draw one tree line: indentation, an expand marker, the label, and dim detail.
fn draw_row(buf: &mut Buffer, x: u16, y: u16, w: u16, row: &TreeRowView, selected: bool) {
    let indent = row.depth * 2;
    let marker = if row.is_group {
        if row.expanded {
            "▾ "
        } else {
            "▸ "
        }
    } else {
        "• "
    };
    let lx = x + indent;

    let label_style = if selected {
        s_sel()
    } else if row.is_group {
        if row.depth == 0 {
            s_head()
        } else {
            s_accent()
        }
    } else {
        // Colour a host by its status; free hosts stay green.
        row.status.map_or_else(s_normal, status_style)
    };
    let detail_style = if selected { s_sel() } else { s_dim() };

    btxt(buf, lx, y, marker, if selected { s_sel() } else { s_ok() });
    let label_x = lx + 2;
    btxt(buf, label_x, y, &row.label, label_style);
    // Right-hand detail, if there's room.
    let dx = label_x + row.label.chars().count() as u16 + 2;
    if dx < x + w && !row.detail.is_empty() {
        let room = (x + w - dx) as usize;
        let text: String = row.detail.chars().take(room).collect();
        btxt(buf, dx, y, &text, detail_style);
    }
}
