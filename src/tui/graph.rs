// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The node-graph screen: hosts grouped under named clusters, positioned by
//! mullion's Sugiyama layered layout ([`crate::graph`]) and drawn as bordered
//! boxes with orthogonal connectors. A window pans across a larger canvas.
//!
//! This is the first cut of the DNS node-graph vision — cluster overview first;
//! proper wire routing and the bitstream come next.

use std::collections::HashMap;

use mullion::border::{draw_box, BorderStyle, Borders, CornerStyle, LineWeight};
use mullion::{Buffer, Rect, TileId};

use super::app::App;
use super::draw::{btxt, keyhints};
use super::theme::{s_accent, s_dim, s_head, s_normal, s_title};
use crate::graph::NodeKind;

/// Paint the graph view for the current [`App`] state.
pub fn screen(buf: &mut Buffer, app: &mut App) {
    let full = buf.area;
    if full.width < 26 || full.height < 8 {
        return;
    }
    let (cw, ch) = app.graph_canvas.size();
    // Keep the pan inside the canvas.
    app.pan.0 = app.pan.0.min(cw.saturating_sub(1));
    app.pan.1 = app.pan.1.min(ch.saturating_sub(1));

    // ── frame + header ──
    let title = format!("netpush — graph: {}/{}", app.range.base, app.range.prefix_len);
    let prog = app.progress.as_ref().map(|(f, l)| (*f, l.as_str()));
    let area = super::draw::frame(buf, full, &title, s_title(), Some(super::draw::data_badge(app)), prog);
    let hosts = app.graph.nodes.len().saturating_sub(app.graph.cluster_count());
    btxt(
        buf,
        area.x,
        area.y,
        &format!(
            "{} clusters · {} hosts    canvas {cw}×{ch}  pan {},{}",
            app.graph.cluster_count(),
            hosts,
            app.pan.0,
            app.pan.1
        ),
        s_dim(),
    );

    let body = Rect::new(area.x, area.y + 1, area.width, area.height.saturating_sub(2));

    // Positions in canvas space (window = the whole canvas).
    let solved = app.graph_canvas.solve(Rect::new(0, 0, cw, ch));
    let pos: HashMap<TileId, Rect> = solved.iter().copied().collect();

    // Edges first, so node boxes draw over the connector ends.
    for (cluster, host) in &app.graph.edges {
        if let (Some(&cr), Some(&hr)) = (pos.get(cluster), pos.get(host)) {
            draw_edge(buf, body, app.pan, cr, hr);
        }
    }

    // Nodes: only those fully inside the body (partial ones appear as you pan).
    for (id, r) in &solved {
        if let Some(screen_rect) = to_screen(*r, body, app.pan) {
            let node = app.graph.node(*id);
            let is_cluster = node.is_some_and(|n| n.kind == NodeKind::Cluster);
            let label = node.map(|n| n.label.as_str()).unwrap_or("");
            draw_node(buf, screen_rect, label, is_cluster);
        }
    }

    // ── footer ──
    keyhints(
        buf,
        area.x,
        area.y + area.height - 1,
        area.width,
        &[("Tab", "tree"), ("hjkl/arrows", "pan"), ("g", "home"), ("q", "quit")],
    );
}

// Note: the outer frame/title is drawn by `super::draw::frame`; this view lays its
// content out inside the returned inner rect.

/// Draw one node box plus its (truncated) label; clusters get a heavy accent border.
fn draw_node(buf: &mut Buffer, r: Rect, label: &str, cluster: bool) {
    let style = BorderStyle {
        weight: if cluster { LineWeight::Heavy } else { LineWeight::Light },
        corners: CornerStyle::Rounded,
        style: if cluster { s_accent() } else { s_dim() },
    };
    draw_box(buf, r, Borders::ALL, &style);
    let inner = r.width.saturating_sub(2) as usize;
    let text: String = label.chars().take(inner).collect();
    let tstyle = if cluster { s_head() } else { s_normal() };
    btxt(buf, r.x + 1, r.y + 1, &text, tstyle);
}

/// Map a canvas-space rect to screen coords, returning `None` unless it fits wholly
/// inside `body` (so a partly-scrolled node is simply not drawn until panned in).
fn to_screen(r: Rect, body: Rect, pan: (u16, u16)) -> Option<Rect> {
    let sx = i32::from(r.x) - i32::from(pan.0) + i32::from(body.x);
    let sy = i32::from(r.y) - i32::from(pan.1) + i32::from(body.y);
    if sx < i32::from(body.x) || sy < i32::from(body.y) {
        return None;
    }
    if sx + i32::from(r.width) > i32::from(body.x) + i32::from(body.width) {
        return None;
    }
    if sy + i32::from(r.height) > i32::from(body.y) + i32::from(body.height) {
        return None;
    }
    Some(Rect::new(sx as u16, sy as u16, r.width, r.height))
}

/// Draw an orthogonal connector from a cluster's bottom-centre down to a host's
/// top-centre (down, across, down), clipped cell-by-cell to `body`.
fn draw_edge(buf: &mut Buffer, body: Rect, pan: (u16, u16), cluster: Rect, host: Rect) {
    let sx = cluster.x + cluster.width / 2;
    let sy = cluster.y + cluster.height; // just below the cluster box
    let ex = host.x + host.width / 2;
    let ey = host.y; // just above the host box
    if ey <= sy {
        return; // only draw the expected top→down direction
    }
    let mid = (sy + ey) / 2;
    for y in sy..=mid {
        plot(buf, body, pan, sx, y, '│');
    }
    let (x0, x1) = if sx <= ex { (sx, ex) } else { (ex, sx) };
    for x in x0..=x1 {
        plot(buf, body, pan, x, mid, '─');
    }
    for y in mid..=ey {
        plot(buf, body, pan, ex, y, '│');
    }
}

/// Plot one connector cell at canvas `(cx, cy)`, if it lands inside `body`.
fn plot(buf: &mut Buffer, body: Rect, pan: (u16, u16), cx: u16, cy: u16, ch: char) {
    let sx = i32::from(cx) - i32::from(pan.0) + i32::from(body.x);
    let sy = i32::from(cy) - i32::from(pan.1) + i32::from(body.y);
    if sx >= i32::from(body.x)
        && sy >= i32::from(body.y)
        && sx < i32::from(body.x) + i32::from(body.width)
        && sy < i32::from(body.y) + i32::from(body.height)
    {
        buf.set_string(sx as u16, sy as u16, &ch.to_string(), s_dim());
    }
}
