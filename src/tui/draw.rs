// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Buffer drawing: the reconciled-address screen and the small primitives it uses
//! (title, count bar, rows, key-hint footer, scrollbar). Primitives mirror census.

use mullion::{render_keyhints, render_scrollbar, style::Style, Buffer, Rect, ScrollMetrics, TextCtx};

use super::app::App;
use super::theme::{
    s_accent, s_dim, s_err, s_normal, s_ok, s_sel, s_title, s_warn, status_label, status_style,
};
use crate::reconcile::{AddressStatus, Counts};

/// Write `text` at `(x, y)` in `style`.
pub fn btxt(buf: &mut Buffer, x: u16, y: u16, text: &str, style: Style) {
    buf.set_string(x, y, text, style);
}

/// Fill `w` cells from `(x, y)` with spaces in `style` — used for the row highlight.
pub fn fill_row(buf: &mut Buffer, x: u16, y: u16, w: u16, style: Style) {
    for cx in x..x + w {
        buf.set_string(cx, y, " ", style);
    }
}

/// Themed key-hint footer via mullion's `render_keyhints`.
pub fn keyhints(buf: &mut Buffer, x: u16, y: u16, w: u16, pairs: &[(&str, &str)]) {
    render_keyhints(buf, Rect::new(x, y, w, 1), pairs, &super::theme::mullion_theme(), TextCtx::LTR);
}

/// Draw a vertical scrollbar in the last column of `area` when `len` rows overflow
/// a `vis`-row window at `offset`; returns the content rect (minus the bar column).
pub fn vscroll(buf: &mut Buffer, area: Rect, offset: usize, len: usize, vis: usize) -> Rect {
    if len <= vis || vis == 0 || area.width < 2 {
        return area;
    }
    let bar = Rect::new(area.x + area.width - 1, area.y, 1, area.height);
    let metrics = ScrollMetrics {
        position: offset as f32 / len as f32,
        extent: vis as f32 / len as f32,
        exact: true,
    };
    render_scrollbar(buf, bar, metrics, s_dim());
    Rect::new(area.x, area.y, area.width - 1, area.height)
}

/// Paint the whole screen for the current [`App`] state.
///
/// Layout (top to bottom): title row, count bar, column header, the scrollable
/// address table, and a key-hint footer. Mutates `app` only to keep the cursor's
/// scroll offset in view for the body height we just measured.
pub fn screen(buf: &mut Buffer, app: &mut App) {
    let area = buf.area;
    if area.width < 24 || area.height < 6 {
        return; // too small to draw anything meaningful
    }

    // ── title row ──
    let mode = app.mode_label();
    btxt(buf, area.x, area.y, &format!("netpush — {:?}", app.range), s_title());
    btxt(
        buf,
        area.x + area.width.saturating_sub(mode.0.len() as u16 + 1),
        area.y,
        mode.0,
        mode.1,
    );

    // ── count bar ──
    count_bar(buf, area.x, area.y + 1, &app.counts);

    // ── column header ──
    let hy = area.y + 2;
    btxt(buf, area.x, hy, "ADDRESS", s_dim());
    btxt(buf, area.x + 16, hy, "STATUS", s_dim());
    btxt(buf, area.x + 34, hy, "NAME", s_dim());

    // ── body ──
    let body = Rect::new(area.x, area.y + 3, area.width, area.height.saturating_sub(4));
    let len = app.rows.len();
    app.page = body.height as usize;
    app.cur.clamp(len);
    app.cur.keep_in_view(len, body.height as usize);

    let content = vscroll(buf, body, app.cur.offset, len, body.height as usize);
    let vis = content.height as usize;
    for (i, row) in app.rows.iter().enumerate().skip(app.cur.offset).take(vis) {
        let y = content.y + (i - app.cur.offset) as u16;
        let selected = i == app.cur.cursor;
        if selected {
            fill_row(buf, content.x, y, content.width, s_sel());
        }
        let base = if selected { s_sel() } else { s_normal() };
        let stat = if selected { s_sel() } else { status_style(row.status) };
        let name_style = if selected { s_sel() } else { s_dim() };

        btxt(buf, content.x, y, &format!("{:<15}", row.addr.to_string()), base);
        btxt(buf, content.x + 16, y, status_label(row.status), stat);
        if let Some(n) = &row.name {
            btxt(buf, content.x + 34, y, n, name_style);
        }
    }

    // ── footer ──
    keyhints(
        buf,
        area.x,
        area.y + area.height - 1,
        area.width,
        &[
            ("j/k", "move"),
            ("g/G", "top/bottom"),
            ("f", "next free"),
            ("q", "quit"),
        ],
    );
}

/// The one-line status tally: each non-zero bucket in its own colour.
fn count_bar(buf: &mut Buffer, x: u16, y: u16, c: &Counts) {
    let mut cx = x;
    let seg = |buf: &mut Buffer, cx: &mut u16, label: &str, n: usize, style: Style| {
        let text = format!("{label} {n}  ");
        btxt(buf, *cx, y, &text, style);
        *cx += text.len() as u16;
    };
    seg(buf, &mut cx, "free", c.free, s_ok());
    seg(buf, &mut cx, "dns-only", c.dns_only, s_warn());
    seg(buf, &mut cx, "netbox-only", c.netbox_only, s_accent());
    seg(buf, &mut cx, "live", c.live_unregistered, s_err());
    seg(buf, &mut cx, "conflict", c.conflict, status_style(AddressStatus::Conflict));
    seg(buf, &mut cx, "allocated", c.allocated, s_dim());
}
