// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The IP-map view: the range laid on a Hilbert curve as a grid of little squares,
//! each a `/(prefix + 2·order)` block coloured by how full it is. Built from
//! [`crate::map::MapGrid`] each frame (`O(facts)`), so a `/8` maps as cheaply as a
//! `/24`. The legend labels the block structure — the covered CIDR and the per-cell
//! subnet size — not linear x/y ticks, which a Hilbert layout has no use for.
//!
//! Every cell is a square: empty IP space is a grey hollow `□`; a used block is a
//! filled `■`. How it is coloured depends on
//! [`DensityStyle`](super::app::DensityStyle):
//! - **Heatmap** (default) — a smooth blackbody/Planck ramp, deep red = barely used →
//!   hot blue = full, so a glance reads occupancy like a thermal image.
//! - **Shade** — a monochrome accent block `░▒▓█`, for low-colour terminals.
//!
//! `s` toggles the two. A highlighted cursor moves over the grid (`hjkl`); `Enter`
//! zooms into the cell under it — always a clean subnet — and `Backspace` zooms back
//! out, so a few steps take a `/8` down to a `/24` the table and tree resolve to
//! single addresses.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use mullion::style::{Color, Style};
use mullion::{Buffer, Rect};

use super::app::{App, DensityStyle};
use super::draw::{btxt, keyhints};
use super::theme::{s_accent, s_dim, s_sel, s_title};
use crate::map::MapGrid;
use crate::reconcile::{self, AddressFacts, Cidr};

/// Empty IP space: a grey hollow square. The small `▫` (not the full-size `□`) reads
/// better on a dense grid — the look from aerie's `spiral_stress`.
const EMPTY_GLYPH: char = '▫';
/// A used block: a filled square (coloured by [`heat_color`], or the shade accent).
/// The small `▪` to match [`EMPTY_GLYPH`].
const USED_GLYPH: char = '▪';

/// A Planck-style blackbody heat ramp, low → high occupancy: deep red, red, orange,
/// yellow, yellow-white, white, white-blue, hot-blue. Colouring a block by how full it
/// is lets the eye read occupancy the way a thermal image reads temperature.
const HEAT: [(u8, u8, u8); 8] = [
    (120, 0, 0),     // deep red — barely used
    (220, 30, 20),   // red
    (255, 120, 20),  // orange
    (255, 200, 40),  // yellow
    (255, 240, 150), // yellow-white
    (245, 245, 245), // white
    (185, 210, 255), // white-blue
    (90, 150, 255),  // hot-blue — full
];

/// The heat colour for a used fraction `f ∈ (0, 1]` — an interpolation of the [`HEAT`]
/// ramp. `f` near 0 gives deep red (a nearly-empty block), `f = 1` hot blue (full).
///
/// How: place `f` on the ramp at position `p = f·(N−1)` over the `N` stops, then blend
/// the two stops straddling `p` by the leftover fraction. Because the ramp is smooth,
/// neighbouring fill levels differ only slightly — the eye reads a gradient, not bands.
fn heat_color(f: f32) -> Color {
    let n = HEAT.len();
    let p = f.clamp(0.0, 1.0) * (n - 1) as f32;
    let i = (p.floor() as usize).min(n - 2);
    let t = p - i as f32;
    let (r0, g0, b0) = HEAT[i];
    let (r1, g1, b1) = HEAT[i + 1];
    let lerp = |a: u8, b: u8| (f32::from(a) + (f32::from(b) - f32::from(a)) * t).round() as u8;
    Color::Rgb(lerp(r0, r1), lerp(g0, g1), lerp(b0, b1))
}

/// Shade-style glyph for a used fraction `f ∈ (0, 1]`: a block `░▒▓█` that deepens with
/// density, in the accent colour. The monochrome fallback for terminals where the heat
/// ramp's colours would be lost. (Empty cells are handled by the caller.)
fn shade_glyph(f: f32) -> (char, Style) {
    let level = ((f * 4.0).ceil() as usize).clamp(1, 4);
    (['░', '▒', '▓', '█'][level - 1], s_accent())
}

/// Paint one map cell (2 columns wide) at buffer position `(x, y)`.
///
/// Empty blocks (`frac == 0`) are a grey hollow square `□`. Used blocks are a filled
/// square `■`, coloured per [`DensityStyle`] — the heat ramp, or the monochrome shade
/// block. `selected` paints the cell in the cursor style so the highlight always wins.
fn paint_cell(buf: &mut Buffer, x: u16, y: u16, frac: f32, style: DensityStyle, selected: bool) {
    let (ch, cell_style) = if frac <= 0.0 {
        (EMPTY_GLYPH, s_dim()) // empty IP space: a grey hollow square
    } else {
        match style {
            DensityStyle::Heatmap => (USED_GLYPH, Style::default().fg(heat_color(frac))),
            DensityStyle::Shade => shade_glyph(frac),
        }
    };
    let s = if selected { s_sel() } else { cell_style };
    buf.set_char(x, y, ch, s);
    buf.set_char(x + 1, y, ch, s);
}

/// The largest Hilbert order whose `2^order × 2^order` grid of 2-wide cells fits in
/// `body` — `floor(log2(min(width/2, height)))`.
fn fit_order(body: Rect) -> u32 {
    let side_max = (body.width / 2).min(body.height);
    if side_max < 1 {
        0
    } else {
        u32::BITS - 1 - u32::from(side_max).leading_zeros()
    }
}

/// Draw the density key at `(x, y)`: `□ empty`, then for the heatmap an
/// `emptier → fuller` gradient swatch of the actual [`HEAT`] colours (so the ramp is
/// self-documenting), or for shade the `░▒▓█` blocks.
fn draw_legend_key(buf: &mut Buffer, x: u16, y: u16, style: DensityStyle) {
    let mut cx = buf.set_string(x, y, "□ empty   ", s_dim());
    match style {
        DensityStyle::Heatmap => {
            cx = buf.set_string(cx, y, "emptier ", s_dim());
            for k in 0..8u16 {
                // Sample the ramp at each stop's centre so the swatch spans deep-red→hot-blue.
                let f = (f32::from(k) + 0.5) / 8.0;
                buf.set_char(cx + k, y, USED_GLYPH, Style::default().fg(heat_color(f)));
            }
            buf.set_string(cx + 8, y, " fuller", s_dim());
        }
        DensityStyle::Shade => {
            buf.set_string(cx, y, "░▒▓█ fuller", s_dim());
        }
    }
}

/// The last address of the block that starts at `base` and holds `block` addresses
/// (`base + block − 1`), for showing a cell's address span.
fn last_of(base: Ipv4Addr, block: u64) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(base).wrapping_add((block - 1) as u32))
}

/// A short, comma-separated list of the hostnames inside `sub` — what lives in the
/// block under the cursor. Shows up to `max` names, then `+N` for the rest; `—` when
/// the block is empty. Names come from the reconciled facts (PTR or NetBox name).
fn names_in(facts: &HashMap<Ipv4Addr, AddressFacts>, sub: Cidr, max: usize) -> String {
    let mut names: Vec<String> = facts
        .values()
        .filter(|f| sub.contains(f.addr))
        .filter_map(|f| reconcile::row_from_facts(f).name)
        .collect();
    if names.is_empty() {
        return "—".to_string();
    }
    names.sort();
    let extra = names.len().saturating_sub(max);
    let mut shown = names.into_iter().take(max).collect::<Vec<_>>().join(", ");
    if extra > 0 {
        shown.push_str(&format!(", +{extra}"));
    }
    shown
}

/// Clip `text` to at most `w` columns (so an info line never overruns the screen).
fn clip(text: &str, w: u16) -> String {
    text.chars().take(w as usize).collect()
}

/// Paint the map view for the current [`App`] state.
pub fn screen(buf: &mut Buffer, app: &mut App) {
    let full = buf.area;
    if full.width < 26 || full.height < 8 {
        return;
    }

    // ── frame (title + data badge in the border) ──
    let title = format!("netpush — map: {}/{}", app.range.base, app.range.prefix_len);
    let prog = app.progress.as_ref().map(|(f, l)| (*f, l.as_str()));
    let area = super::draw::frame(buf, full, &title, s_title(), Some(super::draw::data_badge(app)), prog);

    // ── grid ── (row 0: legend; bottom three rows: cursor info, scope, footer)
    let body = Rect::new(area.x, area.y + 1, area.width, area.height.saturating_sub(4));
    let grid = MapGrid::build(app.range, &app.facts, fit_order(body));
    let side = grid.side();
    let used_total: u32 = grid.used.iter().sum();
    let cell_prefix = app.range.prefix_len + 2 * grid.order as u8;

    // Sync the app's cursor state to this frame's grid: the order sets what `Enter`
    // zooms into, and a shrunk terminal may need the cursor clamped back in-bounds.
    app.map_order = grid.order;
    let last = (side as u32).saturating_sub(1);
    app.map_cur = (app.map_cur.0.min(last), app.map_cur.1.min(last));

    // Legend: block structure, not linear ticks (Hilbert has no meaningful x/y axis).
    let head = format!(
        "Hilbert · {side}×{side} · cell = /{cell_prefix} ({} addrs) · {used_total} used / {} total   ",
        grid.block,
        grid.range.block_len()
    );
    btxt(buf, area.x, area.y, &head, s_dim());
    draw_legend_key(buf, area.x + head.chars().count() as u16, area.y, app.density);

    for d in 0..grid.cells() {
        let (gx, gy) = grid.cell_xy(d);
        let selected = (gx, gy) == app.map_cur;
        let x = body.x + (gx as u16) * 2; // 2-wide cells for a squarer aspect
        let y = body.y + gy as u16;
        if x + 1 < body.x + body.width && y < body.y + body.height {
            paint_cell(buf, x, y, grid.fraction(d), app.density, selected);
        }
    }

    // ── cursor info · scope breadcrumb · footer (bottom three rows) ──
    let info_y = area.y + area.height - 3;
    let scope_y = area.y + area.height - 2;
    let foot_y = area.y + area.height - 1;

    // The block the cursor sits over: its CIDR, address span, occupancy and hostnames.
    // When the grid is a single cell (order 0), that block is the whole current scope.
    let zoomable = app.cursor_subnet().is_some();
    let (cell, used, block) = match app.cursor_subnet() {
        Some(sub) => {
            let d = crate::map::hilbert_xy2d(grid.order, app.map_cur.0, app.map_cur.1) as usize;
            (sub, grid.used.get(d).copied().unwrap_or(0), grid.block)
        }
        None => (app.range, used_total, grid.range.block_len()),
    };
    let info = format!(
        "▸ {}/{}   {} – {}   {}/{} used   {}",
        cell.base,
        cell.prefix_len,
        cell.base,
        last_of(cell.base, block),
        used,
        block,
        names_in(&app.facts, cell, 3),
    );
    btxt(buf, area.x, info_y, &clip(&info, area.width), s_accent());

    // Scope breadcrumb: outermost range › … › current, so you never lose your place.
    let crumb = app
        .scope_chain()
        .iter()
        .map(|c| format!("{}/{}", c.base, c.prefix_len))
        .collect::<Vec<_>>()
        .join(" › ");
    btxt(buf, area.x, scope_y, &clip(&format!("scope: {crumb}"), area.width), s_dim());

    // Footer key hints (zoom only offered while there's a finer subnet to reach).
    let hints: &[(&str, &str)] = if zoomable {
        &[("hjkl", "move"), ("↵", "zoom in"), ("Bksp", "out"), ("s", "style"), ("Tab", "table"), ("q", "quit")]
    } else {
        &[("s", "style"), ("Tab", "table"), ("q", "quit")]
    };
    keyhints(buf, area.x, foot_y, area.width, hints);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heat_ramp_runs_deep_red_to_hot_blue() {
        // Emptiest used block is reddish (r dominates), fullest is bluish (b dominates).
        let Color::Rgb(r_lo, _, b_lo) = heat_color(0.001) else { panic!("expected rgb") };
        assert!(r_lo > b_lo, "low occupancy should be red-dominant, got r={r_lo} b={b_lo}");
        let Color::Rgb(r_hi, _, b_hi) = heat_color(1.0) else { panic!("expected rgb") };
        assert!(b_hi > r_hi, "full block should be blue-dominant, got r={r_hi} b={b_hi}");
        // Endpoints match the ramp exactly.
        assert_eq!(heat_color(0.0), Color::Rgb(HEAT[0].0, HEAT[0].1, HEAT[0].2));
        assert_eq!(heat_color(1.0), Color::Rgb(HEAT[7].0, HEAT[7].1, HEAT[7].2));
    }

    #[test]
    fn heat_color_is_stable_and_bounded_across_the_range() {
        // Every fraction resolves to some RGB (no panic, no out-of-band index).
        for k in 0..=100 {
            let f = k as f32 / 100.0;
            assert!(matches!(heat_color(f), Color::Rgb(_, _, _)));
        }
    }

    #[test]
    fn renders_both_styles_without_panicking() {
        use crate::fixture;
        use mullion::{Buffer, KeyCode, Rect};

        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false, false, crate::config::Config::default());
        app.view = super::super::app::View::Map;
        for _ in 0..2 {
            for (w, h) in [(120u16, 50u16), (80, 24), (40, 10), (24, 6)] {
                let mut buf = Buffer::empty(Rect::new(0, 0, w, h));
                screen(&mut buf, &mut app);
            }
            app.on_key(KeyCode::Char('s')); // flip Heatmap ↔ Shade and render again
        }
    }
}
