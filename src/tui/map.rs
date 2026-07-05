// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The IP-map view: the range laid on a Hilbert curve as a grid of little squares,
//! each a `/(prefix + 2·order)` block coloured by how full it is. Built from
//! [`crate::map::MapGrid`] each frame (`O(facts)`), so a `/8` maps as cheaply as a
//! `/24`. The legend labels the block structure — the covered CIDR and the per-cell
//! subnet size — not linear x/y ticks, which a Hilbert layout has no use for.
//!
//! Each cell is one glyph plus a spacer, so the marks are spaced equally in both
//! dimensions (a terminal cell is ~twice as tall as wide) and the grid reads as squares.
//! Empty IP space is a grey hollow `▫`; a used block is a filled `▪`. Colouring depends on
//! [`DensityStyle`](super::app::DensityStyle):
//! - **Heatmap** (default) — a **logarithmic** ramp, deep red = barely used → white = full,
//!   with no blue; because almost every block is sparse, the log scale spreads the low end
//!   across the reds/oranges and reserves white for a genuinely full block.
//! - **Shade** — a monochrome accent block `░▒▓█`, for low-colour terminals.
//!
//! The cell background trails dark→light along the Hilbert curve, so the serpentine cell
//! order is legible. `s` toggles the two styles. A highlighted cursor moves over the grid
//! (`hjkl`); `Enter` zooms into the cell under it — always a clean subnet — and `Backspace`
//! zooms back out, so a few steps take a `/8` down to a `/24` the table and tree resolve to
//! single addresses.

use std::collections::HashMap;
use std::net::IpAddr;

use mullion::style::{Color, Style};
use mullion::{Buffer, Rect};

use super::app::{App, DensityStyle};
use super::draw::{btxt, keyhints};
use super::theme::{s_accent, s_dim, s_sel, s_title};
use crate::map::MapGrid;
use crate::reconcile::{self, AddressFacts, Cidr, Subnet};

/// Empty IP space: a grey hollow square. The small `▫` (not the full-size `□`) reads
/// better on a dense grid — the look from aerie's `spiral_stress`.
const EMPTY_GLYPH: char = '▫';
/// A used block: a filled square (coloured by [`heat_color`], or the shade accent).
/// The small `▪` to match [`EMPTY_GLYPH`].
const USED_GLYPH: char = '▪';

/// A heat ramp, low → high occupancy: deep-red → red → orange-red → orange → orange-yellow
/// → yellow → yellow-white → white. No blue — a fuller block is simply *hotter*, and a
/// genuinely full block is white. Interpolated to a smooth gradient (not eight bands).
const HEAT: [(u8, u8, u8); 8] = [
    (100, 0, 0),     // deep red
    (200, 0, 0),     // red
    (255, 60, 0),    // orange-red
    (255, 130, 0),   // orange
    (255, 180, 0),   // orange-yellow
    (255, 230, 0),   // yellow
    (255, 250, 180), // yellow-white
    (255, 255, 255), // white — full
];

/// How many decades of occupancy the log scale spans: a block filled below `10^-DECADES`
/// reads as the deep-red floor, a full block (fraction 1) as white.
const HEAT_DECADES: f32 = 3.0;

/// A colour at position `t ∈ [0, 1]` along the [`HEAT`] ramp (linear over the stops).
/// Used directly for the self-documenting legend swatch.
fn ramp_color(t: f32) -> Color {
    let n = HEAT.len();
    let p = t.clamp(0.0, 1.0) * (n - 1) as f32;
    let i = (p.floor() as usize).min(n - 2);
    let frac = p - i as f32;
    let (r0, g0, b0) = HEAT[i];
    let (r1, g1, b1) = HEAT[i + 1];
    let lerp = |a: u8, b: u8| (f32::from(a) + (f32::from(b) - f32::from(a)) * frac).round() as u8;
    Color::Rgb(lerp(r0, r1), lerp(g0, g1), lerp(b0, b1))
}

/// The heat colour for a used fraction `f ∈ (0, 1]` on a **logarithmic** scale: full → white,
/// and each factor-of-ten emptier steps a decade down the ramp toward deep red.
///
/// Why logarithmic — almost every block is barely used, so a linear scale would paint the
/// whole map deep red and waste the palette. `t = 1 + log₁₀(f)/DECADES` spreads the sparse
/// low end across the reds/oranges and reserves white for a genuinely full block.
fn heat_color(f: f32) -> Color {
    let t = if f <= 0.0 { 0.0 } else { (1.0 + f.log10() / HEAT_DECADES).clamp(0.0, 1.0) };
    ramp_color(t)
}

/// A subtle dark background that brightens along the Hilbert curve (cell index `d` of
/// `total`), so the eye can trace the serpentine order — which cell follows which. Kept to
/// dark greys so it sits behind the heat glyphs without competing with them.
fn trail_bg(d: usize, total: usize) -> Color {
    let t = if total > 1 { d as f32 / (total - 1) as f32 } else { 0.0 };
    let g = (14.0 + t * 34.0).round() as u8; // 14 → 48
    Color::Rgb(g, g, g)
}

/// Shade-style glyph for a used fraction `f ∈ (0, 1]`: a block `░▒▓█` that deepens with
/// density, in the accent colour. The monochrome fallback for terminals where the heat
/// ramp's colours would be lost. (Empty cells are handled by the caller.)
fn shade_glyph(f: f32) -> (char, Style) {
    let level = ((f * 4.0).ceil() as usize).clamp(1, 4);
    (['░', '▒', '▓', '█'][level - 1], s_accent())
}

/// Paint one map cell at `(x, y)`: a single glyph in column `x`, then a spacer in `x + 1`.
///
/// One glyph + one space makes the horizontal and vertical spacing of the marks equal (a
/// terminal cell is about twice as tall as wide), so the grid reads as squares rather than
/// wide rectangles. Empty blocks are a grey hollow square, used blocks a filled square
/// coloured per [`DensityStyle`]; `trail` tints the background along the Hilbert curve, and
/// `selected` paints the whole 2-column cell in the cursor style so the highlight wins.
fn paint_cell(buf: &mut Buffer, x: u16, y: u16, frac: f32, style: DensityStyle, selected: bool, trail: Color) {
    let (ch, cell_style) = if frac <= 0.0 {
        (EMPTY_GLYPH, s_dim()) // empty IP space: a grey hollow square
    } else {
        match style {
            DensityStyle::Heatmap => (USED_GLYPH, Style::default().fg(heat_color(frac))),
            DensityStyle::Shade => shade_glyph(frac),
        }
    };
    let glyph_style = if selected { s_sel() } else { cell_style.bg(trail) };
    let spacer_style = if selected { s_sel() } else { Style::default().bg(trail) };
    buf.set_char(x, y, ch, glyph_style);
    buf.set_char(x + 1, y, ' ', spacer_style);
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
    let mut cx = buf.set_string(x, y, "▫ empty   ", s_dim());
    match style {
        DensityStyle::Heatmap => {
            cx = buf.set_string(cx, y, "log: empty ", s_dim());
            for k in 0..12u16 {
                // Even spread along the ramp (deep-red → white), so the key shows every stop.
                let t = f32::from(k) / 11.0;
                buf.set_char(cx + k, y, USED_GLYPH, Style::default().fg(ramp_color(t)));
            }
            buf.set_string(cx + 12, y, " full", s_dim());
        }
        DensityStyle::Shade => {
            buf.set_string(cx, y, "░▒▓█ fuller", s_dim());
        }
    }
}

/// A short, comma-separated list of the hostnames inside `sub` — what lives in the
/// block under the cursor. Shows up to `max` names, then `+N` for the rest; `—` when
/// the block is empty. Names come from the reconciled facts (PTR or NetBox name).
fn names_in(facts: &HashMap<IpAddr, AddressFacts>, sub: Cidr, max: usize) -> String {
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
    let title = format!("canopy — map: {}/{}", app.range.base, app.range.prefix_len);
    let prog = app.progress.as_ref().map(|(f, l)| (*f, l.as_str()));
    let area = super::draw::frame(buf, full, &title, s_title(), Some(super::draw::data_badge(app)), prog, &app.heartbeat());

    // Layout: three header rows — legend, cursor info, scope — ABOVE the Hilbert square, so
    // the "what am I looking at" lines lead; then the grid; then the footer on the last row.
    let legend_y = area.y;
    let info_y = area.y + 1;
    let scope_y = area.y + 2;
    let foot_y = area.y + area.height - 1;
    let body = Rect::new(area.x, area.y + 3, area.width, area.height.saturating_sub(4));

    let grid = MapGrid::build(app.range, &app.facts, fit_order(body));
    let side = grid.side();
    let used_total: u32 = grid.used.iter().sum();
    let cell_prefix = app.range.prefix_len + 2 * grid.order as u8;

    // Sync the app's cursor state to this frame's grid: the order sets what `Enter`
    // zooms into, and a shrunk terminal may need the cursor clamped back in-bounds.
    app.map_order = grid.order;
    let last = (side as u32).saturating_sub(1);
    app.map_cur = (app.map_cur.0.min(last), app.map_cur.1.min(last));

    // Row 0 — block structure + density key (Hilbert has no meaningful linear x/y axis).
    let head = format!(
        "Hilbert · {side}×{side} · cell = /{cell_prefix} ({} addrs) · {used_total} used / {} total   ",
        grid.block,
        grid.range.block_len()
    );
    btxt(buf, area.x, legend_y, &head, s_dim());
    draw_legend_key(buf, area.x + head.chars().count() as u16, legend_y, app.density);

    // Rows 1–2 — the block under the cursor (CIDR, span, occupancy, hostnames) and the
    // scope breadcrumb + real NetBox subnet. When the grid is one cell, that block is the
    // whole current scope.
    let zoomable = app.cursor_subnet().is_some();
    let (cell, used, block) = match app.cursor_subnet() {
        Some(sub) => {
            let d = crate::map::hilbert_xy2d(grid.order, app.map_cur.0, app.map_cur.1) as usize;
            (sub, grid.used.get(d).copied().unwrap_or(0), grid.block)
        }
        None => (app.range, used_total, grid.range.block_len()),
    };
    // For a sparse (huge) block the "/block" denominator is astronomically large and
    // unhelpful, so show just the used count; for an enumerable block show used/total.
    let occ = if cell.is_enumerable() { format!("{used}/{block} used") } else { format!("{used} used") };
    let info = format!(
        "▸ {}/{}   {} – {}   {occ}   {}",
        cell.base,
        cell.prefix_len,
        cell.base,
        cell.last(),
        names_in(&app.facts, cell, 3),
    );
    btxt(buf, area.x, info_y, &clip(&info, area.width), s_accent());

    let crumb = app
        .scope_chain()
        .iter()
        .map(|c| format!("{}/{}", c.base, c.prefix_len))
        .collect::<Vec<_>>()
        .join(" › ");
    let subnet_txt = match Subnet::most_specific(&app.subnets, cell.base) {
        Some(s) if !s.name.is_empty() => format!("   ·   subnet: {}/{} ({})", s.cidr.base, s.cidr.prefix_len, s.name),
        Some(s) => format!("   ·   subnet: {}/{}", s.cidr.base, s.cidr.prefix_len),
        None => String::new(),
    };
    btxt(
        buf,
        area.x,
        scope_y,
        &clip(&format!("scope: {crumb}{subnet_txt}   ·   cells follow the Hilbert curve (bg dark→light)"), area.width),
        s_dim(),
    );

    // The Hilbert grid. One glyph + a spacer per cell for a square aspect; the background
    // trails dark→light along the curve so the serpentine cell order is legible.
    let total = grid.cells();
    for d in 0..total {
        let (gx, gy) = grid.cell_xy(d);
        let selected = (gx, gy) == app.map_cur;
        let x = body.x + (gx as u16) * 2;
        let y = body.y + gy as u16;
        if x + 1 < body.x + body.width && y < body.y + body.height {
            paint_cell(buf, x, y, grid.fraction(d), app.density, selected, trail_bg(d, total));
        }
    }

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
    fn heat_ramp_runs_deep_red_to_white_logarithmically() {
        // A barely-used block is deep red (r dominant, no blue); a full block is white.
        let Color::Rgb(r_lo, _, b_lo) = heat_color(0.0005) else { panic!("expected rgb") };
        assert!(r_lo > b_lo, "low occupancy should be red-dominant, got r={r_lo} b={b_lo}");
        assert_eq!(heat_color(1.0), Color::Rgb(255, 255, 255), "full block is white");
        // Endpoints match the ramp exactly (deep red ↔ white), and there is no blue skew.
        assert_eq!(heat_color(0.0), Color::Rgb(HEAT[0].0, HEAT[0].1, HEAT[0].2));
        // Logarithmic: a 10× fuller block sits strictly higher up the ramp (greener/whiter).
        let Color::Rgb(_, g1, _) = heat_color(0.01) else { panic!() };
        let Color::Rgb(_, g2, _) = heat_color(0.1) else { panic!() };
        assert!(g2 > g1, "10x fuller should be higher on the ramp: g(0.1)={g2} > g(0.01)={g1}");
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
