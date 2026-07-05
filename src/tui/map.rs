// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The IP-map view: the range laid on a Hilbert curve as a grid of little squares,
//! each a `/(prefix + 2·order)` block coloured by how full it is. Built from
//! [`crate::map::MapGrid`] each frame (`O(facts)`), so a `/8` maps as cheaply as a
//! `/24`. The legend labels the block structure — the covered CIDR and the per-cell
//! subnet size — not linear x/y ticks, which a Hilbert layout has no use for.
//!
//! Each cell **draws its segment of the actual Hilbert curve** with rounded box-drawing
//! glyphs (`─│╭╮╰╯`), so the serpentine path — which cell follows which — is visible rather
//! than left to the imagination. Occupancy is the cell **background**, per
//! [`DensityStyle`](super::app::DensityStyle):
//! - **Heatmap** (default) — a **logarithmic** ramp, near-black = empty → deep red = barely
//!   used → white = full, with no blue; because almost every block is sparse, the log scale
//!   spreads the low end across the reds/oranges and reserves white for a genuinely full block.
//! - **Shade** — a monochrome grey ramp, for low-colour terminals.
//!
//! The curve line sits on top in a contrasting colour. `s` toggles the two styles. A
//! highlighted cursor moves over the grid (`hjkl`); `Enter` zooms into the cell under it —
//! always a clean subnet — and `Backspace` zooms back out, so a few steps take a `/8` down
//! to a `/24` the table and tree resolve to single addresses.

use std::collections::HashMap;
use std::net::IpAddr;

use mullion::style::{Color, Style};
use mullion::{Buffer, Rect};

use super::app::{App, DensityStyle};
use super::draw::{btxt, keyhints};
use super::theme::{s_accent, s_dim, s_sel, s_title};
use crate::map::MapGrid;
use crate::reconcile::{self, AddressFacts, Cidr, Subnet};

/// Background of an empty (unused) cell — a near-black, so occupancy reads straight off the
/// cell background: dark = empty, deep-red → white = fuller.
const EMPTY_BG: Color = Color::Rgb(22, 22, 26);

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

/// A grid direction from one cell to an adjacent one.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Dir {
    L,
    R,
    U,
    D,
}

/// The direction from grid cell `a` to an adjacent cell `b` (`None` if not 4-adjacent).
fn dir_between(a: (u32, u32), b: (u32, u32)) -> Option<Dir> {
    match (i64::from(b.0) - i64::from(a.0), i64::from(b.1) - i64::from(a.1)) {
        (1, 0) => Some(Dir::R),
        (-1, 0) => Some(Dir::L),
        (0, 1) => Some(Dir::D),
        (0, -1) => Some(Dir::U),
        _ => None,
    }
}

/// The rounded box-drawing glyph for the Hilbert curve through a cell, from the ports toward
/// its previous and next cell on the curve — plus whether the segment continues to the
/// **right** (so the 2-wide cell's spacer is drawn as `─` and the line stays unbroken).
///
/// A cell has two ports (the curve enters and leaves), one at the curve's endpoints, or none
/// for a lone order-0 cell. The glyph joins them: `─│` straight, `╭╮╰╯` for a turn.
fn curve_glyph(a: Option<Dir>, b: Option<Dir>) -> (char, bool) {
    let has = |d: Dir| a == Some(d) || b == Some(d);
    let (l, r, u, dn) = (has(Dir::L), has(Dir::R), has(Dir::U), has(Dir::D));
    let ch = if l && r {
        '─'
    } else if u && dn {
        '│'
    } else if r && u {
        '╰'
    } else if l && u {
        '╯'
    } else if r && dn {
        '╭'
    } else if l && dn {
        '╮'
    } else if l || r {
        '─' // single horizontal port (an endpoint of the curve)
    } else if u || dn {
        '│' // single vertical port
    } else {
        '·' // a lone cell (order 0)
    };
    (ch, r)
}

/// A foreground colour that stays legible on background `bg`: a dark line on a bright
/// (near-full) cell, a light line on a dark (near-empty) one. Rec. 601 luma decides.
fn contrast_fg(bg: Color) -> Color {
    let Color::Rgb(r, g, b) = bg else { return Color::Rgb(230, 230, 230) };
    let luma = 0.30 * f32::from(r) + 0.59 * f32::from(g) + 0.11 * f32::from(b);
    if luma > 150.0 {
        Color::Rgb(20, 20, 20)
    } else {
        Color::Rgb(225, 225, 225)
    }
}

/// The monochrome (shade-style) background for a used fraction — a grey that lightens
/// logarithmically with occupancy, for terminals where the heat colours would be lost.
fn shade_bg(f: f32) -> Color {
    let t = if f <= 0.0 { 0.0 } else { (1.0 + f.log10() / HEAT_DECADES).clamp(0.0, 1.0) };
    let g = (45.0 + t * 195.0).round() as u8; // 45 → 240 grey
    Color::Rgb(g, g, g)
}

/// Paint one map cell at `(x, y)`: the Hilbert-curve `glyph` in column `x` on a background
/// coloured by occupancy, then a spacer in `x + 1` — a `─` when the curve continues right
/// (`connects_right`) so the line is unbroken, otherwise blank.
///
/// The occupancy is the **background**: near-black when empty, up the deep-red→white heat
/// ramp as the block fills (or a grey ramp in shade mode); the curve line sits on top in a
/// contrasting colour. `selected` paints both columns in the cursor style so it always wins.
fn paint_cell(buf: &mut Buffer, x: u16, y: u16, frac: f32, style: DensityStyle, selected: bool, curve: (char, bool)) {
    let (glyph, connects_right) = curve;
    let bg = if frac <= 0.0 {
        EMPTY_BG
    } else {
        match style {
            DensityStyle::Heatmap => heat_color(frac),
            DensityStyle::Shade => shade_bg(frac),
        }
    };
    let cell = if selected { s_sel() } else { Style::default().fg(contrast_fg(bg)).bg(bg) };
    buf.set_char(x, y, glyph, cell);
    buf.set_char(x + 1, y, if connects_right { '─' } else { ' ' }, cell);
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
    let mut cx = buf.set_string(x, y, "curve on bg · empty ", s_dim());
    buf.set_char(cx, y, ' ', Style::default().bg(EMPTY_BG)); // the empty swatch
    cx += 2;
    match style {
        DensityStyle::Heatmap => {
            for k in 0..12u16 {
                // Background swatches spread evenly along the ramp (deep-red → white).
                buf.set_char(cx + k, y, ' ', Style::default().bg(ramp_color(f32::from(k) / 11.0)));
            }
            buf.set_string(cx + 12, y, " full (log)", s_dim());
        }
        DensityStyle::Shade => {
            for k in 0..12u16 {
                let g = (45.0 + f32::from(k) / 11.0 * 195.0) as u8;
                buf.set_char(cx + k, y, ' ', Style::default().bg(Color::Rgb(g, g, g)));
            }
            buf.set_string(cx + 12, y, " full", s_dim());
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
        &clip(&format!("scope: {crumb}{subnet_txt}   ·   the line is the Hilbert curve · bg = occupancy"), area.width),
        s_dim(),
    );

    // The Hilbert grid: each cell draws its segment of the actual curve (rounded box glyphs)
    // over a background coloured by occupancy, so the serpentine path is visible directly.
    let total = grid.cells();
    for d in 0..total {
        let cur = grid.cell_xy(d);
        let (gx, gy) = cur;
        let selected = (gx, gy) == app.map_cur;
        let x = body.x + (gx as u16) * 2;
        let y = body.y + gy as u16;
        if x + 1 < body.x + body.width && y < body.y + body.height {
            // The ports toward the previous and next cell on the curve give the glyph.
            let prev = (d > 0).then(|| grid.cell_xy(d - 1)).and_then(|p| dir_between(cur, p));
            let next = (d + 1 < total).then(|| grid.cell_xy(d + 1)).and_then(|n| dir_between(cur, n));
            paint_cell(buf, x, y, grid.fraction(d), app.density, selected, curve_glyph(prev, next));
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
    fn curve_glyph_joins_the_ports() {
        // Straights, turns, endpoints, and the lone cell.
        assert_eq!(curve_glyph(Some(Dir::L), Some(Dir::R)).0, '─');
        assert_eq!(curve_glyph(Some(Dir::U), Some(Dir::D)).0, '│');
        assert_eq!(curve_glyph(Some(Dir::R), Some(Dir::D)).0, '╭');
        assert_eq!(curve_glyph(Some(Dir::L), Some(Dir::D)).0, '╮');
        assert_eq!(curve_glyph(Some(Dir::R), Some(Dir::U)).0, '╰');
        assert_eq!(curve_glyph(Some(Dir::L), Some(Dir::U)).0, '╯');
        assert_eq!(curve_glyph(None, Some(Dir::R)).0, '─'); // endpoint
        assert_eq!(curve_glyph(None, None).0, '·'); // order-0 lone cell
        // The connects-right flag (drives the horizontal spacer) is set iff a port faces right.
        assert!(curve_glyph(Some(Dir::L), Some(Dir::R)).1);
        assert!(!curve_glyph(Some(Dir::L), Some(Dir::U)).1);
    }

    #[test]
    fn dir_between_reads_grid_adjacency() {
        assert_eq!(dir_between((2, 2), (3, 2)), Some(Dir::R));
        assert_eq!(dir_between((2, 2), (2, 1)), Some(Dir::U));
        assert_eq!(dir_between((2, 2), (4, 2)), None); // not 4-adjacent
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
