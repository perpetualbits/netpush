// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The IP-map view: the range laid on a **generalized-Hilbert (Gilbert) curve** as a grid of
//! little cells that **fills the whole terminal rectangle** — any `width × height`, not just a
//! square power of two — each cell a contiguous address slice coloured by how full it is. Built
//! from [`crate::map::MapGrid`] each frame (`O(width·height + facts)`), so a `/8` maps as cheaply
//! as a `/24`. The legend labels the grid structure — dimensions, per-cell address count, and the
//! covered range — not linear x/y ticks, which a space-filling layout has no use for.
//!
//! Each cell **draws its segment of the actual Gilbert curve** with rounded box-drawing
//! glyphs (`─│╭╮╰╯`), so the serpentine path — which cell follows which — is visible rather
//! than left to the imagination (the grid dimensions are nudged to share parity so the curve
//! is strictly continuous, an unbroken line). Occupancy is the cell **background**:
//! - **Heatmap** (default) — a **logarithmic** ramp, near-black = empty → deep red = barely
//!   used → white = full, with no blue; because almost every block is sparse, the log scale
//!   spreads the low end across the reds/oranges and reserves white for a genuinely full block.
//! - **Shade** — a monochrome grey ramp, for low-colour terminals.
//!
//! The curve line sits on top in a contrasting colour. `s`/`p` cycle the schemes. A highlighted
//! cursor moves over the grid (`hjkl`); `Enter` zooms into the exact address slice under it —
//! a clean subnet when the geometry is a power of two, else a ragged range — and `Backspace`
//! zooms back out, so a few steps take a `/8` down to where the table and tree resolve to
//! single addresses.

use std::collections::HashMap;
use std::net::IpAddr;

use mullion::style::{Color, Style};
use mullion::{Buffer, Rect};

use super::app::App;
use super::draw::{btxt, keyhints};
use super::palette::{Knobs, Scheme, KNOBS};
use super::theme::{s_accent, s_dim, s_sel, s_title};
use crate::map::MapGrid;
use crate::reconcile::{self, AddrRange, AddressFacts, Subnet};

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

/// Paint one map cell at `(x, y)`: the Hilbert-curve `glyph` in column `x` on background
/// `bg`, foreground `fg`, then a spacer in `x + 1` — a `─` when the curve continues right so
/// the line is unbroken, otherwise blank. The colours come from the active
/// [`Scheme`](super::palette::Scheme); `selected` paints both columns in the cursor style.
fn paint_cell(buf: &mut Buffer, x: u16, y: u16, bg: Color, fg: Color, selected: bool, curve: (char, bool)) {
    let (glyph, connects_right) = curve;
    let cell = if selected { s_sel() } else { Style::default().fg(fg).bg(bg) };
    buf.set_char(x, y, glyph, cell);
    buf.set_char(x + 1, y, if connects_right { '─' } else { ' ' }, cell);
}

/// The background colour for cell `d` when the map is colouring by **group identity**: the hue
/// of the logical group that owns an address in the cell (shared across the whole cluster), at a
/// lightness set by how full the cell is — so a group reads as one coloured region that
/// brightens where it is packed. `None` when the cell holds no grouped address (the caller then
/// keeps the occupancy colour, which leaves empty space at the terminal default).
///
/// A coarse cell can span several groups; it takes the first grouped member in address order —
/// enough to show a cluster's extent, and exact once zoomed to leaf cells.
fn group_bg(app: &App, grid: &MapGrid, d: usize) -> Option<mullion::style::Color> {
    let cr = grid.cell_range(d);
    let mut grouped: Vec<_> = app.facts.values().filter(|f| cr.contains(f.addr)).collect();
    grouped.sort_by_key(|f| f.addr);
    let g = grouped.iter().find_map(|f| app.grouping.group_of(f.addr))?;
    let look = app.grouping.look(&g.id);
    // Occupancy → lightness: any presence is clearly visible (0.20), a full cell brighter (0.48),
    // staying dim enough that the bright curve line still reads on top.
    let light = 0.20 + 0.28 * grid.fraction(d).clamp(0.0, 1.0);
    Some(super::palette::hsl_rgb(look.hue, look.sat, light))
}

/// Choose the Gilbert grid `(width, height)` for `body`, in cells (each cell is two columns
/// wide, one row tall). The grid **fills** the drawable rectangle, but never asks for more
/// cells than the range has addresses (`block_len`): a large range uses the whole screen at
/// a coarse resolution; a small range shrinks to a power-of-two rectangle so each cell is a
/// clean single sub-block. The two dimensions are nudged to share parity so the Gilbert
/// curve is strictly 4-continuous — an unbroken line (see `mullion::spacefill::strictly_continuous`).
fn fit_dims(body: Rect, block_len: u128) -> (u32, u32) {
    let w_max = u32::from(body.width / 2).max(1);
    let h_max = u32::from(body.height).max(1);
    let area = u128::from(w_max) * u128::from(h_max);

    let (mut w, mut h) = if block_len >= area {
        // More addresses than cells: fill the whole rectangle (cells become ragged slices).
        (w_max, h_max)
    } else {
        // Fewer addresses than the screen holds: block_len is a power of two, so pick the
        // largest power-of-two rectangle (2^a × 2^b) that fits — this keeps each cell a
        // clean, aligned sub-block. Prefer a wider grid to use horizontal space.
        let k = (block_len as u64).trailing_zeros();
        let mut best = (1u32, 1u32);
        'outer: for m in (0..=k).rev() {
            for a in (0..=m).rev() {
                let (ww, hh) = (1u64 << a, 1u64 << (m - a));
                if ww <= u64::from(w_max) && hh <= u64::from(h_max) {
                    best = (ww as u32, hh as u32);
                    break 'outer;
                }
            }
        }
        best
    };

    // A strictly-continuous curve (a clean, unbroken line) needs the dimensions to share
    // parity; if they differ, trim one cell off the larger axis.
    if (w + h) % 2 != 0 {
        if h > 1 {
            h -= 1;
        } else if w > 1 {
            w -= 1;
        }
    }
    (w.max(1), h.max(1))
}

/// Draw the palette key at `(x, y)`: the scheme name, an `empty → full` swatch strip
/// generated from the scheme itself (so it is self-documenting under any knob setting), and
/// the currently-selected knob and its value.
fn draw_legend_key(buf: &mut Buffer, x: u16, y: u16, scheme: Scheme, knobs: &Knobs, active_knob: usize) {
    let cx = buf.set_string(x, y, &format!("scheme: {} [p] · ", scheme.name()), s_dim());
    // Background swatches sampled from the scheme across the occupancy range (empty → full).
    let mut sx = cx;
    for k in 0..12u16 {
        let frac = if k == 0 { 0.0 } else { 10f32.powf((f32::from(k) / 11.0 - 1.0) * knobs.decades) };
        let (bg, _) = scheme.paint(frac, 0.5, knobs);
        buf.set_char(sx + k, y, ' ', Style::default().bg(bg));
    }
    sx += 12;
    // The active knob + value (selected with [ ], adjusted with , .).
    let (name, ..) = KNOBS[active_knob];
    buf.set_string(sx, y, &format!("  knob [{}] {} = {:.2}  [,.]", active_knob, name, knobs.get(active_knob)), s_dim());
}

/// A short, comma-separated list of the hostnames inside `sub` — what lives in the
/// block under the cursor. Shows up to `max` names, then `+N` for the rest; `—` when
/// the block is empty. Names come from the reconciled facts (PTR or NetBox name).
fn names_in(facts: &HashMap<IpAddr, AddressFacts>, sub: AddrRange, max: usize) -> String {
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
    let title = format!("canopy — map: {}", app.range.label());
    let prog = app.progress.as_ref().map(|(f, l)| (*f, l.as_str()));
    let area = super::draw::frame(buf, full, &title, s_title(), Some(super::draw::data_badge(app)), prog, &app.heartbeat());

    // Layout: three header rows — legend, cursor info, scope — ABOVE the Hilbert square, so
    // the "what am I looking at" lines lead; then the grid; then the footer on the last row.
    let legend_y = area.y;
    let info_y = area.y + 1;
    let scope_y = area.y + 2;
    let foot_y = area.y + area.height - 1;
    let body = Rect::new(area.x, area.y + 3, area.width, area.height.saturating_sub(4));

    let (gw, gh) = fit_dims(body, app.range.block_len());
    let grid = MapGrid::build(app.range, &app.facts, gw, gh);
    let used_total: u32 = grid.used.iter().sum();

    // Sync the app's cursor state to this frame's grid: the dims set what `Enter` zooms
    // into, and a shrunk terminal may need the cursor clamped back in-bounds.
    app.map_dims = (grid.width, grid.height);
    app.map_cur = (app.map_cur.0.min(grid.width.saturating_sub(1)), app.map_cur.1.min(grid.height.saturating_sub(1)));

    // Row 0 — grid structure + density key (a Gilbert curve has no meaningful linear axis).
    let cell_addrs = grid.range.block_len() / grid.cells().max(1) as u128;
    let head = format!(
        "Gilbert · {gw}×{gh} · cell ≈ {cell_addrs} addrs · {used_total} used / {} total   ",
        grid.range.block_len()
    );
    btxt(buf, area.x, legend_y, &head, s_dim());
    draw_legend_key(buf, area.x + head.chars().count() as u16, legend_y, app.scheme, &app.knobs, app.active_knob);

    // Rows 1–2 — the slice under the cursor (its range, occupancy, hostnames) and the scope
    // breadcrumb + real NetBox subnet. When the grid is one cell, that slice is the whole
    // current scope.
    let cursor_d = grid.xy_to_d(app.map_cur.0, app.map_cur.1);
    let zoomable = cursor_d.is_some() && grid.cells() > 1;
    let (cell, used) = match cursor_d {
        Some(d) => (grid.cell_range(d as usize), grid.used.get(d as usize).copied().unwrap_or(0)),
        None => (app.range, used_total),
    };
    // For a sparse (huge) slice the "/block" denominator is astronomically large and
    // unhelpful, so show just the used count; for an enumerable slice show used/total.
    let block = cell.block_len();
    let occ = if cell.is_enumerable() { format!("{used}/{block} used") } else { format!("{used} used") };
    let info = format!(
        "▸ {}   {} – {}   {occ}   {}",
        cell.label(),
        cell.base(),
        cell.last(),
        names_in(&app.facts, cell, 3),
    );
    btxt(buf, area.x, info_y, &clip(&info, area.width), s_accent());

    let crumb = app
        .scope_chain()
        .iter()
        .map(|c| c.label())
        .collect::<Vec<_>>()
        .join(" › ");
    let subnet_txt = match Subnet::most_specific(&app.subnets, cell.base()) {
        Some(s) if !s.name.is_empty() => format!("   ·   subnet: {}/{} ({})", s.cidr.base, s.cidr.prefix_len, s.name),
        Some(s) => format!("   ·   subnet: {}/{}", s.cidr.base, s.cidr.prefix_len),
        None => String::new(),
    };
    btxt(
        buf,
        area.x,
        scope_y,
        &clip(&format!("scope: {crumb}{subnet_txt}   ·   the line is the Gilbert curve · bg = occupancy"), area.width),
        s_dim(),
    );

    // The Gilbert grid: each cell draws its segment of the actual curve (rounded box glyphs)
    // over a background coloured by occupancy, so the serpentine path is visible directly.
    let total = grid.cells();
    for d in 0..total {
        let cur = grid.cell_xy(d);
        let (gx, gy) = cur;
        let selected = (gx, gy) == app.map_cur;
        let x = body.x + (gx as u16) * 2;
        let y = body.y + gy as u16;
        if x + 1 < body.x + body.width && y < body.y + body.height {
            // The ports toward the previous and next cell give the glyph; the active scheme
            // gives the (background, curve) colours from occupancy and curve position.
            let prev = (d > 0).then(|| grid.cell_xy(d - 1)).and_then(|p| dir_between(cur, p));
            let next = (d + 1 < total).then(|| grid.cell_xy(d + 1)).and_then(|n| dir_between(cur, n));
            let pos = if total > 1 { d as f32 / (total - 1) as f32 } else { 0.0 };
            let (mut bg, fg) = app.scheme.paint(grid.fraction(d), pos, &app.knobs);
            // In group mode, a cell owned by a logical group takes that group's stable hue
            // (occupancy still sets its brightness), so a cluster reads as one coloured region.
            if app.color_by_group {
                if let Some(gbg) = group_bg(app, &grid, d) {
                    bg = gbg;
                }
            }
            paint_cell(buf, x, y, bg, fg, selected, curve_glyph(prev, next));
        }
    }

    // Footer key hints (zoom only offered while there's a finer subnet to reach).
    let hints: &[(&str, &str)] = if zoomable {
        &[("hjkl", "move"), ("↵", "in"), ("Bksp", "out"), ("p", "palette"), ("[ ]", "knob"), (", .", "tune"), ("Tab", "table"), ("q", "quit")]
    } else {
        &[("p", "palette"), ("[ ]", "knob"), (", .", "tune"), ("Tab", "table"), ("q", "quit")]
    };
    keyhints(buf, area.x, foot_y, area.width, hints);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Map a mullion [`Color`] to an SGR parameter string for `fg` (base 30/38) or `bg`
    /// (base 40/48). Rgb becomes a truecolor triple; named colours use the ANSI 16.
    fn sgr(c: mullion::style::Color, bg: bool) -> String {
        use mullion::style::Color;
        let (fg_base, tc, bright_base) = if bg { (40, 48, 100) } else { (30, 38, 90) };
        match c {
            Color::Rgb(r, g, b) => format!("{tc};2;{r};{g};{b}"),
            Color::Reset => format!("{}", fg_base + 9),
            Color::Black => format!("{}", fg_base),
            Color::Red => format!("{}", fg_base + 1),
            Color::Green => format!("{}", fg_base + 2),
            Color::Yellow => format!("{}", fg_base + 3),
            Color::Blue => format!("{}", fg_base + 4),
            Color::Magenta => format!("{}", fg_base + 5),
            Color::Cyan => format!("{}", fg_base + 6),
            Color::Gray => format!("{}", fg_base + 7),
            Color::DarkGray => format!("{}", bright_base),
            Color::LightRed => format!("{}", bright_base + 1),
            Color::LightGreen => format!("{}", bright_base + 2),
            Color::LightYellow => format!("{}", bright_base + 3),
            Color::LightBlue => format!("{}", bright_base + 4),
            Color::LightMagenta => format!("{}", bright_base + 5),
            Color::LightCyan => format!("{}", bright_base + 6),
            Color::White => format!("{}", bright_base + 7),
            Color::Indexed(i) => format!("{tc};5;{i}"),
        }
    }

    /// Render `app`'s current view to a `w×h` buffer and return it as an ANSI-truecolor string —
    /// a way to *see* the map on a terminal without a tty.
    fn dump_ansi(app: &mut App, w: u16, h: u16) -> String {
        use mullion::{Buffer, Rect};
        let mut buf = Buffer::empty(Rect::new(0, 0, w, h));
        screen(&mut buf, app);
        let mut out = String::new();
        for y in 0..h {
            for x in 0..w {
                let cell = buf.get(x, y);
                out.push_str(&format!("\x1b[0;{};{}m", sgr(cell.style.fg, false), sgr(cell.style.bg, true)));
                out.push_str(if cell.symbol.is_empty() { " " } else { &cell.symbol });
            }
            out.push_str("\x1b[0m\n");
        }
        out
    }

    /// Dump the occupancy-coloured map. Ignored by default (writes escape codes to stdout); run
    /// with `cargo test --bin canopy map::tests::dump_map -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_map() {
        let (range, facts) = crate::fixture::demo();
        let mut app = App::new(range, facts, false, false, false, crate::config::Config::default());
        app.view = super::super::app::View::Map;
        println!("{}", dump_ansi(&mut app, 96, 48));
    }

    /// Dump the **group-identity**-coloured map (`g` mode): each logical group's stable hue.
    /// Run with `cargo test --bin canopy map::tests::dump_groups -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_groups() {
        let (range, facts) = crate::fixture::demo();
        let mut app = App::new(range, facts, false, false, false, crate::config::Config::default());
        app.view = super::super::app::View::Map;
        app.color_by_group = true;
        println!("{}", dump_ansi(&mut app, 96, 48));
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
