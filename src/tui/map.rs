// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The IP-map view: the range laid on a **generalized-Hilbert (Gilbert) curve** as a grid of
//! little cells sized so **every cell covers the same power-of-two number of addresses** (1, 2,
//! 4, 8, …). The grid's cell count is a power of two that divides the range, so each cell is a
//! clean, aligned sub-block rather than a ragged slice (see [`mullion::curve_map::fit_dims`]). Built from
//! [`crate::map::MapGrid`] each frame (`O(width·height + facts)`), so a `/8` maps as cheaply as a
//! `/24`. The legend labels the grid structure — dimensions, per-cell address count, and the
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

use mullion::border::{BorderStyle, CornerStyle, LineWeight};
use mullion::curve_map;
use mullion::style::{Color, Style};
use mullion::{Buffer, Rect};

use super::app::App;
use super::draw::{btxt, keyhints};
use super::palette::{Knobs, Scheme, KNOBS};
use super::theme::{s_accent, s_dim, s_sel, s_title};
use crate::map::MapGrid;
use crate::reconcile::{self, AddrRange, AddressFacts, Subnet};

// The Gilbert grid geometry — cell sizing, the rounded curve glyphs, and the per-cell paint
// loop — now lives in [`mullion::curve_map`]; this view only supplies what a cell *means*
// (its address slice and occupancy) as colours.

/// The group treatment for cell `d` when colouring by **group identity**: the [`Look`] of the
/// logical group that owns an address in the cell (its shared hue/saturation and whether it
/// animates) plus the cell's occupancy fraction. `None` when the cell holds no grouped address
/// (the caller then keeps the occupancy colour, which leaves empty space at the terminal default).
///
/// A coarse cell can span several groups; it takes the first grouped member in address order —
/// enough to show a cluster's extent, and exact once zoomed to leaf cells.
fn group_look_at(app: &App, grid: &MapGrid, d: usize) -> Option<(crate::group::Look, f32)> {
    let cr = grid.cell_range(d);
    let mut grouped: Vec<_> = app.facts.values().filter(|f| cr.contains(f.addr)).collect();
    grouped.sort_by_key(|f| f.addr);
    let g = grouped.iter().find_map(|f| app.grouping.group_of(f.addr))?;
    Some((app.grouping.look(&g.id), grid.fraction(d).clamp(0.0, 1.0)))
}

/// Paint one animated cluster cell as a **coloured-square bitstream** using mullion's surf-field
/// [`FlowStyle`](mullion::FlowStyle) `stream_color` (the technique the `spiral_stress` demo
/// pioneered): the group's `band` gives a golden-angle-distinct base hue, the hue streams along
/// the curve position `pos` and scrolls with the clock `t`, and `active` (the cell is occupied —
/// a *set bit* in the stream) makes it glow while empty cells recede. Both of the cell's columns
/// are filled with a solid block so the cluster reads as a run of flowing little squares. The
/// map cursor is drawn as a later overlay, so it still shows on top of a bitstream cell.
fn paint_bitstream(buf: &mut Buffer, x: u16, y: u16, band: usize, pos: f32, t: f32, active: bool) {
    let style = mullion::FlowStyle { band, ..Default::default() }.color(pos, t, active);
    buf.set_char(x, y, '█', style);
    buf.set_char(x + 1, y, '█', style);
}

/// Scale an RGB colour's luma by `f` (clamped), for the chooser's pulse glow. A non-RGB colour
/// (e.g. the terminal-default `Reset` background of empty space) is left untouched.
fn boost(c: Color, f: f32) -> Color {
    match c {
        Color::Rgb(r, g, b) => {
            let s = |v: u8| (f32::from(v) * f).round().clamp(0.0, 255.0) as u8;
            Color::Rgb(s(r), s(g), s(b))
        }
        other => other,
    }
}

/// Draw a rounded boundary around the subnet the cursor sits in. Membership is by **most-specific**
/// subnet, so a cell belongs to exactly one region and only that one subnet is outlined — no
/// doubled edges between neighbours. `mullion::curve_map::draw_region_outline` traces the ring
/// just outside the region; a subnet covering the whole view has its ring off-screen (no line).
fn draw_subnet_outline(buf: &mut Buffer, body: Rect, grid: &MapGrid, app: &App) {
    let Some(cur_d) = grid.xy_to_d(app.map_cur.0, app.map_cur.1) else { return };
    let base = grid.cell_range(cur_d as usize).base();
    let Some(target) = Subnet::most_specific(&app.subnets, base).map(|s| s.cidr) else { return };

    // Which most-specific subnet the map cell under screen `(sx, sy)` belongs to — both columns of
    // a 2-wide cell map to the same grid cell, so the region is a clean 2-column-per-cell shape.
    let inside = |sx: u16, sy: u16| -> bool {
        if sx < body.x || sy < body.y {
            return false;
        }
        let (gx, gy) = ((sx - body.x) / 2, sy - body.y);
        match grid.xy_to_d(u32::from(gx), u32::from(gy)) {
            Some(d) => {
                let b = grid.cell_range(d as usize).base();
                Subnet::most_specific(&app.subnets, b).map(|s| s.cidr) == Some(target)
            }
            None => false,
        }
    };
    let style = BorderStyle { weight: LineWeight::Light, corners: CornerStyle::Rounded, style: s_accent() };
    curve_map::draw_region_outline(buf, body, inside, &style);
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

    let (gw, gh) = curve_map::fit_dims(body, app.range.block_len());
    let grid = MapGrid::build(app.range, &app.facts, gw, gh);
    let used_total: u32 = grid.used.iter().sum();

    // Sync the app's cursor state to this frame's grid: the dims set what `Enter` zooms
    // into, and a shrunk terminal may need the cursor clamped back in-bounds.
    app.map_dims = (grid.width, grid.height);
    app.map_area = body; // remember the grid's screen rect so the mouse can hit-test cells
    app.map_cur = (app.map_cur.0.min(grid.width.saturating_sub(1)), app.map_cur.1.min(grid.height.saturating_sub(1)));

    // Row 0 — grid structure + density key (a Gilbert curve has no meaningful linear axis).
    // The grid is sized so cells() divides the block evenly, so every cell holds exactly this
    // power-of-two address count.
    let cell_addrs = grid.range.block_len() / grid.cells().max(1) as u128;
    let head = format!(
        "Gilbert · {gw}×{gh} · cell = {cell_addrs} addrs · {used_total} used / {} total   ",
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

    // The Gilbert grid. mullion's `curve_map::render` owns the geometry — it draws each cell's
    // segment of the curve with our per-cell `(fg, bg)`; this view only decides the colour.
    // `clock` (seconds since start) animates the cluster bitstream; the loop ticks ~20×/s.
    let clock = app.anim_t();
    let total = grid.cells();

    // The group treatment per cell, computed once (each lookup scans the facts). `None` when not
    // in group mode or the cell has no group; an animated group is overdrawn as a bitstream below.
    let group_cells: Vec<Option<(crate::group::Look, f32)>> =
        if app.color_by_group { (0..total).map(|d| group_look_at(app, &grid, d)).collect() } else { Vec::new() };

    // Quadrant chooser: the selected sub-block's curve luma-pulses, tapering to nothing at the
    // joins so there is no seam with its neighbours (mullion's `pulse_segment`).
    let pulse = app.chooser.and_then(|i| {
        grid.gilbert().subblocks().get(i).map(|sb| curve_map::pulse_segment(total, sb.d_range.clone(), clock, 3))
    });

    // Base layer: occupancy heat, or a quiet static tint for a non-animated group, then the
    // chooser pulse boosts the selected sub-block's luma.
    curve_map::render(buf, body, grid.gilbert(), |d| {
        let pos = if total > 1 { d as f32 / (total - 1) as f32 } else { 0.0 };
        let (bg, fg) = app.scheme.paint(grid.fraction(d), pos, &app.knobs);
        let (mut fg, mut bg) = match group_cells.get(d) {
            Some(Some((look, occ))) if !look.animate => (fg, super::palette::hsl_rgb(look.hue, look.sat, 0.16 + 0.30 * occ)),
            _ => (fg, bg), // curve_map wants (fg, bg); Scheme::paint yields (bg, fg)
        };
        if let Some(p) = &pulse {
            let g = p(d);
            if g > 0.0 {
                (fg, bg) = (boost(fg, 1.0 + g), boost(bg, 1.0 + g));
            }
        }
        (fg, bg)
    });

    // Overlay: animated clusters/services as the flowing coloured-square bitstream.
    for d in 0..total {
        if let Some(Some((look, occ))) = group_cells.get(d) {
            if look.animate {
                let (gx, gy) = grid.cell_xy(d);
                let (x, y) = (body.x + (gx as u16) * 2, body.y + gy as u16);
                if x + 1 < body.x + body.width && y < body.y + body.height {
                    let pos = if total > 1 { d as f32 / (total - 1) as f32 } else { 0.0 };
                    paint_bitstream(buf, x, y, look.band, pos, clock, *occ > 0.0);
                }
            }
        }
    }

    // Overlay: the cursor cell, always on top so it stays findable.
    if let Some(cd) = grid.xy_to_d(app.map_cur.0, app.map_cur.1) {
        let (gx, gy) = grid.cell_xy(cd as usize);
        let (x, y) = (body.x + (gx as u16) * 2, body.y + gy as u16);
        if x + 1 < body.x + body.width && y < body.y + body.height {
            buf.set_char(x, y, curve_map::cell_glyph(grid.gilbert(), cd as usize), s_sel());
            buf.set_char(x + 1, y, ' ', s_sel());
        }
    }

    // Subnet boundary: a rounded outline around the subnet under the cursor (mullion's region
    // outline), a frame we can later hang VLAN/subnet info on.
    if app.show_subnets {
        draw_subnet_outline(buf, body, &grid, app);
    }

    // Footer key hints — context-aware: the quadrant chooser has its own bindings.
    let hints: &[(&str, &str)] = if app.chooser.is_some() {
        &[("hjkl", "quadrant"), ("↵", "zoom in"), ("z", "cells"), ("Bksp", "out"), ("q", "quit")]
    } else if zoomable {
        &[("hl", "walk"), ("kj", "leap"), ("nf", "occ/free"), ("↵", "in"), ("z", "quadrant"), ("g", "groups"), ("b", "subnets"), ("q", "quit")]
    } else {
        &[("p", "palette"), ("g", "groups"), ("b", "subnets"), (", .", "tune"), ("Tab", "table"), ("q", "quit")]
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

    /// Dump the **quadrant chooser** over a larger range: a sub-block selected, its curve
    /// luma-pulsing seam-free across 12 frames. Run with
    /// `cargo test --bin canopy map::tests::dump_chooser -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_chooser() {
        use crate::reconcile::Cidr;
        let range = Cidr::parse("10.87.0.0/18").unwrap();
        let mut app = App::new(range, Vec::new(), false, false, false, crate::config::Config::default());
        app.view = super::super::app::View::Map;
        // Render once to fix map_dims, then enter the chooser and select a middle sub-block.
        let _ = dump_ansi(&mut app, 96, 48);
        app.on_key(mullion::KeyCode::Char('z'));
        app.on_key(mullion::KeyCode::Char('l'));
        let frames = 12;
        for i in 0..frames {
            let t = i as f32 / frames as f32 * (std::f32::consts::TAU);
            app.set_anim_clock(Some(t));
            println!("@@@FRAME {i}@@@");
            println!("{}", dump_ansi(&mut app, 96, 48));
        }
    }

    /// Dump the **group-identity**-coloured map (`g` mode): each logical group's stable hue, with
    /// clusters as the animated coloured-square bitstream. Emits several frames across the
    /// animation cycle (separated by `@@@FRAME t@@@` markers) so a viewer can replay the motion.
    /// Run with `cargo test --bin canopy map::tests::dump_groups -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_groups() {
        let (range, facts) = crate::fixture::demo();
        let mut app = App::new(range, facts, false, false, false, crate::config::Config::default());
        app.view = super::super::app::View::Map;
        app.color_by_group = true;
        // 12 frames over one wave period (2π / speed 3.0 ≈ 2.09s) → a smooth loop.
        let frames = 12;
        for i in 0..frames {
            let t = i as f32 / frames as f32 * (std::f32::consts::TAU / 3.0);
            app.set_anim_clock(Some(t));
            println!("@@@FRAME {i}@@@");
            println!("{}", dump_ansi(&mut app, 96, 48));
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
