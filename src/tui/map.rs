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

use mullion::border::{BorderStyle, CornerStyle, LineWeight};
use mullion::curve_map;
use mullion::style::Color;
use mullion::{Buffer, Rect};

use super::app::App;
use super::draw::{btxt, keyhints};
use super::palette::KNOBS;
use super::theme::{s_accent, s_dim, s_title};
use crate::map::MapGrid;
use crate::reconcile::{AddrRange, Subnet};

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

/// Per-cell bitstream assignment for the animated groups: `Some((band, active))` for a cell that
/// is part of an animated group's **curve span**, `None` otherwise. A cell holding a member is a
/// lit bit (`active`); an empty gap *between* members of the same cluster (within its
/// `[min_d, max_d]` span on the curve) is a dim bit — so a cluster reads as a run of set/unset
/// squares (the vision-doc bitstream), not just isolated dots.
///
/// Members always win over gap-fill, and a gap is only filled if the cell is empty and not
/// already claimed — so one cluster's span never clobbers another group's cells. `O(members +
/// spans)`, small.
fn bitstream_cells(app: &App, grid: &MapGrid) -> Vec<Option<(usize, bool)>> {
    let total = grid.cells();
    let mut out = vec![None; total];
    let cells = total as u128;
    // The member cells of each animated group, as curve indices in the current view.
    let member_ds = |g: &crate::group::Group| -> Vec<usize> {
        let mut ds: Vec<usize> = g
            .members
            .iter()
            .filter_map(|m| m.addr)
            .filter_map(|a| grid.range.offset_of(a).map(|off| grid.range.slice_index(cells, off) as usize))
            .collect();
        ds.sort_unstable();
        ds.dedup();
        ds
    };
    // Pass 1: every animated member is a lit bit (members always win).
    for g in &app.grouping.groups {
        if app.grouping.look(&g.id).animate {
            let band = app.grouping.look(&g.id).band;
            for d in member_ds(g) {
                out[d] = Some((band, true));
            }
        }
    }
    // Pass 2: fill each animated group's span gaps (empty, unclaimed cells) as dim bits.
    for g in &app.grouping.groups {
        if !app.grouping.look(&g.id).animate {
            continue;
        }
        let ds = member_ds(g);
        let (Some(&lo), Some(&hi)) = (ds.first(), ds.last()) else { continue };
        let band = app.grouping.look(&g.id).band;
        for d in lo..=hi {
            if out[d].is_none() && grid.used[d] == 0 {
                out[d] = Some((band, false));
            }
        }
    }
    out
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

/// Blend a colour `amount` (0..1) of the way toward **yellow** — the selected-quadrant pulse.
/// A non-RGB colour (the terminal-default `Reset` of empty cells) is treated as black, so an
/// empty cell in the selected quadrant glows a dim, pulsing yellow rather than staying blank.
fn toward_yellow(c: Color, amount: f32) -> Color {
    let a = amount.clamp(0.0, 1.0);
    let (r0, g0, b0) = match c {
        Color::Rgb(r, g, b) => (r, g, b),
        _ => (0, 0, 0),
    };
    let lerp = |v: u8, t: u8| (f32::from(v) + (f32::from(t) - f32::from(v)) * a).round() as u8;
    Color::Rgb(lerp(r0, 255), lerp(g0, 255), lerp(b0, 0))
}

/// Draw the information pane beside the Gilbert square (text left-aligned to the square, no
/// divider): VIEW, PATH, SUBNET, QUADRANT, then a scrollable host list. The palette lives in the
/// square's edge, not here.
fn draw_info_pane(buf: &mut Buffer, pane: Rect, app: &App, grid: &MapGrid, quads: &[(std::ops::Range<usize>, Rect)], used_total: u32) {
    let (x, w, bottom) = (pane.x, pane.width, pane.y + pane.height);
    let mut y = pane.y;
    let line = |buf: &mut Buffer, y: &mut u16, text: &str, style| {
        if *y < bottom {
            btxt(buf, x, *y, &clip(text, w), style);
        }
        *y += 1;
    };

    let addrs = grid.range.block_len();
    let cell_addrs = addrs / grid.cells().max(1) as u128;
    line(buf, &mut y, "VIEW", s_title());
    line(buf, &mut y, &app.range.label(), s_accent());
    line(buf, &mut y, &format!("{used_total} used / {addrs} addr · {}/cell", cell_addrs), s_dim());
    y += 1;

    line(buf, &mut y, "PATH", s_title());
    line(buf, &mut y, &app.scope_chain().iter().map(mullion_label).collect::<Vec<_>>().join(" › "), s_dim());
    y += 1;

    if let Some(s) = Subnet::most_specific(&app.subnets, app.range.base()) {
        line(buf, &mut y, "SUBNET", s_title());
        let name = if s.name.is_empty() { String::new() } else { format!(" {}", s.name) };
        line(buf, &mut y, &format!("{}/{}{name}", s.cidr.base, s.cidr.prefix_len), s_dim());
        y += 1;
    }

    if let Some((dr, _)) = quads.get(app.zoom_sel) {
        let q = grid.range.span_slices(grid.cells() as u128, dr.start as u128, dr.end as u128);
        let used: u32 = (dr.start..dr.end).filter_map(|d| grid.used.get(d)).sum();
        line(buf, &mut y, &format!("QUADRANT {}/{}", app.zoom_sel + 1, quads.len()), s_title());
        line(buf, &mut y, &q.label(), s_accent());
        line(buf, &mut y, &format!("{} used{}", used, if app.can_zoom_in() { "" } else { " · max zoom" }), s_dim());
        y += 1;
    }

    // The scrollable, paginated host list — only the visible window is drawn, so it is instant
    // even over a huge range (it lists the bounded known hosts, never the address space).
    let hosts = app.hosts_in_view();
    let rows = (bottom.saturating_sub(y + 1)) as usize; // leave the header row
    let scroll = app.host_scroll.min(hosts.len().saturating_sub(1));
    let more = hosts.len().saturating_sub(scroll + rows);
    let label = if more > 0 { format!("HOSTS {}-{}/{} ↕", scroll + 1, scroll + rows.min(hosts.len() - scroll), hosts.len()) } else { format!("HOSTS ({})", hosts.len()) };
    line(buf, &mut y, &label, s_title());
    for (addr, name) in hosts.iter().skip(scroll).take(rows) {
        line(buf, &mut y, &format!("{addr}  {name}"), s_dim());
    }
}

/// A range's short label — a free function so it can be used in an iterator map.
fn mullion_label(r: &AddrRange) -> String {
    r.label()
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


/// Clip `text` to at most `w` columns (so an info line never overruns the screen).
fn clip(text: &str, w: u16) -> String {
    text.chars().take(w as usize).collect()
}

/// Paint the map view (zoom mode) for the current [`App`] state.
pub fn screen(buf: &mut Buffer, app: &mut App) {
    let full = buf.area;
    if full.width < 26 || full.height < 8 {
        return;
    }

    // ── frame (title + data badge in the border) ──
    let title = format!("canopy — map: {}", app.range.label());
    let prog = app.progress.as_ref().map(|(f, l)| (*f, l.as_str()));
    let area = super::draw::frame(buf, full, &title, s_title(), Some(super::draw::data_badge(app)), prog, &app.heartbeat());
    let foot_y = area.y + area.height - 1;

    // Layout: the Gilbert square (with a rounded edge) hugs the left; the info pane follows its
    // right edge with a couple of columns' gap. The square is bound by the available *height* (so
    // it stays square-ish and does not eat the width), leaving the rest for the pane.
    let inner = Rect::new(area.x + 1, area.y + 1, area.width.saturating_sub(2), area.height.saturating_sub(3));
    let sq_region = Rect::new(inner.x, inner.y, inner.width.min(inner.height * 2 + 2), inner.height);
    let (gw, gh) = curve_map::fit_dims(sq_region, app.range.block_len());
    let grid = MapGrid::build(app.range, &app.facts, gw, gh);
    let body = Rect::new(inner.x, inner.y, (gw as u16) * 2, gh as u16);
    let used_total: u32 = grid.used.iter().sum();

    app.map_dims = (grid.width, grid.height);
    app.map_area = body;
    let quads = app.map_quadrants();
    app.zoom_sel = app.zoom_sel.min(quads.len().saturating_sub(1));
    // Keep the vestigial cell cursor on the selected quadrant's corner (used by the subnet outline).
    app.map_cur = quads.get(app.zoom_sel).map_or((0, 0), |(_, b)| (u32::from(b.x), u32::from(b.y)));

    let clock = app.anim_t();
    let total = grid.cells();

    let group_cells: Vec<Option<(crate::group::Look, f32)>> =
        if app.color_by_group { (0..total).map(|d| group_look_at(app, &grid, d)).collect() } else { Vec::new() };

    // The selected quadrant's curve pulses **toward yellow at 2 Hz** (`t = clock·4π`, since the
    // pulse period is 2π in `t`), tapering to nothing at the joins so there is no seam.
    let pulse = quads
        .get(app.zoom_sel)
        .map(|(dr, _)| curve_map::pulse_segment(total, dr.clone(), clock * 4.0 * std::f32::consts::PI, 3));

    // Base layer: occupancy heat / static group tint, then the quadrant pulse blends toward yellow.
    curve_map::render(buf, body, grid.gilbert(), |d| {
        let pos = if total > 1 { d as f32 / (total - 1) as f32 } else { 0.0 };
        let (bg, fg) = app.scheme.paint(grid.fraction(d), pos, &app.knobs);
        let (mut fg, bg) = match group_cells.get(d) {
            Some(Some((look, occ))) if !look.animate => (fg, super::palette::hsl_rgb(look.hue, look.sat, 0.16 + 0.30 * occ)),
            _ => (fg, bg), // curve_map wants (fg, bg); Scheme::paint yields (bg, fg)
        };
        // The selected quadrant flashes the **curve** toward yellow — the background is left alone.
        if let Some(p) = &pulse {
            let a = p(d) * 0.9;
            if a > 0.0 {
                fg = toward_yellow(fg, a);
            }
        }
        (fg, bg)
    });

    // Overlay: animated clusters as the flowing bitstream (span-filled: members lit, gaps dim).
    if app.color_by_group {
        let bits = bitstream_cells(app, &grid);
        for (d, cell) in bits.iter().enumerate() {
            if let Some((band, active)) = *cell {
                let (gx, gy) = grid.cell_xy(d);
                let (x, y) = (body.x + (gx as u16) * 2, body.y + gy as u16);
                if x + 1 < body.x + body.width && y < body.y + body.height {
                    let pos = if total > 1 { d as f32 / (total - 1) as f32 } else { 0.0 };
                    paint_bitstream(buf, x, y, band, pos, clock, active);
                }
            }
        }
    }

    if app.show_subnets {
        draw_subnet_outline(buf, body, &grid, app);
    }

    // The rounded edge around the whole Gilbert square (a frame for zoom animation + info later).
    let edge = Rect::new(body.x.saturating_sub(1), body.y.saturating_sub(1), body.width + 2, body.height + 2);
    let estyle = BorderStyle { weight: LineWeight::Light, corners: CornerStyle::Rounded, style: s_dim() };
    mullion::border::draw_box(buf, edge, mullion::border::Borders::ALL, &estyle);

    // The palette menu lives in a gap in the square's bottom edge — `┤ scheme · knob=val ├`.
    let (kn, ..) = KNOBS[app.active_knob];
    let palette = format!("┤ {} · {}={:.2} ├", app.scheme.name(), kn, app.knobs.get(app.active_knob));
    btxt(buf, edge.x + 2, edge.y + edge.height - 1, &clip(&palette, edge.width.saturating_sub(4)), s_dim());

    // The information pane, hugging the square's right edge with a two-column gap (no divider).
    let pane_x = edge.x + edge.width + 2;
    let pane = Rect::new(pane_x, area.y, (area.x + area.width).saturating_sub(pane_x), area.height.saturating_sub(1));
    app.pane_area = pane;
    if pane.width >= 20 {
        draw_info_pane(buf, pane, app, &grid, &quads, used_total);
    }

    let hints: &[(&str, &str)] =
        &[("← ↑ ↓ →", "quadrant"), ("↵/click", "zoom in"), ("Esc/rclick", "out"), ("g", "groups"), ("b", "subnets"), ("q", "quit")];
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

    /// Span-fill: a cluster's members are lit bits and the empty gaps within its curve span are
    /// dim bits, so the bitstream covers more cells than just the members.
    #[test]
    fn bitstream_span_fills_gaps_between_members() {
        use crate::reconcile::Cidr;
        // Three cluster members spread across the /24 so their span has empty cells between them.
        let ptr = |o: u8| crate::reconcile::AddressFacts {
            addr: format!("10.87.3.{o}").parse().unwrap(),
            netbox: None,
            ptr: Some(format!("netapp-dw{o}-bmc.nfra.nl.")),
            live: true,
        };
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let mut app = App::new(range, vec![ptr(10), ptr(40), ptr(200)], false, false, false, crate::config::Config::default());
        app.view = super::super::app::View::Map;
        app.color_by_group = true;
        let mut buf = Buffer::empty(Rect::new(0, 0, 96, 48));
        screen(&mut buf, &mut app);
        let (w, h) = app.map_dims;
        let grid = MapGrid::build(app.range, &app.facts, w, h);

        let bits = bitstream_cells(&app, &grid);
        let lit = bits.iter().filter(|c| matches!(c, Some((_, true)))).count();
        let dim = bits.iter().filter(|c| matches!(c, Some((_, false)))).count();
        assert_eq!(lit, 3, "the three members are lit bits");
        assert!(dim > 0, "gaps within the cluster's span are dim bits (span-fill)");
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

    /// Dump the **zoom-mode** view over a `/16`: four quadrants, one selected and pulsing toward
    /// yellow, the rounded edge, and the info pane — across 12 frames of the 2 Hz pulse. Run with
    /// `cargo test --bin canopy map::tests::dump_zoom -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_zoom() {
        use crate::reconcile::Cidr;
        let range = Cidr::parse("145.124.0.0/16").unwrap();
        let mut app = App::new(range, Vec::new(), false, false, false, crate::config::Config::default());
        app.view = super::super::app::View::Map;
        let _ = dump_ansi(&mut app, 100, 40); // fix map_dims
        app.on_key(mullion::KeyCode::Right); // select a non-default quadrant
        let frames = 12;
        for i in 0..frames {
            // One 2 Hz cycle: pulse uses t = clock·4π, so clock spans 0..0.5 s over 12 frames.
            app.set_anim_clock(Some(i as f32 / frames as f32 * 0.5));
            println!("@@@FRAME {i}@@@");
            println!("{}", dump_ansi(&mut app, 100, 40));
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
