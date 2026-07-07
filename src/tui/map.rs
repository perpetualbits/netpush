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

use std::net::IpAddr;

use mullion::border::{BorderStyle, CornerStyle, LineWeight};
use mullion::curve_map;
use mullion::style::{Color, Style};
use mullion::{Buffer, Rect};

use super::app::App;
use super::draw::{btxt, keyhints};
use super::palette::KNOBS;
use super::theme::{s_accent, s_dim, s_sel, s_title};
use crate::map::MapGrid;
use crate::reconcile::{AddrRange, Subnet};

/// How long the zoom edge-sweep animation lasts, in seconds.
const ZOOM_ANIM_SECS: f32 = 0.32;

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
fn paint_bitstream(buf: &mut Buffer, x: u16, y: u16, band: usize, pos: f32, t: f32, active: bool, glow: f32) {
    let mut style = mullion::FlowStyle { band, ..Default::default() }.color(pos, t, active);
    if glow > 0.0 {
        style = style.fg(lighten(style.fg, glow));
    }
    buf.set_char(x, y, '█', style);
    buf.set_char(x + 1, y, '█', style);
}

/// The **hover glow** value per curve cell: a soft gaussian band centred on the synced cell
/// `hover`, fading along the curve (σ ≈ 3 cells) and pulsing gently. `0` everywhere when nothing
/// is hovered. Returned as an owned `Vec` so the render closures can index it cheaply.
fn hover_glow(hover: Option<usize>, total: usize, clock: f32) -> Vec<f32> {
    let Some(hd) = hover else { return Vec::new() };
    // A tight, bright core: a small sigma keeps the beacon focused so raising the amplitude reads as
    // *brighter*, not as a wide white smear — the gaussian falloff still carries the glow's gradient.
    const SIGMA: f32 = 2.4;
    let pulse = 0.85 + 0.15 * (clock * std::f32::consts::TAU * 0.7).sin(); // steadier, so it stays bright
    (0..total)
        .map(|d| {
            let dist = (d as isize - hd as isize).abs() as f32;
            let g = (-(dist * dist) / (2.0 * SIGMA * SIGMA)).exp();
            (g * pulse * 1.7).clamp(0.0, 1.7) // much brighter than the ambient/quadrant lifts
        })
        .collect()
}

/// The **ambient shimmer** per curve cell: a slow, soft travelling light that threads the whole
/// curve when idle and *gathers where the estate has structure* — occupied cells lift far more
/// than empty space — so the shape of the data breathes into view. As if the curve's placement
/// were a projected image, scrolled slowly back into the light. Palette-true and restrained: two
/// slow waves at different rates beat together for a non-repeating sheen, kept low-amplitude.
fn ambient_glow(grid: &MapGrid, total: usize, clock: f32) -> Vec<f32> {
    use std::f32::consts::TAU;
    let denom = total.max(1) as f32;
    (0..total)
        .map(|d| {
            let u = d as f32 / denom; // position along the curve, 0..1
            // Two slow travelling waves (different spatial rates, opposite drift) beat together.
            let a = 0.5 + 0.5 * ((u * 5.0 - clock * 0.11) * TAU).sin();
            let b = 0.5 + 0.5 * ((u * 11.0 + clock * 0.06) * TAU).sin();
            let wave = 0.6 * a + 0.4 * b;
            // A faint sheen everywhere; much brighter where hosts actually live (structure).
            let structure = if grid.used[d] > 0 { 0.55 + 0.45 * grid.fraction(d) } else { 0.12 };
            (wave * structure * 0.5).clamp(0.0, 1.0) // half amplitude — self-assured, not showy
        })
        .collect()
}

/// Brighten an RGB colour by `amount` (0..1) — a luma lift that keeps the hue, so the glow
/// *lifts* each cell's own palette rather than whitening it. Non-RGB colours are untouched.
fn lighten(c: Color, amount: f32) -> Color {
    match c {
        Color::Rgb(r, g, b) => {
            let f = 1.0 + amount.clamp(0.0, 1.7);
            let s = |v: u8| (f32::from(v) * f).round().min(255.0) as u8;
            Color::Rgb(s(r), s(g), s(b))
        }
        other => other,
    }
}

/// The colour a synced host lights up in: the **same hue as its block on the curve**, at full
/// brightness — deliberately *not* the cursor blue, so the name and its cell read as one thing. A
/// host in a group glows in the group's hue; an ungrouped host in a bright warm tone that matches
/// the occupancy heat of the curve.
fn synced_style(app: &App, addr: IpAddr) -> Style {
    let fg = match app.grouping.group_of(addr) {
        Some(g) => {
            let l = app.grouping.look(&g.id);
            super::palette::hsl_rgb(l.hue, l.sat.max(0.55), 0.70)
        }
        None => Color::Rgb(235, 214, 170), // bright warm, matching the occupancy ramp — never blue
    };
    Style::default().fg(fg)
}

/// The compact **two-column field strip** across the top: VIEW + SUBNET in the left column, PATH +
/// QUADRANT in the right. Half the height of the old stacked pane, which is what frees the room for
/// the square and the host list to share a height.
fn draw_fields(buf: &mut Buffer, strip: Rect, app: &App, grid: &MapGrid, quads: &[(std::ops::Range<usize>, Rect)], used_total: u32) {
    let half = strip.width / 2;
    let colw = half.saturating_sub(1);
    let (lx, rx, y0) = (strip.x, strip.x + half, strip.y);
    let put = |buf: &mut Buffer, x: u16, dy: u16, text: &str, st| {
        if y0 + dy < strip.y + strip.height {
            btxt(buf, x, y0 + dy, &clip(text, colw), st);
        }
    };

    // Left column: VIEW, SUBNET.
    let addrs = grid.range.block_len();
    let cell_addrs = addrs / grid.cells().max(1) as u128;
    put(buf, lx, 0, &format!("VIEW  {}", app.range.label()), s_title());
    put(buf, lx, 1, &format!("      {used_total} used / {addrs} · {cell_addrs}/cell"), s_dim());
    if let Some(s) = Subnet::most_specific(&app.subnets, app.range.base()) {
        let name = if s.name.is_empty() { String::new() } else { format!(" {}", s.name) };
        put(buf, lx, 3, &format!("SUBNET  {}/{}{name}", s.cidr.base, s.cidr.prefix_len), s_title());
    }

    // Right column: PATH, QUADRANT.
    put(buf, rx, 0, "PATH", s_title());
    put(buf, rx, 1, &format!("  {}", app.scope_chain().iter().map(mullion_label).collect::<Vec<_>>().join(" › ")), s_dim());
    if let Some((dr, _)) = quads.get(app.zoom_sel) {
        let q = grid.range.span_slices(grid.cells() as u128, dr.start as u128, dr.end as u128);
        let used: u32 = (dr.start..dr.end).filter_map(|d| grid.used.get(d)).sum();
        put(buf, rx, 3, &format!("QUADRANT  {}/{}  {}  {used} used", app.zoom_sel + 1, quads.len(), q.label()), s_title());
    }
}

/// The scrollable, paginated **host list** — an outlined box with a mullion scrollbar; a host in
/// the synced cell lights up (the hover sync). Lazy: only the visible window is drawn, so it is
/// instant even over a huge range (it lists the bounded known hosts, never the address space).
/// Any family shows — a v6 address prints and syncs exactly like a v4 one. Returns its rows
/// rectangle, so a pointer over a name maps back to its curve cell (reciprocal sync).
fn draw_host_list(buf: &mut Buffer, list_box: Rect, app: &App) -> Rect {
    if list_box.height < 3 || list_box.width < 8 {
        return Rect::new(0, 0, 0, 0);
    }
    let hosts = app.hosts_in_view();
    let bstyle = BorderStyle { weight: LineWeight::Light, corners: CornerStyle::Rounded, style: s_dim() };
    mullion::border::draw_box(buf, list_box, mullion::border::Borders::ALL, &bstyle);
    let rows = list_box.height.saturating_sub(2) as usize; // inside the top/bottom border
    let text_w = list_box.width.saturating_sub(3); // a border each side + a scrollbar column
    let scroll = app.host_scroll.min(hosts.len().saturating_sub(1));
    let shown = rows.min(hosts.len().saturating_sub(scroll));
    // The count sits in a gap in the box's top edge, like the palette on the square.
    let label = format!("┤ hosts {}–{}/{} ├", (scroll + 1).min(hosts.len().max(1)), scroll + shown, hosts.len());
    btxt(buf, list_box.x + 2, list_box.y, &clip(&label, list_box.width.saturating_sub(4)), s_dim());
    for (i, (addr, name)) in hosts.iter().skip(scroll).take(rows).enumerate() {
        let synced = app.hover_d.is_some() && app.cell_of_addr(*addr) == app.hover_d;
        let style = if synced { synced_style(app, *addr) } else { s_dim() };
        btxt(buf, list_box.x + 1, list_box.y + 1 + i as u16, &clip(&format!("{addr}  {name}"), text_w), style);
    }
    // A scrollbar on the right inside edge shows where the window sits in the whole list.
    let track = Rect::new(list_box.x + list_box.width - 1, list_box.y + 1, 1, rows as u16);
    mullion::render_scrollbar(buf, track, mullion::ScrollMetrics::from_window(scroll, rows, hosts.len()), s_dim());
    Rect::new(list_box.x + 1, list_box.y + 1, text_w, shown as u16)
}

/// A range's short label — a free function so it can be used in an iterator map.
fn mullion_label(r: &AddrRange) -> String {
    r.label()
}

/// Draw the lasso **callout** over the live map: the rounded ring around the selected snake, a
/// leader wire routed to a floating box with the summary lines, all composited by mullion as
/// marching-ants so the occupancy shows through the chrome. canopy owns the selection membership
/// (`inside`), the anchor (the moving head), the box placement, and the lines; mullion draws it.
fn draw_lasso_callout(buf: &mut Buffer, body: Rect, grid: &MapGrid, app: &App, clock: f32) {
    let Some((lo, hi)) = app.lasso_dspan() else { return };
    let Some(summary) = app.lasso_summary() else { return };

    // Selection membership by screen cell — two columns map to one grid cell (mirrors the subnet
    // outline), so the region is a clean 2-column-per-cell shape.
    let inside = |sx: u16, sy: u16| -> bool {
        if sx < body.x || sy < body.y {
            return false;
        }
        let (gx, gy) = ((sx - body.x) / 2, sy - body.y);
        grid.xy_to_d(u32::from(gx), u32::from(gy)).is_some_and(|d| (lo..=hi).contains(&(d as usize)))
    };

    // Anchor the leader at the moving head cell — where the eye is.
    let head = app.lasso.map_or(hi, |l| l.head).min(grid.cells().saturating_sub(1));
    let (hx, hy) = grid.cell_xy(head);
    let anchor = (body.x + hx as u16 * 2, body.y + hy as u16);

    // Place the box top-right of the body, sized to its lines (v1: canopy places, mullion routes).
    let lines = summary.lines();
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let longest = refs.iter().map(|s| s.chars().count()).max().unwrap_or(0) as u16;
    let bw = (longest + 2).clamp(12, body.width.max(12)).min(body.width);
    let bh = (refs.len() as u16 + 2).min(body.height.max(3));
    let box_rect = Rect::new((body.x + body.width).saturating_sub(bw), body.y, bw, bh);

    let style = BorderStyle { weight: LineWeight::Light, corners: CornerStyle::Rounded, style: s_sel() };
    curve_map::callout(buf, body, inside, anchor, box_rect, &refs, &style, clock, curve_map::CalloutDuty::default());
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

    // Layout: a compact two-column field strip at the top; below it the Gilbert square (left,
    // rounded edge) and the host list (right) share the same top and height, so their bases line
    // up. Compacting the fields is what frees the vertical room for the two to match.
    let fields_h: u16 = 5.min(area.height.saturating_sub(6));
    let fields = Rect::new(area.x + 1, area.y, area.width.saturating_sub(2), fields_h);
    let content_top = area.y + fields_h;
    let content_h = foot_y.saturating_sub(content_top); // rows for square + scroller (above footer)

    // Fit the square to the content height (square-ish, height-bound). Its edge and the host-list
    // box then share `content_top` and the fitted height.
    let sq_region = Rect::new(area.x + 2, content_top + 1, content_h.saturating_mul(2), content_h.saturating_sub(2));
    let (gw, gh) = curve_map::fit_dims(sq_region, app.range.block_len());
    let grid = MapGrid::build(app.range, &app.facts, gw, gh);
    let edge = Rect::new(area.x + 1, content_top, gw as u16 * 2 + 2, gh as u16 + 2);
    let body = Rect::new(edge.x + 1, edge.y + 1, gw as u16 * 2, gh as u16);
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

    // The curve's light — all soft *lifts*, never a hard flash, combined into one gentle luma
    // boost per cell:
    //  · the selected quadrant: a slow glow (~0.4 Hz), seam-free at the joins — a calm shimmer,
    //    not the old 2 Hz flash;
    //  · pointing: a focused gaussian band on the synced cell (hover sync);
    //  · idle: a slow ambient shimmer, gathering where the estate has structure.
    // Each lifts a cell's own colour rather than whitening it, so the light stays multicoloured.
    let qglow = quads
        .get(app.zoom_sel)
        .map(|(dr, _)| curve_map::pulse_segment(total, dr.clone(), clock * std::f32::consts::TAU * 0.4, 4));
    let hovering = app.hover_d.is_some();
    let ambient = match app.hover_d {
        Some(hd) => hover_glow(Some(hd), total, clock),
        None => ambient_glow(&grid, total, clock),
    };
    // The lasso selection breathes *solidly* (colour channel; the curve glyph stays put) — the
    // agreed split where the selection glows and only the callout chrome dithers.
    let lasso_span = app.lasso_dspan();
    let lasso_glow = lasso_span.map(|(lo, hi)| curve_map::pulse_segment(total, lo..hi + 1, clock * std::f32::consts::TAU * 0.3, 3));
    // The hover beacon / selection glow burn brighter than the idle shimmer's restrained ceiling.
    let cap = if hovering || lasso_span.is_some() { 1.7 } else { 0.85 };
    let lift: Vec<f32> = (0..total)
        .map(|d| {
            let base = ambient.get(d).copied().unwrap_or(0.0);
            let q = qglow.as_ref().map_or(0.0, |p| p(d) * 0.5);
            let ls = lasso_glow.as_ref().map_or(0.0, |p| p(d) * 0.9); // self-assured, near-solid
            (base + q + ls).min(cap)
        })
        .collect();

    // Base layer: occupancy heat / static group tint, lifted by the combined light.
    curve_map::render(buf, body, grid.gilbert(), |d| {
        let pos = if total > 1 { d as f32 / (total - 1) as f32 } else { 0.0 };
        let (bg, fg) = app.scheme.paint(grid.fraction(d), pos, &app.knobs);
        let (mut fg, bg) = match group_cells.get(d) {
            Some(Some((look, occ))) if !look.animate => (fg, super::palette::hsl_rgb(look.hue, look.sat, 0.16 + 0.30 * occ)),
            _ => (fg, bg), // curve_map wants (fg, bg); Scheme::paint yields (bg, fg)
        };
        fg = lighten(fg, lift[d]);
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
                    paint_bitstream(buf, x, y, band, pos, clock, active, lift[d]);
                }
            }
        }
    }

    if app.show_subnets {
        draw_subnet_outline(buf, body, &grid, app);
    }

    // The rounded edge around the whole Gilbert square (a frame for the zoom sweep + palette).
    let estyle = BorderStyle { weight: LineWeight::Light, corners: CornerStyle::Rounded, style: s_dim() };
    mullion::border::draw_box(buf, edge, mullion::border::Borders::ALL, &estyle);

    // A zoom sweep in flight: the selected quadrant's edge grows to fill the square (zoom-in) or
    // shrinks back onto its slot (zoom-out), eased with mullion's `smoothstep`/`lerp_rect`. Drawn
    // bright, over the static edge; on completion `advance_zoom_anim` commits the scope change.
    if let Some(rect) = app.advance_zoom_anim(clock, edge, ZOOM_ANIM_SECS) {
        let sweep = BorderStyle { weight: LineWeight::Light, corners: CornerStyle::Rounded, style: s_sel() };
        mullion::border::draw_box(buf, rect, mullion::border::Borders::ALL, &sweep);
    }

    // The palette menu lives in a gap in the square's bottom edge — `┤ scheme · knob=val ├`.
    let (kn, ..) = KNOBS[app.active_knob];
    let palette = format!("┤ {} · {}={:.2} ├", app.scheme.name(), kn, app.knobs.get(app.active_knob));
    btxt(buf, edge.x + 2, edge.y + edge.height - 1, &clip(&palette, edge.width.saturating_sub(4)), s_dim());

    // The host list: same top and height as the square's edge, to its right — bases level.
    let list_x = edge.x + edge.width + 2;
    let list_box = Rect::new(list_x, edge.y, (area.x + area.width).saturating_sub(list_x), edge.height);
    app.pane_area = list_box;
    // Bring the hovered cell's hosts to the top of the list before painting — "they scroll to you".
    app.ease_hosts_to_hover(list_box.height.saturating_sub(2) as usize);
    app.host_list_area = if list_box.width >= 16 { draw_host_list(buf, list_box, app) } else { Rect::new(0, 0, 0, 0) };

    // The two-column field strip across the top.
    draw_fields(buf, fields, app, &grid, &quads, used_total);

    // The lasso callout — ring + routed leader + floating box — composited over the live map by
    // mullion as marching-ants, so the map breathes through the chrome (labels stay opaque). Drawn
    // last so it sits over everything in the body.
    if app.lasso.is_some() {
        draw_lasso_callout(buf, body, &grid, app, clock);
    }

    let hints: &[(&str, &str)] = if app.lasso.is_some() {
        &[("← ↑ ↓ →", "stretch"), ("s", "snap"), ("l/Esc", "done"), ("q", "quit")]
    } else {
        &[("← ↑ ↓ →", "quadrant"), ("↵/click", "zoom"), ("Esc", "out"), ("l", "lasso"), ("g", "groups"), ("q", "quit")]
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

    /// Dump the **ambient shimmer**: the idle map (no hover) breathing over one slow travelling
    /// cycle. Run with `cargo test --bin canopy map::tests::dump_ambient -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_ambient() {
        let (range, facts) = crate::fixture::demo();
        let mut app = App::new(range, facts, false, false, false, crate::config::Config::default());
        app.view = super::super::app::View::Map;
        app.hover_d = None; // idle → ambient shimmer
        let _ = dump_ansi(&mut app, 96, 44); // fix map_dims
        let frames = 16;
        for i in 0..frames {
            app.set_anim_clock(Some(i as f32 / frames as f32 * 9.0)); // ~one slow sweep
            println!("@@@FRAME {i}@@@");
            println!("{}", dump_ansi(&mut app, 96, 44));
        }
    }

    /// Dump the **hover sync**: sweep the hover along the curve over the fixture so the glow band
    /// moves and host names light up in succession. Run with
    /// `cargo test --bin canopy map::tests::dump_hover -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_hover() {
        let (range, facts) = crate::fixture::demo();
        let mut app = App::new(range, facts, false, false, false, crate::config::Config::default());
        app.view = super::super::app::View::Map;
        let _ = dump_ansi(&mut app, 96, 44); // fix map_dims
        let frames = 16;
        for i in 0..frames {
            // Sweep the synced cell across the occupied region; advance the pulse clock too.
            app.hover_d = Some(8 + i * 8);
            app.set_anim_clock(Some(i as f32 * 0.12));
            println!("@@@FRAME {i}@@@");
            println!("{}", dump_ansi(&mut app, 96, 44));
        }
    }

    /// Dump the **zoom edge-sweep**: press Enter on a quadrant and capture the growing edge frame
    /// by frame, up to the commit. Run with
    /// `cargo test --bin canopy map::tests::dump_zoom_anim -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn dump_zoom_anim() {
        use crate::reconcile::Cidr;
        let range = Cidr::parse("145.124.0.0/16").unwrap();
        let mut app = App::new(range, Vec::new(), false, false, false, crate::config::Config::default());
        app.view = super::super::app::View::Map;
        app.set_anim_clock(Some(0.0));
        let _ = dump_ansi(&mut app, 100, 40); // fix map_dims
        app.on_key(mullion::KeyCode::Right); // pick a quadrant (top-right)
        app.on_key(mullion::KeyCode::Enter); // start the grow sweep (start_t = 0.0)
        let frames = 12;
        for i in 0..frames {
            app.set_anim_clock(Some(i as f32 / (frames - 1) as f32 * ZOOM_ANIM_SECS)); // 0..0.32 s
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
