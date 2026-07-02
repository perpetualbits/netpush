// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! Colour palette and `Style` helpers, in census's house style, plus the mapping
//! from [`AddressStatus`](crate::reconcile::AddressStatus) to a colour + label.

use mullion::style::{Color, Modifier, Style};

use crate::reconcile::AddressStatus;

// ─── palette ─────────────────────────────────────────────────────────────────

/// Panel border colour.
pub const C_BORDER: Color = Color::Rgb(70, 70, 100);
/// Default foreground text.
pub const C_FG: Color = Color::Rgb(200, 200, 210);
/// Dimmed / secondary text.
pub const C_DIM: Color = Color::Rgb(110, 110, 130);
/// Bright heading text.
pub const C_HEAD: Color = Color::Rgb(255, 255, 255);
/// Sub-heading / accent (blue).
pub const C_HDR2: Color = Color::Rgb(140, 170, 255);
/// Title colour.
pub const C_TITLE: Color = Color::Rgb(160, 160, 255);
/// Selected-row foreground.
pub const C_SEL_FG: Color = Color::Rgb(0, 0, 0);
/// Selected-row background.
pub const C_SEL_BG: Color = Color::Rgb(80, 120, 210);
/// Success / free (green).
pub const C_OK: Color = Color::Rgb(80, 200, 100);
/// Warning / drift (amber).
pub const C_WARN: Color = Color::Rgb(230, 180, 60);
/// Error / squatter (red).
pub const C_ERR: Color = Color::Rgb(220, 80, 80);
/// Conflict (magenta).
pub const C_CONFLICT: Color = Color::Rgb(210, 110, 210);

// ─── style helpers ───────────────────────────────────────────────────────────

/// Border style.
pub fn s_border() -> Style {
    Style::default().fg(C_BORDER)
}
/// Normal text style.
pub fn s_normal() -> Style {
    Style::default().fg(C_FG)
}
/// Dim text style.
pub fn s_dim() -> Style {
    Style::default().fg(C_DIM)
}
/// Title text style.
pub fn s_title() -> Style {
    Style::default().fg(C_TITLE).add_modifier(Modifier::BOLD)
}
/// Heading text style.
pub fn s_head() -> Style {
    Style::default().fg(C_HEAD).add_modifier(Modifier::BOLD)
}
/// Accent (blue) text style.
pub fn s_accent() -> Style {
    Style::default().fg(C_HDR2)
}
/// Selected-row style.
pub fn s_sel() -> Style {
    Style::default().fg(C_SEL_FG).bg(C_SEL_BG)
}
/// Success style.
pub fn s_ok() -> Style {
    Style::default().fg(C_OK)
}
/// Warning style.
pub fn s_warn() -> Style {
    Style::default().fg(C_WARN)
}
/// Error style.
pub fn s_err() -> Style {
    Style::default().fg(C_ERR)
}

/// Map census's palette onto mullion's semantic [`Theme`](mullion::Theme) so the
/// engine's render helpers (`render_keyhints`, …) paint in netpush colours.
pub fn mullion_theme() -> mullion::Theme {
    mullion::Theme {
        border: s_border(),
        border_focused: s_accent(),
        text: s_normal(),
        text_dim: s_dim(),
        accent: s_accent(),
        selection: s_sel(),
        heading: s_head(),
        ok: s_ok(),
        warn: s_warn(),
        error: s_err(),
    }
}

// ─── status → colour + label ───────────────────────────────────────────────────

/// The short label shown in the STATUS column for each verdict.
#[must_use]
pub fn status_label(s: AddressStatus) -> &'static str {
    match s {
        AddressStatus::Free => "free",
        AddressStatus::Allocated => "allocated",
        AddressStatus::NetBoxOnly => "netbox-only",
        AddressStatus::DnsOnly => "dns-only",
        AddressStatus::LiveUnregistered => "live!",
        AddressStatus::Conflict => "CONFLICT",
    }
}

/// The colour for a verdict: green free, dim allocated, blue netbox-only, amber
/// dns-only drift, red live squatter, magenta conflict.
#[must_use]
pub fn status_style(s: AddressStatus) -> Style {
    match s {
        AddressStatus::Free => s_ok(),
        AddressStatus::Allocated => s_dim(),
        AddressStatus::NetBoxOnly => s_accent(),
        AddressStatus::DnsOnly => s_warn(),
        AddressStatus::LiveUnregistered => s_err(),
        AddressStatus::Conflict => Style::default().fg(C_CONFLICT).add_modifier(Modifier::BOLD),
    }
}
