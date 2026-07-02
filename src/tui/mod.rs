// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The terminal UI, built on `mullion`. One screen for now: the reconciled
//! address table. Structured like census (`app` orchestrates, `draw` paints,
//! `theme` holds the palette, `focus` the list cursor).

pub mod app;
pub mod draw;
pub mod focus;
pub mod theme;

pub use app::run;
