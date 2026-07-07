// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The **fabric** subsystem: read-only collection of diagnostic artifacts from
//! network devices (switches/routers) into a versioned on-disk store. Pure model
//! (`inventory`, `profile`, `store`) plus one thin I/O seam (`collect`'s
//! `CommandRunner`, implemented for `sources::vantage::Vantage`). Wired into
//! `main` via the `--fabric-collect` CLI.
//!
//! Some surface (data fields in `profile`/`store` types) remains unused until
//! export/TUI work consumes them.
#![allow(dead_code)]

pub mod collect;
pub mod inventory;
pub mod profile;
pub mod store;
