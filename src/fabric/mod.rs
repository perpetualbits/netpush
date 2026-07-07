// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The **fabric** subsystem: read-only collection of diagnostic artifacts from
//! network devices (switches/routers) into a versioned on-disk store. Pure model
//! (`inventory`, `profile`, `store`) plus one thin I/O seam (`collect`'s
//! `CommandRunner`, implemented for `sources::vantage::Vantage`).
//!
//! Built ahead of its consumers: `inventory` lands in this task, `profile`/`store`/
//! `collect` follow in later tasks and wire it into `main`. Until then this surface
//! is unused from the binary's perspective, so dead-code warnings are allowed here.
#![allow(dead_code)]

pub mod inventory;
