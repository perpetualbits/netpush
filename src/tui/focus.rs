// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! The cursor/offset bookkeeping a scrollable list needs. Lifted from census's
//! `focus::ListCursor` — the windowing arithmetic lives in `mullion::visible_window`.

/// A scrollable list's selected row plus the scroll offset that keeps it in view.
#[derive(Debug, Clone, Copy, Default)]
pub struct ListCursor {
    /// Index of the selected row.
    pub cursor: usize,
    /// Index of the first visible row.
    pub offset: usize,
}

impl ListCursor {
    /// A fresh cursor at the top of the list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset to the top of the list.
    pub fn reset(&mut self) {
        self.cursor = 0;
        self.offset = 0;
    }

    /// Move the cursor up one row (saturating at 0).
    pub fn up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    /// Move the cursor down one row, clamped to `len`.
    pub fn down(&mut self, len: usize) {
        if self.cursor + 1 < len {
            self.cursor += 1;
        }
    }

    /// Jump by `delta` rows (e.g. PageUp/PageDown), clamped to `[0, len)`.
    pub fn page(&mut self, delta: isize, len: usize) {
        let max = len.saturating_sub(1) as isize;
        let next = (self.cursor as isize + delta).clamp(0, max.max(0));
        self.cursor = next as usize;
    }

    /// Jump straight to the last row.
    pub fn end(&mut self, len: usize) {
        self.cursor = len.saturating_sub(1);
    }

    /// Clamp the cursor so it cannot point past the end of a (possibly shrunk) list.
    pub fn clamp(&mut self, len: usize) {
        if len > 0 && self.cursor >= len {
            self.cursor = len - 1;
        }
    }

    /// Adjust `offset` so `cursor` stays within a window of `visible` rows, never
    /// leaving blank space past the end.
    pub fn keep_in_view(&mut self, len: usize, visible: usize) {
        mullion::visible_window(self.cursor, &mut self.offset, len, visible);
    }
}
