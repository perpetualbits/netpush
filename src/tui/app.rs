// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! TUI orchestrator: application state, the event loop, key routing, and render
//! dispatch. One screen for now — the reconciled address table.

use std::io;
use std::time::Duration;

use crossterm::event::{Event, KeyEvent};
use mullion::{backend::CrosstermBackend, style::Style, EventReader, KeyCode, Terminal};

use super::draw;
use super::focus::ListCursor;
use super::theme::{s_dim, s_err, s_warn};
use crate::reconcile::{self, AddressFacts, AddressRow, Cidr, Counts};

/// Idle redraw cap (~20 fps) so the UI stays responsive without busy-looping.
const RENDER_TICK: Duration = Duration::from_millis(50);

/// The whole application state.
pub struct App {
    /// The range being browsed.
    pub range: Cidr,
    /// The reconciled rows, one per host address, in address order.
    pub rows: Vec<AddressRow>,
    /// Cached status tally for the header.
    pub counts: Counts,
    /// The list cursor (selection + scroll offset).
    pub cur: ListCursor,
    /// Body height measured at the last render — used for PageUp/PageDown.
    pub page: usize,

    write_mode: bool,
    dry_run: bool,
    quit: bool,
}

impl App {
    /// Build the app by reconciling `facts` over `range`.
    #[must_use]
    pub fn new(range: Cidr, facts: Vec<AddressFacts>, write_mode: bool, dry_run: bool) -> Self {
        let rows = reconcile::reconcile(range, &facts);
        let counts = reconcile::counts(&rows);
        App {
            range,
            rows,
            counts,
            cur: ListCursor::new(),
            page: 10,
            write_mode,
            dry_run,
            quit: false,
        }
    }

    /// The mode badge shown top-right: colourful because write mode is dangerous.
    #[must_use]
    pub fn mode_label(&self) -> (&'static str, Style) {
        if self.dry_run {
            ("DRY-RUN", s_warn())
        } else if self.write_mode {
            ("WRITE", s_err())
        } else {
            ("READ-ONLY", s_dim())
        }
    }

    /// Route one key press.
    pub fn on_key(&mut self, code: KeyCode) {
        let len = self.rows.len();
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('j') | KeyCode::Down => self.cur.down(len),
            KeyCode::Char('k') | KeyCode::Up => self.cur.up(),
            KeyCode::Char('g') | KeyCode::Home => self.cur.reset(),
            KeyCode::Char('G') | KeyCode::End => self.cur.end(len),
            KeyCode::PageUp => self.cur.page(-(self.page as isize), len),
            KeyCode::PageDown => self.cur.page(self.page as isize, len),
            KeyCode::Char('f') => self.jump_next_free(),
            _ => {}
        }
    }

    /// Move the cursor to the next free address after the current one, wrapping
    /// around the list. Does nothing if there are no free addresses.
    fn jump_next_free(&mut self) {
        let len = self.rows.len();
        if len == 0 {
            return;
        }
        for step in 1..=len {
            let i = (self.cur.cursor + step) % len;
            if self.rows[i].status.is_free() {
                self.cur.cursor = i;
                return;
            }
        }
    }
}

/// Enter the alternate screen, run the loop, and always restore the terminal.
///
/// # Errors
/// Propagates terminal setup / draw errors.
pub fn run(range: Cidr, facts: Vec<AddressFacts>, write_mode: bool, dry_run: bool) -> anyhow::Result<()> {
    let mut app = App::new(range, facts, write_mode, dry_run);
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    term.enter()?;
    let result = main_loop(&mut term, &mut app);
    term.leave()?;
    result
}

/// The draw / read-key loop: redraw, then wait up to one tick for a key.
fn main_loop(term: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> anyhow::Result<()> {
    let reader = EventReader::new();
    while !app.quit {
        term.draw(|buf| draw::screen(buf, app))?;
        if let Some(Event::Key(KeyEvent { code, .. })) = reader.recv_timeout(RENDER_TICK) {
            app.on_key(code);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;
    use mullion::{Buffer, Rect};

    #[test]
    fn fixture_reconciles_to_expected_statuses() {
        let (range, facts) = fixture::demo();
        let app = App::new(range, facts, false, false);
        assert!(app.counts.dns_only >= 10); // the -ipmi/-bmc/iprotect drift
        assert_eq!(app.counts.live_unregistered, 1); // the .90 squatter
        assert_eq!(app.counts.netbox_only, 5);
        assert!(app.counts.free > 200);
    }

    #[test]
    fn renders_without_panicking_at_many_sizes() {
        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false);
        for (w, h) in [(120u16, 50u16), (80, 24), (40, 10), (24, 6), (20, 4)] {
            let mut buf = Buffer::empty(Rect::new(0, 0, w, h));
            draw::screen(&mut buf, &mut app);
        }
    }

    #[test]
    fn next_free_lands_on_a_free_address() {
        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false);
        app.jump_next_free();
        assert!(app.rows[app.cur.cursor].status.is_free());
    }
}
