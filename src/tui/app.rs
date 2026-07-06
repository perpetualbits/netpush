// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  Epsilon Null Operation
//! TUI orchestrator: application state, the event loop, key routing, and render
//! dispatch. One screen for now — the reconciled address table.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use mullion::style::{Color, Style};
use mullion::{backend::CrosstermBackend, EventReader, GraphCanvas, KeyCode, RangeSource, Rect, Terminal};

use super::draw;
use super::focus::ListCursor;
use super::theme::{s_dim, s_err, s_warn};
use crate::config::Config;
use crate::graph::DnsGraph;
use crate::live::{self, LiveData};
use crate::plan::{Allocation, Plan};
use crate::reconcile::{self, AddrRange, AddressFacts, AddressRow, AddressStatus, Cidr, Counts, Subnet};
use crate::sources::Vantage;

/// The result the live-gather thread sends back.
type LiveResult = anyhow::Result<LiveData>;

/// The result the allocate-apply thread sends back (a log of what it did).
type ApplyResult = anyhow::Result<String>;

/// Which step of the allocate flow the overlay is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocPhase {
    /// Typing the FQDN for the address.
    Naming,
    /// Reviewing the built plan before applying.
    Preview,
}

/// A saved map scope for zoom-out: a range and the facts within it.
struct ZoomFrame {
    range: AddrRange,
    facts: Rc<HashMap<IpAddr, AddressFacts>>,
}

/// The in-progress "allocate this address" flow.
pub struct AllocFlow {
    /// The address being allocated.
    pub addr: IpAddr,
    /// The FQDN being typed.
    pub input: String,
    /// The plan, once built (Preview phase).
    pub plan: Option<Plan>,
    /// Which step we're on.
    pub phase: AllocPhase,
}

/// Idle redraw cap (~20 fps) so the UI stays responsive without busy-looping.
const RENDER_TICK: Duration = Duration::from_millis(50);

/// Which screen is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// The reconciled address table.
    Table,
    /// The cluster node graph.
    Graph,
    /// The expandable network → cluster → host tree.
    Tree,
    /// The IP map: the range as a grid of used/free blocks.
    Map,
}

impl View {
    /// The next view in the `Tab` cycle.
    #[must_use]
    fn next(self) -> View {
        match self {
            View::Table => View::Graph,
            View::Graph => View::Tree,
            View::Tree => View::Map,
            View::Map => View::Table,
        }
    }
}

pub use super::palette::{Knobs, Scheme};

/// The program's connection state, shown by the orbiting heartbeat on the frame:
/// it keeps travelling as long as the UI is responsive (a liveness signal), and its
/// colour says how we stand with the endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// Not connected yet — demo data, or waiting to be pointed at live sources (blue).
    Waiting,
    /// A gather is in flight — talking to NetBox/DNS/the probe right now (yellow).
    Working,
    /// Live data loaded cleanly; the endpoints answered (green).
    Connected,
    /// The last gather failed — an endpoint is unreachable or errored (red, pulsing).
    Broken,
}

/// The whole application state.
pub struct App {
    /// The range being browsed. A CIDR at the top level; a map zoom can narrow it to a
    /// ragged [`AddrRange`] slice with no single prefix.
    pub range: AddrRange,
    /// Number of usable host addresses in `range` — the table's row count. A `/8` is
    /// 16M, so rows are computed on demand ([`row_at`](App::row_at)), never stored.
    pub total: usize,
    /// The raw per-address facts, keyed by address. Bounded by what the sources
    /// reported (never the whole range), so it also backs inspect and the graph/tree.
    /// Shared (`Rc`) so a [`RangeSource`] closure can borrow it.
    pub facts: Rc<HashMap<IpAddr, AddressFacts>>,
    /// Cached status tally for the header (derived from `facts` + `total`).
    pub counts: Counts,
    /// Whether `facts` came from the live sources (`true`) or the demo fixture.
    pub live: bool,
    /// The list cursor (selection + scroll offset).
    pub cur: ListCursor,
    /// Body height measured at the last render — used for PageUp/PageDown.
    pub page: usize,
    /// Whether the inspect panel for the selected row is open.
    pub detail: bool,

    /// Which screen is showing.
    pub view: View,
    /// The cluster graph, built from the known facts (never the whole range).
    pub graph: DnsGraph,
    /// The laid-out canvas for the graph view.
    pub graph_canvas: GraphCanvas,
    /// Pan offset (canvas cells) for the graph view.
    pub pan: (u16, u16),
    /// Selected visible row in the tree view.
    pub tree_cur: usize,
    /// Group keys currently expanded in the tree view.
    pub tree_expanded: HashSet<String>,
    /// Cursor cell `(x, y)` on the Gilbert map grid.
    pub map_cur: (u32, u32),
    /// The map grid `(width, height)` measured at the last map render — used to clamp the
    /// cursor and to compute which slice a cell covers (the render owns the fit).
    pub map_dims: (u32, u32),
    /// The map grid's on-screen rectangle at the last render — lets a mouse `(column, row)` be
    /// mapped back to a grid cell (each cell is two columns wide).
    pub map_area: Rect,
    /// Parent scopes to return to on zoom-out (each a range + its facts).
    zoom_stack: Vec<ZoomFrame>,
    /// How the map colours cells by occupancy.
    /// The map's colour scheme, its tunable knobs, and which knob the `[`/`]` selector
    /// currently points at (adjusted with `,`/`.`).
    pub scheme: Scheme,
    pub knobs: Knobs,
    pub active_knob: usize,
    /// Logical groupings (clusters, name-families, services) reconciled from the current
    /// facts — the map paints each group's stable hue when [`color_by_group`](App::color_by_group)
    /// is on. Rebuilt whenever the facts change (a live gather, a map zoom).
    pub grouping: crate::group::Grouping,
    /// `true` when the map colours cells by **group identity** (hue = which cluster) instead of
    /// occupancy; toggled with `g`. Occupancy still sets the brightness of a grouped cell.
    pub color_by_group: bool,
    /// The **quadrant chooser**: `Some(i)` selects the `i`-th top-level sub-block of the current
    /// map view (its curve segment luma-pulses); the arrows step between sub-blocks and `Enter`
    /// zooms into the selected one. `None` is the normal per-cell cursor mode. Toggled with `z`.
    pub chooser: Option<usize>,
    /// When `true`, the map draws a rounded boundary around the subnet under the cursor (later
    /// reusable for VLANs). Toggled with `b`.
    pub show_subnets: bool,
    /// The human-asserted groups (from `conf.d/<site>.groups.toml`) and native NetBox clusters,
    /// kept so the grouping can be re-fused with inference whenever the facts change (a zoom).
    /// Empty on the demo/offline path; populated by [`set_group_sources`](App::set_group_sources).
    asserted_groups: Vec<crate::group::Group>,
    native_groups: Vec<crate::group::Group>,
    /// When set, the fixed animation clock value used instead of the real elapsed time — a
    /// headless-render hook (see [`set_anim_clock`](App::set_anim_clock)); `None` in normal use.
    anim_override: Option<f32>,
    /// NetBox-defined subnets (variable-length) covering the range — used to label the
    /// real subnet the map cursor sits in. Empty until live data (or demo) supplies them.
    pub subnets: Vec<Subnet>,
    /// Connection state, driving the heartbeat's colour.
    link: Link,
    /// When the app started — the clock the orbiting heartbeat reads for its phase.
    started: Instant,

    /// Connection settings, used to gather live data on demand.
    pub cfg: Config,
    /// `true` while a background live-gather is running.
    pub loading: bool,
    /// Set by the `L` key; the event loop services it (fetching the token with the
    /// TUI suspended) and clears it.
    request_live: bool,
    /// Latest live-gather progress `(fraction 0–1, label)`, shown as a bar in the
    /// frame while `loading`. `None` when no gather is running.
    pub progress: Option<(f32, String)>,
    /// Channel carrying progress updates from the background gather thread.
    progress_rx: Option<mpsc::Receiver<(f32, String)>>,
    /// `true` while a background allocate-apply is running.
    pub applying: bool,
    /// A short status line (message, is_error) shown in the header.
    pub status: Option<(String, bool)>,
    /// The in-progress allocate flow, if any.
    pub alloc: Option<AllocFlow>,
    /// Channel to the in-flight live-gather thread, if any.
    live_rx: Option<mpsc::Receiver<LiveResult>>,
    /// Channel to the in-flight allocate-apply thread, if any.
    apply_rx: Option<mpsc::Receiver<ApplyResult>>,

    write_mode: bool,
    dry_run: bool,
    quit: bool,
}

impl App {
    /// Build the app from the `facts` gathered over `range`. `live` records whether
    /// the facts are real (from the sources) or the demo fixture; `cfg` lets the TUI
    /// gather live data on demand. Rows are never materialized — only `facts`
    /// (bounded) and the row count are kept.
    #[must_use]
    pub fn new(range: Cidr, facts: Vec<AddressFacts>, write_mode: bool, dry_run: bool, live: bool, cfg: Config) -> Self {
        // The survey scope arrives as a CIDR; internally the browse scope is a general
        // address range so a map zoom can narrow it to a ragged slice.
        let range = AddrRange::from(range);
        let total = range.host_count().min(usize::MAX as u128) as usize;
        let facts: Rc<HashMap<IpAddr, AddressFacts>> =
            Rc::new(facts.into_iter().map(|f| (f.addr, f)).collect());
        let counts = reconcile::counts_from_facts(range.host_count(), &facts);
        let (graph, graph_canvas) = build_graph(&facts);
        // Infer logical groups from the naming scheme up front (asserted/native sources fold
        // in later); the map can then colour by identity from the first frame.
        let grouping = crate::group::merge(Vec::new(), Vec::new(), crate::group::infer(&facts));
        App {
            range,
            total,
            facts,
            counts,
            live,
            cur: ListCursor::new(),
            page: 10,
            detail: false,
            view: View::Table,
            graph,
            graph_canvas,
            pan: (0, 0),
            tree_cur: 0,
            tree_expanded: HashSet::new(),
            map_cur: (0, 0),
            map_dims: (0, 0),
            zoom_stack: Vec::new(),
            scheme: Scheme::default(),
            knobs: Knobs::default(),
            active_knob: 0,
            grouping,
            color_by_group: false,
            chooser: None,
            show_subnets: false,
            map_area: Rect::new(0, 0, 0, 0),
            asserted_groups: Vec::new(),
            native_groups: Vec::new(),
            anim_override: None,
            subnets: Vec::new(),
            // Live CLI start means the endpoints already answered; otherwise we are on
            // demo data, not yet connected.
            link: if live { Link::Connected } else { Link::Waiting },
            started: Instant::now(),
            cfg,
            loading: false,
            request_live: false,
            progress: None,
            progress_rx: None,
            applying: false,
            status: None,
            alloc: None,
            live_rx: None,
            apply_rx: None,
            write_mode,
            dry_run,
            quit: false,
        }
    }

    /// Ask for a live gather. This only *raises a flag*; the event loop
    /// ([`main_loop`]) picks it up, because the token fetch may need to suspend the
    /// TUI so `pinentry` gets a clean terminal, and only the loop owns the terminal.
    fn request_live_gather(&mut self) {
        if self.loading {
            return;
        }
        self.request_live = true;
        self.link = Link::Working;
    }

    /// Take (and clear) a pending live-gather request. Called once per loop tick by
    /// [`main_loop`], which then fetches the token and calls [`spawn_live_gather`].
    #[must_use]
    pub fn take_live_request(&mut self) -> bool {
        std::mem::take(&mut self.request_live)
    }

    /// Start the background SSH sweep with an already-fetched `token` (no-op if one is
    /// already running). The sweep takes tens of seconds, so it runs off-thread and
    /// reports back through a channel; the UI keeps redrawing meanwhile.
    pub fn spawn_live_gather(&mut self, token: String) {
        if self.loading {
            return;
        }
        // Live gathering probes the scope by AXFR / reverse zone — a CIDR-shaped operation.
        // A map zoom into a ragged slice has no prefix to probe, so refuse until zoomed to a
        // clean CIDR (zoom out, or onto an aligned cell).
        let Some(range) = self.range.as_cidr() else {
            self.status = Some(("live refresh needs a CIDR-aligned scope — zoom out first".to_string(), true));
            return;
        };
        let (tx, rx) = mpsc::channel();
        let (ptx, prx) = mpsc::channel(); // progress updates
        let cfg = self.cfg.clone();
        std::thread::spawn(move || {
            let progress = |frac: f32, label: &str| {
                let _ = ptx.send((frac, label.to_string()));
            };
            let _ = tx.send(live::gather_live_with_token(&range, &cfg, token, progress));
        });
        self.live_rx = Some(rx);
        self.progress_rx = Some(prx);
        self.loading = true;
        self.progress = Some((0.0, "starting…".to_string()));
        self.status = Some(("gathering live data…".to_string(), false));
    }

    /// The `pass` entry to unlock for the NetBox token — read by [`main_loop`] when it
    /// services a live request.
    #[must_use]
    pub fn token_pass(&self) -> &str {
        &self.cfg.token_pass
    }

    /// Set the status line (message, is_error) — used by the loop to report a token
    /// failure it handled outside the normal key path.
    pub fn set_status(&mut self, msg: impl Into<String>, is_error: bool) {
        self.status = Some((msg.into(), is_error));
    }

    /// Seed the NetBox subnets (e.g. from the initial `--live` gather or the demo
    /// fixture); the in-TUI `L` load refreshes them via [`apply_live`].
    pub fn set_subnets(&mut self, subnets: Vec<Subnet>) {
        self.subnets = subnets;
    }

    /// Seconds since start — the clock the orbiting heartbeat reads. The render loop
    /// ticks ~20×/s even with no input, so the heartbeat keeps moving as long as the UI
    /// is responsive; it only pauses if the main thread blocks (e.g. the passphrase
    /// prompt), which is precisely the "am I frozen?" signal it exists to give.
    #[must_use]
    pub fn anim_t(&self) -> f32 {
        self.anim_override.unwrap_or_else(|| self.started.elapsed().as_secs_f32())
    }

    /// Pin the animation clock to a fixed value (a headless render hook, so a frame at a chosen
    /// phase can be captured deterministically). `None` restores the real elapsed clock. Test-only.
    #[cfg(test)]
    pub fn set_anim_clock(&mut self, t: Option<f32>) {
        self.anim_override = t;
    }

    /// The heartbeat to draw on the frame this tick: its phase (from the clock) and the
    /// colour + pulse for the current [`Link`] state.
    #[must_use]
    pub fn heartbeat(&self) -> draw::Heartbeat {
        let (color, pulse) = match self.link {
            Link::Waiting => (Color::Rgb(80, 150, 255), false),   // blue — waiting to connect
            Link::Working => (Color::Rgb(230, 200, 60), false),   // yellow — talking to endpoints
            Link::Connected => (Color::Rgb(90, 205, 110), false), // green — connected cleanly
            Link::Broken => (Color::Rgb(225, 70, 70), true),      // red, pulsing — link down
        };
        draw::Heartbeat { t: self.anim_t(), color, pulse }
    }

    /// Check whether the background gather has finished; apply or report its result.
    /// Called once per loop tick.
    pub fn poll_live(&mut self) {
        // Drain any progress updates first, keeping the latest for the bar.
        if let Some(prx) = &self.progress_rx {
            while let Ok(update) = prx.try_recv() {
                self.progress = Some(update);
            }
        }
        let Some(rx) = &self.live_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(data)) => self.apply_live(data),
            Ok(Err(e)) => {
                self.status = Some((format!("live load failed: {e}"), true));
                self.loading = false;
                self.live_rx = None;
                self.progress = None;
                self.progress_rx = None;
                self.link = Link::Broken; // an endpoint failed — heartbeat goes red
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.loading = false;
                self.live_rx = None;
                self.progress = None;
                self.progress_rx = None;
                self.link = Link::Broken;
            }
        }
    }

    /// Replace the current data with freshly gathered live facts and rebuild views.
    fn apply_live(&mut self, data: LiveData) {
        self.subnets = data.subnets;
        self.facts = Rc::new(data.facts.into_iter().map(|f| (f.addr, f)).collect());
        self.counts = reconcile::counts_from_facts(self.range.host_count(), &self.facts);
        let (graph, canvas) = build_graph(&self.facts);
        self.graph = graph;
        self.graph_canvas = canvas;
        self.live = true;
        self.loading = false;
        self.live_rx = None;
        self.progress = None;
        self.progress_rx = None;
        self.link = Link::Connected; // endpoints answered — heartbeat goes green
        self.pan = (0, 0);
        self.cur.clamp(self.total);
        self.status = Some(("live data loaded".to_string(), false));
    }

    /// The raw facts for `addr`, if any source reported it (free addresses have none).
    #[must_use]
    pub fn facts_for(&self, addr: IpAddr) -> Option<&AddressFacts> {
        self.facts.get(&addr)
    }

    /// The reconciled row at table index `i`, computed on demand from `facts` — the
    /// lazy core that lets the table browse a huge range without materializing it.
    #[must_use]
    pub fn row_at(&self, i: usize) -> AddressRow {
        reconcile::reconcile_at(self.range, &self.facts, i as u128)
    }

    /// A `mullion::RangeSource` over the whole range, each row built lazily from its
    /// index. This is the paginated data source (a `/8` costs the same as a `/24`);
    /// a `VirtualList` can window it. Returned by value so callers own their cursor.
    #[must_use]
    pub fn table_source(&self) -> RangeSource<AddressRow, impl Fn(u64) -> AddressRow> {
        let range = self.range;
        let facts = Rc::clone(&self.facts);
        RangeSource::new(self.total as u64, move |i| reconcile::reconcile_at(range, &facts, u128::from(i)))
    }

    /// The reconciled rows for the **known** addresses only (those any source
    /// reported), sorted by address — bounded by `facts`, so it is safe to build for
    /// the graph and tree even over a `/8`. Free space is represented as a count.
    #[must_use]
    pub fn known_rows(&self) -> Vec<AddressRow> {
        let mut rows: Vec<AddressRow> = self.facts.values().map(reconcile::row_from_facts).collect();
        rows.sort_by_key(|r| r.addr);
        rows
    }

    /// Whether the address table lists **every** address (an enumerable range) or only
    /// the **known** ones (a sparse IPv6 range too large to enumerate).
    #[must_use]
    pub fn table_sparse(&self) -> bool {
        !self.range.is_enumerable()
    }

    /// The number of navigable rows in the table: every address for an enumerable range,
    /// or just the known addresses for a sparse one.
    #[must_use]
    pub fn table_len(&self) -> usize {
        if self.table_sparse() {
            self.facts.len()
        } else {
            self.total
        }
    }

    /// The reconciled row currently under the table cursor, for whichever mode is
    /// active — the `i`-th address of the range, or the `i`-th known address.
    #[must_use]
    pub fn selected_row(&self) -> Option<AddressRow> {
        if self.table_sparse() {
            self.known_rows().into_iter().nth(self.cur.cursor)
        } else {
            (self.cur.cursor < self.total).then(|| self.row_at(self.cur.cursor))
        }
    }

    /// Begin allocating the selected row — only free addresses qualify.
    fn start_alloc(&mut self) {
        let Some(row) = self.selected_row() else {
            return;
        };
        if !row.status.is_free() {
            self.status = Some(("only free addresses can be allocated".to_string(), true));
            return;
        }
        self.detail = false;
        self.alloc = Some(AllocFlow { addr: row.addr, input: String::new(), plan: None, phase: AllocPhase::Naming });
    }

    /// Keys while the allocate overlay is open.
    fn on_key_alloc(&mut self, code: KeyCode) {
        let phase = match &self.alloc {
            Some(f) => f.phase,
            None => return,
        };
        match phase {
            AllocPhase::Naming => match code {
                KeyCode::Esc => self.alloc = None,
                KeyCode::Enter => self.build_alloc_plan(),
                KeyCode::Backspace => {
                    if let Some(f) = &mut self.alloc {
                        f.input.pop();
                    }
                }
                KeyCode::Char(c) => {
                    if let Some(f) = &mut self.alloc {
                        f.input.push(c);
                    }
                }
                _ => {}
            },
            AllocPhase::Preview => match code {
                KeyCode::Esc => self.alloc = None,
                KeyCode::Char('y') | KeyCode::Enter => self.start_apply(),
                _ => {}
            },
        }
    }

    /// Build the allocation plan from the typed name and move to the Preview phase.
    fn build_alloc_plan(&mut self) {
        let (addr, fqdn) = match &self.alloc {
            Some(f) => (f.addr, f.input.trim().to_string()),
            None => return,
        };
        if fqdn.is_empty() {
            self.status = Some(("type a name first".to_string(), true));
            return;
        }
        // A NetBox allocation carries the host's containing prefix. A ragged map-zoom slice
        // has none, so writes are only offered on a CIDR-aligned scope.
        let Some(prefix_len) = self.range.as_cidr().map(|c| c.prefix_len) else {
            self.status = Some(("allocation needs a CIDR-aligned scope — zoom out first".to_string(), true));
            return;
        };
        let alloc = Allocation { addr, prefix_len, fqdn };
        // The plan only needs the target address's current row for its free-check.
        let target = self
            .facts
            .get(&addr)
            .map(reconcile::row_from_facts)
            .unwrap_or(AddressRow { addr, status: AddressStatus::Free, name: None });
        match Plan::for_allocation(alloc, &self.cfg.netbox_url, Some(&[target])) {
            Ok(plan) => {
                if let Some(f) = &mut self.alloc {
                    f.plan = Some(plan);
                    f.phase = AllocPhase::Preview;
                }
            }
            Err(e) => self.status = Some((format!("{e}"), true)),
        }
    }

    /// Whether the TUI may actually push changes: write mode on, dry-run off.
    #[must_use]
    pub fn can_apply(&self) -> bool {
        self.write_mode && !self.dry_run
    }

    /// Apply the previewed plan on a background thread. Refuses unless writes are
    /// enabled, so a read-only or dry-run session can preview but never mutate.
    fn start_apply(&mut self) {
        if !self.can_apply() {
            self.status = Some(("read-only — restart with --write to apply".to_string(), true));
            return;
        }
        let plan = match self.alloc.as_ref().and_then(|f| f.plan.clone()) {
            Some(p) => p,
            None => return,
        };
        let (tx, rx) = mpsc::channel();
        let vantage = self.cfg.vantage.clone();
        let jump = self.cfg.jump.clone();
        let token_pass = self.cfg.token_pass.clone();
        std::thread::spawn(move || {
            let res = live::get_token(&token_pass).and_then(|tok| plan.apply(&Vantage::with_jump(&vantage, &jump), &tok));
            let _ = tx.send(res);
        });
        self.apply_rx = Some(rx);
        self.applying = true;
        self.status = Some(("applying…".to_string(), false));
    }

    /// Poll the allocate-apply thread; on completion report and close the flow.
    /// Called once per loop tick.
    pub fn poll_apply(&mut self) {
        let Some(rx) = &self.apply_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(_log)) => {
                self.applying = false;
                self.apply_rx = None;
                self.alloc = None;
                self.status = Some(("allocation applied".to_string(), false));
            }
            Ok(Err(e)) => {
                self.applying = false;
                self.apply_rx = None;
                self.status = Some((format!("apply failed: {e}"), true));
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.applying = false;
                self.apply_rx = None;
            }
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

    /// Route one key press, first handling the global keys (view toggle, live load).
    pub fn on_key(&mut self, code: KeyCode) {
        // The allocate overlay captures all keys while open.
        if self.alloc.is_some() {
            self.on_key_alloc(code);
            return;
        }
        match code {
            KeyCode::Tab => {
                self.view = self.view.next();
                return;
            }
            KeyCode::Char('L') => {
                self.request_live_gather();
                return;
            }
            _ => {}
        }
        match self.view {
            View::Table => self.on_key_table(code),
            View::Graph => self.on_key_graph(code),
            View::Tree => self.on_key_tree(code),
            View::Map => self.on_key_map(code),
        }
    }

    /// Keys for the map view: move the cursor over the Gilbert grid, `Enter` zooms
    /// into the highlighted cell (its exact address slice), `Backspace`/`-` zooms back out.
    fn on_key_map(&mut self, code: KeyCode) {
        // `z` toggles the quadrant chooser; while it is on, the arrows step between sub-blocks
        // and Enter zooms into the selected one, so its keys are handled separately.
        if code == KeyCode::Char('z') {
            self.toggle_chooser();
            return;
        }
        if self.chooser.is_some() {
            match code {
                KeyCode::Char('q') | KeyCode::Char('Q') => self.quit = true,
                KeyCode::Left | KeyCode::Char('h') | KeyCode::Up | KeyCode::Char('k') => self.chooser_step(-1),
                KeyCode::Right | KeyCode::Char('l') | KeyCode::Down | KeyCode::Char('j') => self.chooser_step(1),
                KeyCode::Enter | KeyCode::Char('+') => self.zoom_into_chooser(),
                KeyCode::Esc => self.chooser = None, // leave the chooser without zooming
                KeyCode::Backspace | KeyCode::Char('-') => self.zoom_out(),
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.quit = true,
            // Esc only ever zooms out — never quits, so an extra zoom-out is harmless. Only q/Q
            // leave canopy.
            KeyCode::Esc => self.zoom_out(),
            // Walk *along the Gilbert curve*: h/l step one cell (address-adjacent), k/j jump a
            // "row" (the grid width) for a bigger stride; n/f leap to the next occupied/free zone.
            KeyCode::Left | KeyCode::Char('h') => self.map_walk(-1),
            KeyCode::Right | KeyCode::Char('l') => self.map_walk(1),
            KeyCode::Up | KeyCode::Char('k') => self.map_walk(-i64::from(self.map_dims.0.max(1))),
            KeyCode::Down | KeyCode::Char('j') => self.map_walk(i64::from(self.map_dims.0.max(1))),
            KeyCode::Char('n') => self.jump_zone(true, true),
            KeyCode::Char('N') => self.jump_zone(false, true),
            KeyCode::Char('f') => self.jump_zone(true, false),
            KeyCode::Char('F') => self.jump_zone(false, false),
            KeyCode::Enter | KeyCode::Char('+') => self.zoom_into_cursor(),
            KeyCode::Backspace | KeyCode::Char('-') => self.zoom_out(),
            KeyCode::Char('s') | KeyCode::Char('p') => self.scheme = self.scheme.cycle(),
            KeyCode::Char('g') => self.color_by_group = !self.color_by_group,
            KeyCode::Char('b') => self.show_subnets = !self.show_subnets,
            KeyCode::Char('[') => {
                self.active_knob = (self.active_knob + super::palette::KNOBS.len() - 1) % super::palette::KNOBS.len();
            }
            KeyCode::Char(']') => self.active_knob = (self.active_knob + 1) % super::palette::KNOBS.len(),
            KeyCode::Char(',') => self.knobs.adjust(self.active_knob, -1.0),
            KeyCode::Char('.') => self.knobs.adjust(self.active_knob, 1.0),
            _ => {}
        }
    }

    /// The current map view's top-level sub-blocks (the curve's own quadrant partition), from
    /// mullion. Empty when the grid is a single cell (nothing to choose).
    #[must_use]
    pub fn map_subblocks(&self) -> Vec<mullion::spacefill::SubBlock> {
        let (w, h) = self.map_dims;
        if u128::from(w) * u128::from(h) <= 1 {
            return Vec::new();
        }
        mullion::spacefill::Gilbert::new(w, h).subblocks()
    }

    /// Enter the quadrant chooser (selecting the sub-block under the cursor) or leave it.
    fn toggle_chooser(&mut self) {
        if self.chooser.is_some() {
            self.chooser = None;
            return;
        }
        let (w, h) = self.map_dims;
        let subs = self.map_subblocks();
        if subs.is_empty() {
            return; // one cell — nothing to choose
        }
        // Start on the sub-block containing the current cursor cell.
        let g = mullion::spacefill::Gilbert::new(w, h);
        let start = g.xy_to_d(self.map_cur.0, self.map_cur.1).map_or(0, |d| g.subblock_at(d as usize));
        self.chooser = Some(start.min(subs.len() - 1));
    }

    /// Step the chooser selection by `delta` sub-blocks, wrapping.
    fn chooser_step(&mut self, delta: isize) {
        let n = self.map_subblocks().len();
        if let (Some(i), true) = (self.chooser, n > 0) {
            let next = (i as isize + delta).rem_euclid(n as isize) as usize;
            self.chooser = Some(next);
        }
    }

    /// Zoom into the selected sub-block: narrow the scope to the address run its cells cover.
    fn zoom_into_chooser(&mut self) {
        let (w, h) = self.map_dims;
        let cells = u128::from(w) * u128::from(h);
        let subs = self.map_subblocks();
        let Some(sb) = self.chooser.and_then(|i| subs.get(i)) else { return };
        let sub = self.range.span_slices(cells, sb.d_range.start as u128, sb.d_range.end as u128);
        self.zoom_stack.push(ZoomFrame { range: self.range, facts: Rc::clone(&self.facts) });
        let sub_facts: HashMap<IpAddr, AddressFacts> =
            self.facts.iter().filter(|(a, _)| sub.contains(**a)).map(|(a, f)| (*a, f.clone())).collect();
        self.chooser = None;
        self.set_scope(sub, Rc::new(sub_facts));
        self.status = Some((format!("zoomed into {}", self.range.label()), false));
    }

    /// The chain of ranges from the outermost scope down to the current one — the map's
    /// zoom breadcrumb. The first entry is where you started; the last is the current
    /// scope. Each parent came from a `ZoomFrame` pushed on the way in.
    #[must_use]
    pub fn scope_chain(&self) -> Vec<AddrRange> {
        let mut chain: Vec<AddrRange> = self.zoom_stack.iter().map(|f| f.range).collect();
        chain.push(self.range);
        chain
    }

    /// The address slice the map cursor sits over — the contiguous run that cell covers on
    /// the Gilbert curve. `None` when the grid is a single cell, i.e. nothing finer to zoom
    /// into. The slice is a clean CIDR when the geometry is a power of two, else ragged.
    #[must_use]
    pub fn cursor_range(&self) -> Option<AddrRange> {
        let (w, h) = self.map_dims;
        let cells = u128::from(w) * u128::from(h);
        if cells <= 1 {
            return None;
        }
        let d = mullion::spacefill::Gilbert::new(w, h).xy_to_d(self.map_cur.0, self.map_cur.1)?;
        Some(self.range.nth_slice(cells, u128::from(d)))
    }

    /// The grid cell `(x, y)` under a mouse `(column, row)`, or `None` if outside the grid. Each
    /// cell is two screen columns wide, so the column is halved relative to the grid's origin.
    fn map_cell_at(&self, column: u16, row: u16) -> Option<(u32, u32)> {
        let a = self.map_area;
        if a.width == 0 || column < a.x || row < a.y || column >= a.x + a.width || row >= a.y + a.height {
            return None;
        }
        let (gx, gy) = (u32::from((column - a.x) / 2), u32::from(row - a.y));
        let (w, h) = self.map_dims;
        (gx < w && gy < h).then_some((gx, gy))
    }

    /// Mouse control for the map: left-click selects the cell under the pointer, the wheel zooms
    /// (up = into that cell, down = out). Ignored in the other views for now.
    pub fn on_mouse(&mut self, ev: MouseEvent) {
        if self.view != View::Map {
            return;
        }
        match ev.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(cell) = self.map_cell_at(ev.column, ev.row) {
                    self.map_cur = cell;
                    self.chooser = None;
                }
            }
            MouseEventKind::ScrollUp => {
                if let Some(cell) = self.map_cell_at(ev.column, ev.row) {
                    self.map_cur = cell;
                    self.zoom_into_cursor();
                }
            }
            MouseEventKind::ScrollDown => self.zoom_out(),
            _ => {}
        }
    }

    /// The cursor's index along the Gilbert curve in the current grid (`0` if the grid is empty).
    fn cursor_d(&self) -> usize {
        let (w, h) = self.map_dims;
        if w == 0 || h == 0 {
            return 0;
        }
        mullion::spacefill::Gilbert::new(w, h).xy_to_d(self.map_cur.0, self.map_cur.1).unwrap_or(0) as usize
    }

    /// Move the cursor `delta` cells **along the curve** (clamped to the grid) — the serpentine
    /// walk that follows address order, not raw 2-D motion.
    fn map_walk(&mut self, delta: i64) {
        let (w, h) = self.map_dims;
        let total = u128::from(w) * u128::from(h);
        if total == 0 {
            return;
        }
        let d = (self.cursor_d() as i64 + delta).clamp(0, total as i64 - 1) as usize;
        self.map_cur = mullion::spacefill::Gilbert::new(w, h).d_to_xy(d);
    }

    /// Jump the cursor to the start of the next (`forward`) or previous run of **occupied**
    /// (`occupied`) or free cells along the curve — a "zone" being a maximal run of like cells.
    /// A no-op when there is no such zone ahead.
    fn jump_zone(&mut self, forward: bool, occupied: bool) {
        let (w, h) = self.map_dims;
        let total = (u128::from(w) * u128::from(h)) as usize;
        if total <= 1 {
            return;
        }
        let grid = crate::map::MapGrid::build(self.range, &self.facts, w, h);
        let hit = |d: usize| (grid.used[d] > 0) == occupied;
        // A run-start is a hit cell whose predecessor on the curve is a miss (or the very first).
        let run_start = |d: usize| hit(d) && (d == 0 || !hit(d - 1));
        let cur = self.cursor_d();
        let found =
            if forward { (cur + 1..total).find(|&d| run_start(d)) } else { (0..cur).rev().find(|&d| run_start(d)) };
        if let Some(d) = found {
            self.map_cur = grid.cell_xy(d);
        }
    }

    /// Zoom into the cell under the cursor, if there is a finer slice.
    fn zoom_into_cursor(&mut self) {
        if let Some(sub) = self.cursor_range() {
            self.zoom_stack.push(ZoomFrame { range: self.range, facts: Rc::clone(&self.facts) });
            let sub_facts: HashMap<IpAddr, AddressFacts> = self
                .facts
                .iter()
                .filter(|(a, _)| sub.contains(**a))
                .map(|(a, f)| (*a, f.clone()))
                .collect();
            self.set_scope(sub, Rc::new(sub_facts));
            self.status = Some((format!("zoomed into {}", sub.label()), false));
        }
    }

    /// Return to the parent scope (a no-op at the top).
    fn zoom_out(&mut self) {
        if let Some(f) = self.zoom_stack.pop() {
            self.set_scope(f.range, f.facts);
            self.status = Some((format!("zoomed out to {}", self.range.label()), false));
        }
    }

    /// Install the human-asserted and native-cluster group sources (from `groups.toml` and, when
    /// live, NetBox), then re-fuse the grouping. Called once at startup so the map's `g` mode
    /// reflects the canopy config, not just naming inference.
    pub fn set_group_sources(&mut self, asserted: Vec<crate::group::Group>, native: Vec<crate::group::Group>) {
        self.asserted_groups = asserted;
        self.native_groups = native;
        self.rebuild_grouping();
    }

    /// Re-fuse the grouping from the stored asserted + native sources and the current facts'
    /// inference. Called whenever the facts change (startup, a zoom) so identity stays in sync.
    fn rebuild_grouping(&mut self) {
        self.grouping = crate::group::merge(
            self.asserted_groups.clone(),
            self.native_groups.clone(),
            crate::group::infer(&self.facts),
        );
    }

    /// Point the whole app at `range` with `facts` (already narrowed to it), rebuilding
    /// every derived view. Used by both zoom directions so all four views stay in sync.
    fn set_scope(&mut self, range: AddrRange, facts: Rc<HashMap<IpAddr, AddressFacts>>) {
        self.range = range;
        self.total = range.host_count().min(usize::MAX as u128) as usize;
        self.counts = reconcile::counts_from_facts(range.host_count(), &facts);
        let (graph, canvas) = build_graph(&facts);
        self.graph = graph;
        self.graph_canvas = canvas;
        self.facts = facts;
        self.rebuild_grouping();
        self.cur = ListCursor::new();
        self.tree_cur = 0;
        self.tree_expanded.clear();
        self.pan = (0, 0);
        self.map_cur = (0, 0);
        self.chooser = None; // a new scope has different sub-blocks; leave the chooser
        self.detail = false;
    }

    /// Keys for the tree view: move, expand/collapse a group, inspect a host.
    fn on_key_tree(&mut self, code: KeyCode) {
        let rows = super::tree::rows(self);
        if rows.is_empty() {
            return;
        }
        self.tree_cur = self.tree_cur.min(rows.len() - 1);
        let row = &rows[self.tree_cur];
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.quit = true,
            // Esc closes the inspect panel if open; never quits (only q/Q do).
            KeyCode::Esc => self.detail = false,
            KeyCode::Char('j') | KeyCode::Down => {
                if self.tree_cur + 1 < rows.len() {
                    self.tree_cur += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.tree_cur = self.tree_cur.saturating_sub(1);
            }
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
                if row.is_group {
                    if let Some(k) = &row.key {
                        if !self.tree_expanded.insert(k.clone()) {
                            self.tree_expanded.remove(k); // toggle: was present → collapse
                        }
                    }
                } else if let Some(addr) = row.addr {
                    self.inspect_addr(addr);
                }
            }
            KeyCode::Char('h') | KeyCode::Left => {
                // Collapse the group this row belongs to (its own, or its parent).
                if let Some(k) = row.key.clone() {
                    self.tree_expanded.remove(&k);
                }
            }
            _ => {}
        }
    }

    /// Open the inspect panel for `addr` by pointing the table cursor at its row — the
    /// address's whole-range index when enumerable, or its position among the known rows
    /// when sparse (so v6 inspect lands on the right row).
    fn inspect_addr(&mut self, addr: IpAddr) {
        let pos = if self.table_sparse() {
            self.known_rows().iter().position(|r| r.addr == addr)
        } else {
            self.range.host_index(addr).map(|i| i as usize)
        };
        if let Some(i) = pos {
            self.cur.cursor = i;
            self.detail = true;
        }
    }

    /// Keys for the table view: list navigation and the inspect panel.
    fn on_key_table(&mut self, code: KeyCode) {
        let len = self.table_len();
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.quit = true,
            // Esc closes the inspect panel if open; never quits (only q/Q do).
            KeyCode::Esc => self.detail = false,
            KeyCode::Enter => self.detail = !self.detail,
            KeyCode::Char('a') => self.start_alloc(),
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

    /// Keys for the graph view: pan the window across the canvas.
    fn on_key_graph(&mut self, code: KeyCode) {
        let (cw, ch) = self.graph_canvas.size();
        const STEP: u16 = 4;
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.quit = true,
            KeyCode::Left | KeyCode::Char('h') => self.pan.0 = self.pan.0.saturating_sub(STEP),
            KeyCode::Right | KeyCode::Char('l') => self.pan.0 = (self.pan.0 + STEP).min(cw.saturating_sub(1)),
            KeyCode::Up | KeyCode::Char('k') => self.pan.1 = self.pan.1.saturating_sub(STEP),
            KeyCode::Down | KeyCode::Char('j') => self.pan.1 = (self.pan.1 + STEP).min(ch.saturating_sub(1)),
            KeyCode::Char('g') | KeyCode::Home => self.pan = (0, 0),
            _ => {}
        }
    }

    /// Move the cursor to the next free address after the current one, wrapping
    /// around the range. Rows are computed on demand, so this scans lazily; on a
    /// mostly-empty range the next address is usually free, so it returns at once.
    fn jump_next_free(&mut self) {
        // In sparse mode the table lists only known (taken) addresses; "next free" over a
        // 2^N free space is meaningless, so it's a no-op there.
        if self.table_sparse() {
            self.status = Some(("next-free needs an enumerable range".to_string(), true));
            return;
        }
        let len = self.total;
        if len == 0 {
            return;
        }
        for step in 1..=len {
            let i = (self.cur.cursor + step) % len;
            if self.row_at(i).status.is_free() {
                self.cur.cursor = i;
                return;
            }
        }
    }
}

/// Build the cluster graph and its laid-out canvas from the known facts (bounded —
/// only addresses a source reported, never the whole range).
fn build_graph(facts: &HashMap<IpAddr, AddressFacts>) -> (DnsGraph, GraphCanvas) {
    let mut rows: Vec<AddressRow> = facts.values().map(reconcile::row_from_facts).collect();
    rows.sort_by_key(|r| r.addr);
    let graph = DnsGraph::from_rows(&rows);
    let canvas = graph.layout();
    (graph, canvas)
}

/// Enter the alternate screen, run the loop, and always restore the terminal.
///
/// # Errors
/// Propagates terminal setup / draw errors.
#[allow(clippy::too_many_arguments)] // a top-level wiring entry: each arg is a distinct startup input
pub fn run(
    range: Cidr,
    facts: Vec<AddressFacts>,
    subnets: Vec<Subnet>,
    write_mode: bool,
    dry_run: bool,
    live: bool,
    cfg: Config,
    initial_status: Option<String>,
    groups: (Vec<crate::group::Group>, Vec<crate::group::Group>),
) -> anyhow::Result<()> {
    let mut app = App::new(range, facts, write_mode, dry_run, live, cfg);
    app.set_subnets(subnets);
    app.set_group_sources(groups.0, groups.1);
    // A note carried in from startup (e.g. "discovered N blocks; browsing this one").
    if let Some(msg) = initial_status {
        app.status = Some((msg, false));
    }
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    term.enter()?;
    // Capture mouse events so the map can be clicked/scrolled; always released on the way out.
    let _ = crossterm::execute!(io::stdout(), crossterm::event::EnableMouseCapture);
    let result = main_loop(&mut term, &mut app);
    let _ = crossterm::execute!(io::stdout(), crossterm::event::DisableMouseCapture);
    term.leave()?;
    result
}

/// The draw / read-key loop: redraw, then wait up to one tick for a key.
fn main_loop(term: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> anyhow::Result<()> {
    let mut reader = EventReader::new();
    while !app.quit {
        app.poll_live();
        app.poll_apply();
        term.draw(|buf| match app.view {
            View::Table => draw::screen(buf, app),
            View::Graph => super::graph::screen(buf, app),
            View::Tree => super::tree::screen(buf, app),
            View::Map => super::map::screen(buf, app),
        })?;
        match reader.recv_timeout(RENDER_TICK) {
            Some(Event::Key(KeyEvent { code, .. })) => app.on_key(code),
            Some(Event::Mouse(ev)) => app.on_mouse(ev),
            _ => {}
        }
        // Service a live request here, where we own the terminal: the token fetch may
        // launch `pinentry`, which needs a normal tty *and* the keyboard to itself — so
        // we drop our stdin reader across the prompt, then bring it back.
        if app.take_live_request() {
            reader = fetch_token_and_spawn(term, reader, app)?;
        }
    }
    Ok(())
}

/// Fetch the NetBox token, then start the background sweep with it.
///
/// If the token is in the environment, `get_token` returns without prompting and the
/// screen is left untouched. Otherwise `pass`→`gpg`→`pinentry` needs the real terminal:
/// we drop the [`EventReader`] (so its thread stops consuming stdin and the passphrase
/// reaches pinentry), leave raw/alternate-screen mode, prompt, then restore both and
/// return a fresh reader. On failure the status line reports it and nothing is spawned.
fn fetch_token_and_spawn(
    term: &mut Terminal<CrosstermBackend<io::Stdout>>,
    reader: EventReader,
    app: &mut App,
) -> anyhow::Result<EventReader> {
    let env_token = std::env::var("CANOPY_NETBOX_TOKEN").is_ok_and(|v| !v.trim().is_empty());
    if env_token {
        match live::get_token(app.token_pass()) {
            Ok(tok) => app.spawn_live_gather(tok),
            Err(e) => app.set_status(format!("live load failed: {e}"), true),
        }
        return Ok(reader);
    }

    drop(reader); // stop the stdin-polling thread so pinentry gets the keystrokes
    term.leave()?; // cooked mode + main screen: pinentry owns the terminal
    eprintln!("canopy: unlocking the NetBox token (pass/gpg) — enter your passphrase…");
    let token = live::get_token(app.token_pass());
    term.enter()?; // back into the TUI …
    term.clear()?; // … and force a full repaint: pinentry scribbled over the screen,
                   // so mullion's cached model of it is stale and the diff would skip cells.
    match token {
        Ok(tok) => app.spawn_live_gather(tok),
        Err(e) => app.set_status(format!("live load failed: {e}"), true),
    }
    Ok(EventReader::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;
    use mullion::{Buffer, Rect};

    #[test]
    fn fixture_reconciles_to_expected_statuses() {
        let (range, facts) = fixture::demo();
        let app = App::new(range, facts, false, false, false, Config::default());
        assert!(app.counts.dns_only >= 10); // the -ipmi/-bmc/iprotect drift
        assert_eq!(app.counts.live_unregistered, 1); // the .90 squatter
        assert_eq!(app.counts.netbox_only, 5);
        assert!(app.counts.free > 200);
    }

    #[test]
    fn renders_without_panicking_at_many_sizes() {
        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        for (w, h) in [(120u16, 50u16), (80, 24), (40, 10), (24, 6), (20, 4)] {
            let mut buf = Buffer::empty(Rect::new(0, 0, w, h));
            draw::screen(&mut buf, &mut app);
        }
    }

    #[test]
    fn graph_view_renders_and_pans_without_panicking() {
        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        app.on_key(KeyCode::Tab); // switch to the graph view
        assert_eq!(app.view, View::Graph);
        assert!(app.graph.cluster_count() > 0);
        for (w, h) in [(120u16, 50u16), (80, 24), (40, 10), (24, 6)] {
            let mut buf = Buffer::empty(Rect::new(0, 0, w, h));
            crate::tui::graph::screen(&mut buf, &mut app);
            app.on_key(KeyCode::Right); // pan around while rendering
            app.on_key(KeyCode::Down);
        }
        app.on_key(KeyCode::Tab); // Graph → Tree
        app.on_key(KeyCode::Tab); // Tree → Map
        app.on_key(KeyCode::Tab); // Map → Table
        assert_eq!(app.view, View::Table);
    }

    #[test]
    fn inspect_panel_toggles_and_renders() {
        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        assert!(!app.detail);
        app.on_key(KeyCode::Enter);
        assert!(app.detail); // Enter opens the inspect panel
        app.cur.cursor = 10; // a dns-only row (10.87.3.11)
        let mut buf = Buffer::empty(Rect::new(0, 0, 90, 22));
        draw::screen(&mut buf, &mut app);
        app.on_key(KeyCode::Esc);
        assert!(!app.detail && !app.quit); // Esc closes the panel, does not quit
    }

    #[test]
    fn applying_live_facts_switches_source_and_rebuilds() {
        let (range, demo) = fixture::demo();
        let mut app = App::new(range, demo, false, false, false, Config::default());
        assert!(!app.live);
        // Demo start: not connected yet → the heartbeat is blue.
        assert!(matches!(app.heartbeat().color, Color::Rgb(80, 150, 255)));
        app.apply_live(LiveData {
            facts: vec![AddressFacts {
                addr: "10.87.3.5".parse().unwrap(),
                netbox: None,
                ptr: Some("thing.nfra.nl.".into()),
                live: false,
            }],
            subnets: vec![Subnet { cidr: Cidr::parse("10.87.3.0/26").unwrap(), name: "IPMI".into() }],
        });
        assert!(app.live && !app.loading);
        assert_eq!(app.counts.dns_only, 1); // the one supplied PTR
        assert_eq!(app.subnets.len(), 1); // subnets carried in from the gather
        // The heartbeat goes green once the endpoints have answered.
        assert!(matches!(app.heartbeat().color, Color::Rgb(90, 205, 110)));
        assert!(app.status.as_ref().is_some_and(|(m, e)| m.contains("loaded") && !*e));
    }

    #[test]
    fn allocate_flow_builds_plan_and_gates_apply() {
        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        // Cursor 0 is 10.87.3.1 (free in the fixture).
        app.on_key(KeyCode::Char('a'));
        assert!(app.alloc.is_some());
        for c in "dop370-ipmi.nfra.nl".chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Enter); // build the plan → Preview
        let flow = app.alloc.as_ref().unwrap();
        assert_eq!(flow.phase, AllocPhase::Preview);
        assert!(flow.plan.is_some());
        // Read-only: 'y' must NOT apply; it errors and keeps the overlay open.
        app.on_key(KeyCode::Char('y'));
        assert!(app.alloc.is_some());
        assert!(app.status.as_ref().is_some_and(|(_, e)| *e));
        app.on_key(KeyCode::Esc);
        assert!(app.alloc.is_none());
    }

    #[test]
    fn allocate_refuses_a_taken_row() {
        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        app.cur.cursor = 10; // 10.87.3.11, a dns-only (taken) row
        app.on_key(KeyCode::Char('a'));
        assert!(app.alloc.is_none());
        assert!(app.status.as_ref().is_some_and(|(_, e)| *e));
    }



    #[test]
    fn next_free_lands_on_a_free_address() {
        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        app.jump_next_free();
        assert!(app.row_at(app.cur.cursor).status.is_free());
    }

    #[test]
    fn tree_expands_collapses_and_inspects() {
        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        app.view = View::Tree;

        let collapsed = crate::tui::tree::rows(&app).len();
        // Groups are alphabetical after the root: (free), (unregistered), dop, …
        app.tree_cur = 3; // the "dop" group row
        app.on_key(KeyCode::Enter); // expand
        assert!(app.tree_expanded.contains("dop"));
        assert_eq!(crate::tui::tree::rows(&app).len(), collapsed + 2); // dop has 2 hosts

        // Enter on a host opens the inspect panel for that address.
        app.tree_cur = 4; // first dop host (10.87.3.68)
        app.on_key(KeyCode::Enter);
        assert!(app.detail);
        assert_eq!(app.row_at(app.cur.cursor).addr, "10.87.3.68".parse::<IpAddr>().unwrap());

        // Left collapses the group the cursor sits in.
        app.detail = false;
        app.tree_cur = 3;
        app.on_key(KeyCode::Left);
        assert!(!app.tree_expanded.contains("dop"));
    }


    #[test]
    fn tab_cycles_all_three_views() {
        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        assert_eq!(app.view, View::Table);
        app.on_key(KeyCode::Tab);
        assert_eq!(app.view, View::Graph);
        app.on_key(KeyCode::Tab);
        assert_eq!(app.view, View::Tree);
        app.on_key(KeyCode::Tab);
        assert_eq!(app.view, View::Map);
        app.on_key(KeyCode::Tab);
        assert_eq!(app.view, View::Table);
    }


    #[test]
    fn heartbeat_glows_a_bump_on_the_border() {
        use mullion::{Buffer, Rect};
        let area = Rect::new(0, 0, 24, 6);
        let mut buf = Buffer::empty(area);
        // t = 0 → the bump sits at the top-left corner (perimeter position 0).
        let beat = draw::Heartbeat { t: 0.0, color: Color::Rgb(90, 205, 110), pulse: false };
        let _ = draw::frame(&mut buf, area, "x", crate::tui::theme::s_title(), None, None, &beat);
        // The corner is tinted green (high G), while a far cell keeps the dim border.
        let corner = buf.get(0, 0).style.fg;
        assert!(matches!(corner, Color::Rgb(_, g, _) if g > 150), "bump greens the corner: {corner:?}");
        let far = buf.get(12, 5).style.fg; // opposite side of the ring
        assert!(matches!(far, Color::Rgb(70, 70, 100)), "far border stays dim: {far:?}");
    }

    #[test]
    fn sparse_ipv6_table_lists_known_only_with_true_free_count() {
        let range = Cidr::parse("2001:db8::/48").unwrap();
        let facts: Vec<AddressFacts> = (1..=5u128)
            .map(|i| AddressFacts {
                addr: IpAddr::V6(std::net::Ipv6Addr::from(u128::from(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)) + i)),
                netbox: None,
                ptr: Some(format!("h{i}.nfra.nl.")),
                live: false,
            })
            .collect();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        assert!(app.table_sparse());
        assert_eq!(app.table_len(), 5); // known addresses only, not 2^80 rows
        // Free count is the true 2^80 − 5, not the usize-clamped total.
        assert_eq!(app.counts.free, (1u128 << 80) - 5);
        assert_eq!(app.counts.dns_only, 5);
        // The cursor selects the i-th known address.
        app.cur.cursor = 2;
        assert_eq!(app.selected_row().unwrap().addr, "2001:db8::3".parse::<IpAddr>().unwrap());
        // 'G' jumps to the last known row, bounded by the known count, not the range size.
        app.on_key(KeyCode::Char('G'));
        assert_eq!(app.cur.cursor, 4);
    }

    #[test]
    fn ipv6_range_renders_every_view_without_panicking() {
        use mullion::{Buffer, Rect};
        let range = Cidr::parse("2001:db8::/48").unwrap();
        // A couple of v6 hosts near the network address.
        let facts: Vec<AddressFacts> = (1..=4u128)
            .map(|i| AddressFacts {
                addr: IpAddr::V6(std::net::Ipv6Addr::from(u128::from(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)) + i)),
                netbox: None,
                ptr: Some(format!("h{i}.nfra.nl.")),
                live: false,
            })
            .collect();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        assert!(!app.range.is_enumerable()); // a /48 is sparse
        assert_eq!(app.counts.dns_only, 4);
        for view in [View::Table, View::Graph, View::Tree, View::Map] {
            app.view = view;
            for (w, h) in [(90u16, 24u16), (40, 12)] {
                let mut buf = Buffer::empty(Rect::new(0, 0, w, h));
                match view {
                    View::Table => draw::screen(&mut buf, &mut app),
                    View::Graph => crate::tui::graph::screen(&mut buf, &mut app),
                    View::Tree => crate::tui::tree::screen(&mut buf, &mut app),
                    View::Map => crate::tui::map::screen(&mut buf, &mut app),
                }
            }
        }
    }

    #[test]
    fn every_view_draws_the_outer_frame() {
        use mullion::{Buffer, Rect};
        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        for view in [View::Table, View::Graph, View::Tree, View::Map] {
            app.view = view;
            let mut buf = Buffer::empty(Rect::new(0, 0, 90, 24));
            match view {
                View::Table => draw::screen(&mut buf, &mut app),
                View::Graph => crate::tui::graph::screen(&mut buf, &mut app),
                View::Tree => crate::tui::tree::screen(&mut buf, &mut app),
                View::Map => crate::tui::map::screen(&mut buf, &mut app),
            }
            // Rounded corners on all four corners of the frame.
            assert_eq!(buf.get(0, 0).symbol, "╭", "{view:?} top-left corner");
            assert_eq!(buf.get(89, 0).symbol, "╮", "{view:?} top-right corner");
            assert_eq!(buf.get(0, 23).symbol, "╰", "{view:?} bottom-left corner");
            // The title is bookended into the top edge (┤ … ├).
            let top: String = (0..90).map(|x| buf.get(x, 0).symbol.clone()).collect();
            assert!(top.contains("canopy"), "{view:?} title in the top border: {top:?}");
            assert!(top.contains('┤') && top.contains('├'), "{view:?} bookend caps");
        }
    }

    #[test]
    fn loading_draws_a_progress_bar_in_the_bottom_border() {
        use mullion::{Buffer, Rect};
        let (range, facts) = fixture::demo();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        app.loading = true;
        app.progress = Some((0.5, "DNS reverse sweep 2000/4000".into()));
        let mut buf = Buffer::empty(Rect::new(0, 0, 90, 24));
        draw::screen(&mut buf, &mut app);
        let bottom: String = (0..90).map(|x| buf.get(x, 23).symbol.clone()).collect();
        assert!(bottom.contains("DNS reverse sweep"), "bar label in bottom border: {bottom:?}");
        assert!(bottom.contains("50%"), "percentage shown: {bottom:?}");
        assert!(bottom.contains('█') && bottom.contains('░'), "half-filled bar: {bottom:?}");
        // The table shows its LOADING badge on the inner status row (row 1); its top
        // border carries the mode badge instead.
        let status_row: String = (0..90).map(|x| buf.get(x, 1).symbol.clone()).collect();
        assert!(status_row.contains("LOADING"), "loading badge on status row: {status_row:?}");
    }

    #[test]
    fn map_zoom_narrows_scope_and_zoom_out_restores_it() {
        // A /8 with one host outside the top-left cell; render sets the grid order,
        // then Enter zooms into the cursor cell and everything narrows to that subnet.
        let range = Cidr::parse("10.0.0.0/8").unwrap();
        let facts = vec![AddressFacts {
            addr: "10.1.0.5".parse().unwrap(),
            netbox: None,
            ptr: Some("thing.nfra.nl.".into()),
            live: false,
        }];
        let mut app = App::new(range, facts, false, false, false, Config::default());
        app.view = View::Map;
        // Render once so map_dims is set from the fitted grid.
        let mut buf = Buffer::empty(Rect::new(0, 0, 120, 50));
        crate::tui::map::screen(&mut buf, &mut app);
        let (w, h) = app.map_dims;
        assert!(w > 0 && h > 0);
        let parent_total = app.total;
        let top = AddrRange::from(range);

        // Move the cursor onto the cell whose slice actually holds the host, then zoom in.
        let host: IpAddr = "10.1.0.5".parse().unwrap();
        let grid = crate::map::MapGrid::build(app.range, &HashMap::new(), w, h);
        let d = (0..grid.cells()).find(|&d| grid.cell_range(d).contains(host)).unwrap();
        app.map_cur = grid.cell_xy(d);
        let target = app.cursor_range().unwrap();
        assert!(target.contains(host));
        app.on_key(KeyCode::Enter);
        assert_eq!(app.range, target);
        assert_eq!(app.scope_chain(), vec![top, target]); // parent › current
        assert!(app.total < parent_total);
        // The one host survived the narrowing (it lies inside the zoomed slice).
        assert_eq!(app.counts.dns_only, 1);
        assert_eq!(app.map_cur, (0, 0)); // cursor reset on scope change

        // Zoom back out restores the /8 and its full facts.
        app.on_key(KeyCode::Backspace);
        assert_eq!(app.range, top);
        assert_eq!(app.total, parent_total);
        assert_eq!(app.scope_chain(), vec![top]); // back to just the top scope
    }

    #[test]
    fn quadrant_chooser_steps_and_zooms_into_a_subblock() {
        let range = Cidr::parse("10.0.0.0/8").unwrap();
        let mut app = App::new(range, Vec::new(), false, false, false, Config::default());
        app.view = View::Map;
        let mut buf = Buffer::empty(Rect::new(0, 0, 120, 50));
        crate::tui::map::screen(&mut buf, &mut app); // sets map_dims
        let top = AddrRange::from(range);
        let subs = app.map_subblocks();
        assert!(subs.len() >= 2, "a big grid has ≥2 sub-blocks to choose between");

        // `z` enters the chooser on the sub-block under the cursor (cursor at (0,0) → block 0).
        app.on_key(KeyCode::Char('z'));
        assert_eq!(app.chooser, Some(0));
        app.on_key(KeyCode::Char('l')); // step to the next sub-block
        let sel = app.chooser.unwrap();
        assert!(sel < subs.len() && sel != 0);

        // Enter zooms into exactly that sub-block's address run, and leaves the chooser.
        let expected = top.span_slices(u128::from(app.map_dims.0) * u128::from(app.map_dims.1), subs[sel].d_range.start as u128, subs[sel].d_range.end as u128);
        app.on_key(KeyCode::Enter);
        assert_eq!(app.chooser, None);
        assert_eq!(app.range, expected);
        assert!(app.total < (top.host_count().min(usize::MAX as u128) as usize));
        assert_eq!(app.scope_chain(), vec![top, expected]);

        // Esc leaves the chooser without zooming; Backspace restored parent already, so re-enter.
        app.on_key(KeyCode::Char('z'));
        assert!(app.chooser.is_some());
        app.on_key(KeyCode::Esc);
        assert_eq!(app.chooser, None);
        assert_eq!(app.range, expected); // Esc in chooser did NOT zoom out
    }

    #[test]
    fn mouse_click_selects_the_cell_and_scroll_zooms() {
        use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
        let range = Cidr::parse("10.0.0.0/8").unwrap();
        let mut app = App::new(range, Vec::new(), false, false, false, Config::default());
        app.view = View::Map;
        let mut buf = Buffer::empty(Rect::new(0, 0, 120, 50));
        crate::tui::map::screen(&mut buf, &mut app); // sets map_dims + map_area
        let a = app.map_area;
        assert!(a.width > 0);

        // Left-click at a known screen position maps to grid cell ((col-x)/2, row-y).
        let (col, row) = (a.x + 8, a.y + 2);
        let click = MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column: col, row, modifiers: KeyModifiers::empty() };
        app.on_mouse(click);
        assert_eq!(app.map_cur, (4, 2));

        // Scroll up over a cell zooms into it; scroll down zooms back out.
        let parent = app.range;
        let scroll_up =
            MouseEvent { kind: MouseEventKind::ScrollUp, column: a.x + 20, row: a.y + 4, modifiers: KeyModifiers::empty() };
        app.on_mouse(scroll_up);
        assert_ne!(app.range, parent, "scroll-up zoomed into a sub-range");
        let scroll_down =
            MouseEvent { kind: MouseEventKind::ScrollDown, column: a.x, row: a.y, modifiers: KeyModifiers::empty() };
        app.on_mouse(scroll_down);
        assert_eq!(app.range, parent, "scroll-down zoomed back out");
    }

    #[test]
    fn subnet_outline_draws_a_boundary_when_toggled() {
        use crate::reconcile::Subnet;
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let mut app = App::new(range, Vec::new(), false, false, false, Config::default());
        app.view = View::Map;
        app.set_subnets(vec![
            Subnet { cidr: Cidr::parse("10.87.3.0/24").unwrap(), name: "control".into() },
            Subnet { cidr: Cidr::parse("10.87.3.64/26").unwrap(), name: "IPMI".into() },
        ]);
        let area = Rect::new(0, 0, 120, 50);
        let mut buf = Buffer::empty(area);
        crate::tui::map::screen(&mut buf, &mut app); // fix map_dims
        // Put the cursor inside the /26 so its most-specific subnet is IPMI.
        let (w, h) = app.map_dims;
        let grid = crate::map::MapGrid::build(app.range, &HashMap::new(), w, h);
        let host: IpAddr = "10.87.3.70".parse().unwrap();
        let d = (0..grid.cells()).find(|&d| grid.cell_range(d).contains(host)).unwrap();
        app.map_cur = grid.cell_xy(d);

        let symbols = |app: &mut App| {
            let mut b = Buffer::empty(area);
            crate::tui::map::screen(&mut b, app);
            (0..area.height).flat_map(|y| (0..area.width).map(move |x| (x, y))).map(|(x, y)| b.get(x, y).symbol.clone()).collect::<Vec<_>>()
        };
        let off = symbols(&mut app);
        app.show_subnets = true;
        let on = symbols(&mut app);
        assert_ne!(off, on, "toggling subnet outlines must change the render");
        // The /26 is a quarter of the /24, so its ring is on-screen (not clipped) — outline glyphs appear.
        let box_glyphs = ['╭', '╮', '╰', '╯', '─', '│', '├', '┤', '┬', '┴', '┼'];
        let count = |v: &[String]| v.iter().filter(|s| s.chars().next().is_some_and(|c| box_glyphs.contains(&c))).count();
        assert!(count(&on) > count(&off), "the outline adds box-drawing glyphs");
    }

    #[test]
    fn map_scheme_cycles_and_knobs_adjust() {
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let mut app = App::new(range, Vec::new(), false, false, false, Config::default());
        app.view = View::Map;
        assert_eq!(app.scheme, Scheme::default()); // the default look
        app.on_key(KeyCode::Char('p')); // cycle the scheme
        assert_ne!(app.scheme, Scheme::default());
        // The knob selector + adjust: pick 'ceiling' (index 1) and nudge it down.
        app.on_key(KeyCode::Char(']')); // active_knob 0 → 1 (ceiling)
        assert_eq!(app.active_knob, 1);
        let before = app.knobs.get(1);
        app.on_key(KeyCode::Char(',')); // decrease
        assert!(app.knobs.get(1) < before);
    }

    #[test]
    fn map_names_the_real_subnet_under_the_cursor() {
        use mullion::{Buffer, Rect};
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let mut app = App::new(range, Vec::new(), false, false, false, Config::default());
        app.set_subnets(vec![
            Subnet { cidr: Cidr::parse("10.87.3.0/24").unwrap(), name: "control".into() },
            Subnet { cidr: Cidr::parse("10.87.3.0/26").unwrap(), name: "IPMI".into() },
        ]);
        app.view = View::Map;
        let mut buf = Buffer::empty(Rect::new(0, 0, 88, 16));
        crate::tui::map::screen(&mut buf, &mut app);
        // The scope row is now the third header row above the grid (buffer row 3: top border
        // 0, legend 1, cursor-info 2, scope 3). It names the most-specific NetBox subnet at
        // the cursor: 10.87.3.0 → the /26, not the /24.
        let scope: String = (0..88).map(|x| buf.get(x, 3).symbol.clone()).collect();
        assert!(scope.contains("subnet: 10.87.3.0/26 (IPMI)"), "scope row: {scope:?}");
    }

    #[test]
    fn map_curve_walk_clamps_to_the_curve_ends() {
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let mut app = App::new(range, Vec::new(), false, false, false, Config::default());
        app.view = View::Map;
        let mut buf = Buffer::empty(Rect::new(0, 0, 120, 50));
        crate::tui::map::screen(&mut buf, &mut app);
        let (w, h) = app.map_dims;
        let total = (u128::from(w) * u128::from(h)) as usize;
        let g = mullion::spacefill::Gilbert::new(w, h);
        // Hammering forward along the curve lands on its last index (the endpoint), not a corner.
        for _ in 0..(total + 8) {
            app.on_key(KeyCode::Right);
            app.on_key(KeyCode::Down);
        }
        assert_eq!(g.xy_to_d(app.map_cur.0, app.map_cur.1), Some(total as u32 - 1));
        // And back the other way clamps at index 0 — the curve starts at the origin.
        for _ in 0..(total + 8) {
            app.on_key(KeyCode::Left);
            app.on_key(KeyCode::Up);
        }
        assert_eq!(app.map_cur, (0, 0));

        // A single step right advances exactly one cell along the curve.
        app.on_key(KeyCode::Right);
        assert_eq!(g.xy_to_d(app.map_cur.0, app.map_cur.1), Some(1));
    }

    #[test]
    fn jump_zone_leaps_to_the_next_occupied_run() {
        // Two occupied cells with a gap between them on the curve; `n` jumps to the run holding
        // the second, `N` back to the first.
        let range = Cidr::parse("10.87.3.0/24").unwrap();
        let hosts = ["10.87.3.5", "10.87.3.200"]; // far apart → different cells/zones
        let facts: Vec<AddressFacts> = hosts
            .iter()
            .map(|a| AddressFacts { addr: a.parse().unwrap(), netbox: None, ptr: Some("x.".into()), live: true })
            .collect();
        let mut app = App::new(range, facts, false, false, false, Config::default());
        app.view = View::Map;
        let mut buf = Buffer::empty(Rect::new(0, 0, 120, 50));
        crate::tui::map::screen(&mut buf, &mut app);
        let (w, h) = app.map_dims;
        let grid = crate::map::MapGrid::build(app.range, &app.facts, w, h);
        let occ_d = |app: &App| grid.xy_to_d(app.map_cur.0, app.map_cur.1).map(|d| grid.used[d as usize] > 0);

        app.map_cur = (0, 0);
        app.on_key(KeyCode::Char('n')); // → first occupied run
        assert_eq!(occ_d(&app), Some(true), "n landed on an occupied cell");
        let first = app.map_cur;
        app.on_key(KeyCode::Char('n')); // → the next occupied run
        assert_eq!(occ_d(&app), Some(true));
        assert_ne!(app.map_cur, first, "n advanced to a different occupied zone");
    }

    #[test]
    fn a_slash_8_is_lazy_and_paginates() {
        use mullion::VirtualList;
        let range = Cidr::parse("10.0.0.0/8").unwrap();
        // One known host in a 16M-address range — must be instant, not a 16M Vec.
        let facts = vec![AddressFacts {
            addr: "10.0.0.5".parse().unwrap(),
            netbox: None,
            ptr: Some("thing.nfra.nl.".into()),
            live: false,
        }];
        let app = App::new(range, facts, false, false, false, Config::default());
        assert_eq!(app.total, 16_777_214);
        assert_eq!(app.counts.free, 16_777_213); // total − the one known host
        assert_eq!(app.counts.dns_only, 1);

        // row_at anywhere is O(1); a deep index is free.
        assert!(app.row_at(10_000_000).status.is_free());
        assert_eq!(app.row_at(4).addr, "10.0.0.5".parse::<IpAddr>().unwrap());

        // The RangeSource drives a VirtualList over the /8, materializing only a window.
        let mut list = VirtualList::new(app.table_source(), 20, 32);
        assert!(!list.visible().is_empty());
        list.scroll_by(1_000_000);
        assert!(!list.visible().is_empty());
    }
}
