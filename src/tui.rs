// SPDX-License-Identifier: GPL-3.0-only
/// ratatui-based TUI module for zelynic live mode.
///
/// Provides a premium visual experience with:
/// - Unicode box drawing (╭─┬─╮╰─┴─╯)
/// - Braille sparklines (⣷⣶⣶⣿⣿⣶) for bandwidth history
/// - Dual RX/TX sparklines with separator
/// - Table scrolling with j/k and arrow keys
/// - Status dots (●/○) for limited/free processes
/// - Persistent header/footer
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame, Terminal,
};
use std::{
    collections::HashMap,
    io::stdout,
    time::{Duration, Instant},
};

use crate::limiter::OxyState;
use crate::monitor::{aggregate_by_process, collect_bandwidth_stats, ProcessBandwidth};
use crate::units::format_bytes;

/// Number of history samples kept per process for sparklines.
const SPARKLINE_HISTORY_LEN: usize = 6;

/// Bandwidth history for sparklines (keeps last N seconds of data).
#[derive(Debug, Clone)]
pub struct BandwidthHistory {
    /// Download rates (bytes/s) for sparkline
    pub rx_history: Vec<u64>,
    /// Upload rates (bytes/s) for sparkline
    pub tx_history: Vec<u64>,
    /// Maximum history length
    max_len: usize,
}

impl BandwidthHistory {
    fn new(max_len: usize) -> Self {
        Self {
            rx_history: Vec::with_capacity(max_len),
            tx_history: Vec::with_capacity(max_len),
            max_len,
        }
    }

    fn update(&mut self, rx_rate: u64, tx_rate: u64) {
        if self.rx_history.len() >= self.max_len {
            self.rx_history.remove(0);
        }
        if self.tx_history.len() >= self.max_len {
            self.tx_history.remove(0);
        }
        self.rx_history.push(rx_rate);
        self.tx_history.push(tx_rate);
    }
}

/// Type alias for process snapshot data to reduce complexity.
type ProcessSnapshotData = HashMap<u32, (String, u64, u64)>;

/// TUI application state.
pub struct TuiApp {
    /// Update interval
    interval: Duration,
    /// Interval in seconds for display
    interval_secs: u64,
    /// Bandwidth history per process
    history: HashMap<u32, BandwidthHistory>,
    /// Previous snapshot for rate calculation
    prev_snapshot: Option<(Instant, ProcessSnapshotData)>,
    /// Current process data
    processes: Vec<ProcessBandwidth>,
    /// Total system RX
    total_rx: u64,
    /// Total system TX
    total_tx: u64,
    /// Interface name
    interface: String,
    /// Should quit
    should_quit: bool,
    /// Active limits (for status dots)
    limited_pids: std::collections::HashSet<u32>,
    /// Table scroll state
    table_state: TableState,
}

impl TuiApp {
    fn new_with_interface(interval_secs: u64, interface: &str) -> Result<Self> {
        let interface = interface.to_string();

        // Load active limits (non-fatal if state file is unreadable)
        let limited_pids: std::collections::HashSet<u32> = OxyState::load()
            .map(|s| s.limits.iter().map(|r| r.pid).collect())
            .unwrap_or_default();

        Ok(Self {
            interval: Duration::from_secs(interval_secs),
            interval_secs,
            history: HashMap::new(),
            prev_snapshot: None,
            processes: Vec::new(),
            total_rx: 0,
            total_tx: 0,
            interface,
            should_quit: false,
            limited_pids,
            table_state: TableState::default(),
        })
    }

    fn update(&mut self) -> Result<()> {
        let now = Instant::now();

        // Collect current stats
        let entries = collect_bandwidth_stats()?;
        self.processes = aggregate_by_process(&entries);

        // Calculate totals
        self.total_rx = self.processes.iter().map(|p| p.total_received).sum();
        self.total_tx = self.processes.iter().map(|p| p.total_sent).sum();

        // Build current snapshot
        let current: HashMap<u32, (String, u64, u64)> = self
            .processes
            .iter()
            .map(|p| (p.pid, (p.name.clone(), p.total_sent, p.total_received)))
            .collect();

        // Calculate rates and update history
        if let Some((prev_time, prev_data)) = self.prev_snapshot.take() {
            let elapsed = now.duration_since(prev_time).as_secs_f64().max(0.001);

            for proc in &self.processes {
                let rx_rate = prev_data
                    .get(&proc.pid)
                    .map(|prev| {
                        (proc.total_received.saturating_sub(prev.2) as f64 / elapsed) as u64
                    })
                    .unwrap_or(0);

                let tx_rate = prev_data
                    .get(&proc.pid)
                    .map(|prev| (proc.total_sent.saturating_sub(prev.1) as f64 / elapsed) as u64)
                    .unwrap_or(0);

                // Update history
                self.history
                    .entry(proc.pid)
                    .or_insert_with(|| BandwidthHistory::new(SPARKLINE_HISTORY_LEN))
                    .update(rx_rate, tx_rate);
            }
        }

        self.prev_snapshot = Some((now, current));

        // Refresh limited pids (non-fatal if state file is unreadable)
        if let Ok(state) = OxyState::load() {
            self.limited_pids = state.limits.iter().map(|r| r.pid).collect();
        }

        Ok(())
    }

    fn handle_input(&mut self) -> Result<()> {
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                        KeyCode::Char('c')
                            if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                        {
                            self.should_quit = true;
                        }
                        KeyCode::Char('j') | KeyCode::Down => self.scroll_down(),
                        KeyCode::Char('k') | KeyCode::Up => self.scroll_up(),
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    /// Move scroll position down by one row.
    fn scroll_down(&mut self) {
        if let Some(selected) = self.table_state.selected() {
            let last = self.processes.len().saturating_sub(1);
            let next = (selected.min(last) + 1).min(last);
            self.table_state.select(Some(next));
        } else if !self.processes.is_empty() {
            self.table_state.select(Some(0));
        }
    }

    /// Move scroll position up by one row.
    fn scroll_up(&mut self) {
        if let Some(selected) = self.table_state.selected() {
            self.table_state.select(Some(selected.saturating_sub(1)));
        } else if !self.processes.is_empty() {
            self.table_state
                .select(Some(self.processes.len().saturating_sub(1)));
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        // Main layout
        let main_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(10),   // Table / empty state
                Constraint::Length(1), // Footer
            ])
            .split(frame.area());

        // Draw header
        self.draw_header(frame, main_layout[0]);

        // Draw table or empty state
        self.draw_table(frame, main_layout[1]);

        // Draw footer
        self.draw_footer(frame, main_layout[2]);
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let header_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .border_set(symbols::border::ROUNDED);

        let process_count = self.processes.len();
        let header_text = format!(
            " {} {} │ {}s │ {} │ {} proc{} │ RX: {} │ TX: {} ",
            "zelynic",
            "live",
            self.interval_secs,
            self.interface,
            process_count,
            if process_count == 1 { "" } else { "s" },
            format_bytes(self.total_rx),
            format_bytes(self.total_tx)
        );

        let header = Paragraph::new(header_text)
            .block(header_block)
            .style(Style::default().fg(Color::White))
            .alignment(Alignment::Center);

        frame.render_widget(header, area);
    }

    fn draw_table(&mut self, frame: &mut Frame, area: Rect) {
        // Show empty state when no processes have network connections
        if self.processes.is_empty() {
            self.draw_empty_state(frame, area);
            return;
        }

        // Define columns
        let header_cells = [
            "Status",
            "PID",
            "Process",
            "RX/s",
            "TX/s",
            "History (RX|TX)",
            "RX Total",
            "TX Total",
        ]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        })
        .collect::<Vec<_>>();

        let header = Row::new(header_cells)
            .style(Style::default().bg(Color::DarkGray))
            .height(1);

        // Sort processes by total bandwidth rate descending
        let mut sorted_processes: Vec<_> = self.processes.iter().collect();
        sorted_processes.sort_by(|a, b| {
            let a_hist = self.history.get(&a.pid);
            let b_hist = self.history.get(&b.pid);
            let a_rate = a_hist
                .map(|h| h.rx_history.last().unwrap_or(&0) + h.tx_history.last().unwrap_or(&0))
                .unwrap_or(0);
            let b_rate = b_hist
                .map(|h| h.rx_history.last().unwrap_or(&0) + h.tx_history.last().unwrap_or(&0))
                .unwrap_or(0);
            b_rate.cmp(&a_rate) // Descending
        });

        // Build rows
        let rows: Vec<Row> = sorted_processes
            .iter()
            .map(|proc| {
                let is_limited = self.limited_pids.contains(&proc.pid);
                let status = if is_limited { "\u{25CF}" } else { "\u{25CB}" }; // ● / ○
                let status_color = if is_limited { Color::Red } else { Color::Green };

                let hist = self.history.get(&proc.pid);
                let rx_rate = hist.and_then(|h| h.rx_history.last()).copied().unwrap_or(0);
                let tx_rate = hist.and_then(|h| h.tx_history.last()).copied().unwrap_or(0);

                // Dual sparkline: RX↓ and TX↑ separated by │
                let history_str = match hist {
                    Some(h) if !h.rx_history.is_empty() || !h.tx_history.is_empty() => {
                        let rx_spark = build_sparkline(&h.rx_history, Color::Green);
                        let tx_spark = build_sparkline(&h.tx_history, Color::Yellow);
                        format!("{}\u{2502}{}", rx_spark, tx_spark) // │ separator
                    }
                    _ => "\u{2014}".to_string(), // —
                };

                let cells = vec![
                    Cell::from(Span::styled(
                        status.to_string(),
                        Style::default().fg(status_color),
                    )),
                    Cell::from(proc.pid.to_string()),
                    Cell::from(proc.name.clone()),
                    Cell::from(format_bytes(rx_rate) + "/s"),
                    Cell::from(format_bytes(tx_rate) + "/s"),
                    Cell::from(history_str).style(Style::default().fg(Color::Cyan)),
                    Cell::from(format_bytes(proc.total_received)),
                    Cell::from(format_bytes(proc.total_sent)),
                ];

                Row::new(cells).height(1)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(6),  // Status
                Constraint::Length(8),  // PID
                Constraint::Min(12),    // Process (flexible)
                Constraint::Length(10), // RX/s
                Constraint::Length(10), // TX/s
                Constraint::Length(15), // History (dual sparklines)
                Constraint::Length(12), // RX Total
                Constraint::Length(12), // TX Total
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .border_set(symbols::border::ROUNDED)
                .title("Bandwidth by Process"),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White));

        frame.render_stateful_widget(table, area, &mut self.table_state);
    }

    /// Draw centered empty state when no network connections are found.
    fn draw_empty_state(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .border_set(symbols::border::ROUNDED)
            .title("Bandwidth by Process");

        let empty_text = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "No active network connections",
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Waiting for network activity...",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "This interface may have no traffic or monitoring requires permissions.",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
        ])
        .block(block)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });

        frame.render_widget(empty_text, area);
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let footer_text =
            " [q] Quit │ [\u{2191}\u{2193}/j/k] Scroll │ \u{25CF} Limited │ \u{25CB} Free │ RX\u{2193}\u{2502}TX\u{2191} ";

        let footer = Paragraph::new(footer_text)
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center);

        frame.render_widget(footer, area);
    }
}

/// Build a braille sparkline string from a slice of bandwidth rate values.
///
/// Uses 7 braille levels from ⣀ (lowest) to ⣿ (highest) with dynamic
/// scaling relative to the maximum value in the data.
fn build_sparkline(data: &[u64], _color: Color) -> String {
    if data.is_empty() {
        return "\u{2014}".to_string(); // —
    }

    let chars = [
        "\u{2840}", "\u{2844}", "\u{2846}", "\u{2847}", "\u{284F}", "\u{285F}", "\u{28FF}",
    ];
    //          ⣀          ⣄          ⣆          ⣇          ⣏          ⣟          ⣿
    let max_val = data.iter().copied().max().unwrap_or(1).max(1);

    data.iter()
        .map(|&v| {
            if v == 0 {
                "\u{2840}" // ⣀
            } else {
                let idx = ((v as f64 / max_val as f64) * 6.0) as usize;
                chars[idx.min(6)]
            }
        })
        .collect::<String>()
}

/// Run the ratatui TUI live mode.
pub fn run_live_tui(interval_secs: u64, iface_override: Option<&str>) -> Result<()> {
    // Validate interface BEFORE entering alternate screen / raw mode,
    // so that errors can print cleanly without corrupting the terminal.
    let interface = match iface_override {
        Some(i) => {
            crate::limiter::validate_interface(i)?;
            i.to_string()
        }
        None => crate::limiter::get_default_interface().unwrap_or_else(|_| "unknown".to_string()),
    };

    // Setup terminal
    stdout().execute(EnterAlternateScreen)?;
    enable_raw_mode()?;

    // Install panic hook to restore terminal on panic.
    // We wrap the original hook in Arc so we can restore it after TUI exits.
    use std::sync::Arc;
    let original_hook = Arc::new(std::panic::take_hook());
    let panic_hook_ref = original_hook.clone();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
        panic_hook_ref(panic_info);
    }));

    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut app = TuiApp::new_with_interface(interval_secs, &interface)?;

    // Initial update
    app.update()?;

    let result = (|| -> Result<()> {
        let mut last_update = Instant::now();

        loop {
            // Draw
            terminal.draw(|f| app.draw(f))?;

            // Handle input
            app.handle_input()?;

            if app.should_quit {
                break;
            }

            // Update data periodically
            if last_update.elapsed() >= app.interval {
                app.update()?;
                last_update = Instant::now();
            }

            std::thread::sleep(Duration::from_millis(50));
        }

        Ok(())
    })();

    // Cleanup — always restore terminal, even on error
    let _ = disable_raw_mode();
    let _ = stdout().execute(LeaveAlternateScreen);

    // Restore original panic hook so subsequent panics (after TUI exit) don't
    // try to leave alternate screen again.
    let _ = std::panic::take_hook();
    std::panic::set_hook(Arc::try_unwrap(original_hook).unwrap_or_else(|arc| {
        // If Arc has extra references (shouldn't happen), create a no-op clone
        Box::new(move |info| arc(info))
    }));

    result
}
