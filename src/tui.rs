/// ratatui-based TUI module for oxy live mode.
///
/// Provides a premium visual experience with:
/// - Unicode box drawing (╭─┬─╮╰─┴─╯)
/// - Braille sparklines (⣷⣶⣶⣿⣿⣶) for bandwidth history
/// - Gradient progress bars
/// - Status dots (●/○)
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
    text::Span,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
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
    fn new(_pid: u32, _name: String, max_len: usize) -> Self {
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
}

impl TuiApp {
    fn new(interval_secs: u64) -> Result<Self> {
        let interface =
            crate::limiter::get_default_interface().unwrap_or_else(|_| "unknown".to_string());

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
                    .or_insert_with(|| BandwidthHistory::new(proc.pid, proc.name.clone(), 6))
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
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    fn draw(&mut self, frame: &mut Frame) {
        // Main layout
        let main_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(10),   // Table
                Constraint::Length(1), // Footer
            ])
            .split(frame.area());

        // Draw header
        self.draw_header(frame, main_layout[0]);

        // Draw table
        self.draw_table(frame, main_layout[1]);

        // Draw footer
        self.draw_footer(frame, main_layout[2]);
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let header_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .border_set(symbols::border::ROUNDED);

        let header_text = format!(
            " {} {} │ {}s refresh │ Interface: {} │ RX: {} │ TX: {} │ Press 'q' to quit ",
            "oxy",
            "live",
            self.interval_secs,
            self.interface,
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
        // Define columns
        let header_cells = [
            "Status", "PID", "Process", "RX/s", "TX/s", "History", "RX Total", "TX Total",
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

        // Sort processes by total bandwidth rate
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
                let status = if is_limited { "●" } else { "○" };
                let status_color = if is_limited { Color::Red } else { Color::Green };

                let hist = self.history.get(&proc.pid);
                let rx_rate = hist.and_then(|h| h.rx_history.last()).copied().unwrap_or(0);
                let tx_rate = hist.and_then(|h| h.tx_history.last()).copied().unwrap_or(0);

                let sparkline_data: Vec<u64> =
                    hist.map(|h| h.rx_history.clone()).unwrap_or_default();

                // Create sparkline widget as text
                let history_str = if sparkline_data.is_empty() {
                    "—".to_string()
                } else {
                    // Simple sparkline representation with dynamic scaling
                    let chars = ["⣀", "⣄", "⣆", "⣇", "⣏", "⣟", "⣿"];
                    let max_val = sparkline_data.iter().copied().max().unwrap_or(1).max(1);
                    sparkline_data
                        .iter()
                        .map(|&v| {
                            if v == 0 {
                                "⣀"
                            } else {
                                let idx = ((v as f64 / max_val as f64) * 6.0) as usize;
                                chars[idx.min(6)]
                            }
                        })
                        .collect::<String>()
                };

                let cells = vec![
                    Cell::from(Span::styled(status, Style::default().fg(status_color))),
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
                Constraint::Length(15), // Process
                Constraint::Length(10), // RX/s
                Constraint::Length(10), // TX/s
                Constraint::Length(8),  // History
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
        );

        let mut table_state = TableState::default();
        frame.render_stateful_widget(table, area, &mut table_state);
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let footer_text = " [q] Quit │ ● Limited │ ○ Free │ Braille: ⣷ High ⣀ Low ";

        let footer = Paragraph::new(footer_text)
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center);

        frame.render_widget(footer, area);
    }
}

/// Run the ratatui TUI live mode.
pub fn run_live_tui(interval_secs: u64) -> Result<()> {
    // Setup terminal
    stdout().execute(EnterAlternateScreen)?;
    enable_raw_mode()?;

    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut app = TuiApp::new(interval_secs)?;

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

    // Cleanup
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    result
}
