//! `casual dash` (the `tui` feature) — a live terminal dashboard that tails a
//! proxy JSONL log and shows requests streaming in, with running counters.
//!
//! It's deliberately decoupled from the proxy: run `casual proxy --log-file
//! traffic.jsonl` in one terminal and `casual dash traffic.jsonl` in another.
//! The dashboard just follows the file, so it never slows the proxy down.

use anyhow::Result;
use clap::Args;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Args)]
pub struct DashArgs {
    /// The proxy JSONL log to tail.
    #[arg(default_value = "traffic.jsonl")]
    pub log: PathBuf,
}

#[derive(serde::Deserialize, Clone)]
struct Record {
    ts_ms: u128,
    kind: String,
    method: String,
    host: String,
    port: u16,
}

#[derive(Default)]
struct State {
    recent: VecDeque<Record>,
    total: usize,
    http: usize,
    connect: usize,
    hosts: HashMap<String, usize>,
    offset: u64,
}

pub fn run(args: DashArgs) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, &args.log);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run_loop<B: Backend>(terminal: &mut Terminal<B>, path: &Path) -> Result<()> {
    let mut state = State::default();
    loop {
        poll_file(path, &mut state);
        terminal.draw(|f| draw(f, path, &state))?;

        if event::poll(Duration::from_millis(400))?
            && let Event::Key(k) = event::read()?
        {
            let quit = matches!(k.code, KeyCode::Char('q') | KeyCode::Esc)
                || (k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL));
            if quit {
                return Ok(());
            }
        }
    }
}

fn poll_file(path: &Path, state: &mut State) {
    let Ok(file) = File::open(path) else {
        return;
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if len < state.offset {
        state.offset = 0; // file was truncated/rotated
    }
    let mut reader = BufReader::new(file);
    if reader.seek(SeekFrom::Start(state.offset)).is_err() {
        return;
    }
    let mut line = String::new();
    loop {
        line.clear();
        let n = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 || !line.ends_with('\n') {
            break; // EOF or a partial line still being written
        }
        state.offset += n as u64;
        if let Ok(rec) = serde_json::from_str::<Record>(line.trim()) {
            state.total += 1;
            match rec.kind.as_str() {
                "http" => state.http += 1,
                "connect" | "intercept" => state.connect += 1,
                _ => {}
            }
            *state.hosts.entry(rec.host.clone()).or_insert(0) += 1;
            state.recent.push_front(rec);
            state.recent.truncate(200);
        }
    }
}

fn draw(f: &mut Frame, path: &Path, state: &State) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    let title = Paragraph::new(format!("casual dash — tailing {}", path.display()))
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let top_host = state
        .hosts
        .iter()
        .max_by_key(|(_, c)| **c)
        .map(|(h, c)| format!("{h} ({c})"))
        .unwrap_or_else(|| "-".into());
    let stats = Paragraph::new(format!(
        "requests {}   http {}   https {}   unique hosts {}   top {top_host}",
        state.total,
        state.http,
        state.connect,
        state.hosts.len()
    ))
    .block(Block::default().borders(Borders::ALL).title("stats"));
    f.render_widget(stats, chunks[1]);

    let rows = state.recent.iter().map(|r| {
        let kind_color = match r.kind.as_str() {
            "http" => Color::Green,
            "connect" | "intercept" => Color::Magenta,
            _ => Color::Gray,
        };
        Row::new(vec![
            Cell::from(hms(r.ts_ms)),
            Cell::from(r.kind.clone()).style(Style::default().fg(kind_color)),
            Cell::from(r.method.clone()),
            Cell::from(format!("{}:{}", r.host, r.port)),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["time(UTC)", "kind", "method", "host:port"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("recent requests"),
    );
    f.render_widget(table, chunks[2]);

    let footer = Paragraph::new("q or Esc to quit — waiting for traffic if empty")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[3]);
}

/// Epoch-ms to HH:MM:SS in UTC, no timezone crates.
fn hms(ts_ms: u128) -> String {
    let secs = (ts_ms / 1000) % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}
