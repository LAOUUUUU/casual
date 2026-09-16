//! `casual dash` (the `tui` feature) — a live, btop-style dashboard.
//!
//! Top half: a NETWORK monitor. The dashboard runs a proxy itself (on
//! 127.0.0.1:<port>), so the moment you point a browser/app at it, requests
//! stream into the table with live counters and a req/s sparkline.
//!
//! Bottom half: a PLUGINS picker (left) and a CONSOLE (right). Select a plugin
//! to drop its command into the console, or just type any casual command
//! (`dns example.com A`, `hash /etc/hosts`, `scan .`) and press Enter — it runs
//! as a subprocess and the output lands in the console pane.
//!
//! Tab cycles panels; q or Ctrl-C quits (Esc leaves the console back to panels).

use anyhow::Result;
use clap::Args;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Row, Sparkline, Table,
};
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::proxy::{self, RequestEvent};
use crate::{config, plugin};

#[derive(Args)]
pub struct DashArgs {
    /// Port for the built-in proxy (default: config `proxy_port`, else 8080).
    #[arg(short, long)]
    pub port: Option<u16>,
}

/// Shared network state, written by the embedded proxy thread.
#[derive(Default)]
struct Net {
    recent: VecDeque<RequestEvent>,
    total: u64,
    http: u64,
    connect: u64,
    hosts: HashMap<String, u64>,
    err: Option<String>,
}

impl Net {
    fn push(&mut self, ev: RequestEvent) {
        self.total += 1;
        if ev.kind == "http" {
            self.http += 1;
        } else {
            self.connect += 1;
        }
        *self.hosts.entry(ev.host.clone()).or_insert(0) += 1;
        self.recent.push_front(ev);
        self.recent.truncate(300);
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Focus {
    Net,
    Plugins,
    Console,
}

struct App {
    focus: Focus,
    plugins: Vec<(String, String, String)>,
    sel: usize,
    input: String,
    output: Vec<String>,
    running: usize,
    tx: Sender<Vec<String>>,
    rx: Receiver<Vec<String>>,
    rate: VecDeque<u64>,
    last_total: u64,
    last_tick: Instant,
    port: u16,
}

pub fn run(args: DashArgs) -> Result<()> {
    let port = args.port.unwrap_or_else(|| config::load().proxy_port());
    let net = Arc::new(Mutex::new(Net::default()));

    // Embedded proxy on its own thread; feeds the shared Net.
    {
        let ok = Arc::clone(&net);
        let err = Arc::clone(&net);
        thread::spawn(move || {
            let sink = Arc::clone(&ok);
            let served = proxy::serve_events("127.0.0.1", port, move |ev| {
                if let Ok(mut s) = sink.lock() {
                    s.push(ev);
                }
            });
            if let Err(e) = served
                && let Ok(mut s) = err.lock()
            {
                s.err = Some(e.to_string());
            }
        });
    }

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout))?;

    let result = run_loop(&mut term, &net, port);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    result
}

fn run_loop<B: Backend>(term: &mut Terminal<B>, net: &Arc<Mutex<Net>>, port: u16) -> Result<()> {
    let (tx, rx) = mpsc::channel::<Vec<String>>();
    let mut app = App {
        focus: Focus::Net,
        plugins: plugin::catalog(),
        sel: 0,
        input: String::new(),
        output: welcome(port),
        running: 0,
        tx,
        rx,
        rate: VecDeque::new(),
        last_total: 0,
        last_tick: Instant::now(),
        port,
    };

    loop {
        // Absorb finished command output.
        while let Ok(lines) = app.rx.try_recv() {
            app.output.extend(lines);
            let cap = 1000;
            if app.output.len() > cap {
                app.output.drain(0..app.output.len() - cap);
            }
            app.running = app.running.saturating_sub(1);
        }

        // Update the req/s history roughly once a second.
        if app.last_tick.elapsed() >= Duration::from_secs(1) {
            let total = net.lock().map(|s| s.total).unwrap_or(0);
            app.rate.push_back(total.saturating_sub(app.last_total));
            app.last_total = total;
            if app.rate.len() > 60 {
                app.rate.pop_front();
            }
            app.last_tick = Instant::now();
        }

        term.draw(|f| draw(f, &app, net))?;

        if event::poll(Duration::from_millis(200))?
            && let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
            && handle_key(k, &mut app)
        {
            return Ok(());
        }
    }
}

/// Returns true when the app should quit.
fn handle_key(k: KeyEvent, app: &mut App) -> bool {
    if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
        return true;
    }
    match app.focus {
        Focus::Console => match k.code {
            KeyCode::Esc => app.focus = Focus::Net,
            KeyCode::Tab => app.focus = next(app.focus),
            KeyCode::Enter => run_command(app),
            KeyCode::Backspace => {
                app.input.pop();
            }
            KeyCode::Char(c) => app.input.push(c),
            _ => {}
        },
        Focus::Plugins => match k.code {
            KeyCode::Char('q') => return true,
            KeyCode::Tab => app.focus = next(app.focus),
            KeyCode::Up => app.sel = app.sel.saturating_sub(1),
            KeyCode::Down => {
                if app.sel + 1 < app.plugins.len() {
                    app.sel += 1;
                }
            }
            KeyCode::Enter => {
                if let Some((name, _, _)) = app.plugins.get(app.sel) {
                    app.input = format!("{name} ");
                    app.focus = Focus::Console;
                }
            }
            _ => {}
        },
        Focus::Net => match k.code {
            KeyCode::Char('q') => return true,
            KeyCode::Tab => app.focus = next(app.focus),
            _ => {}
        },
    }
    false
}

fn next(f: Focus) -> Focus {
    match f {
        Focus::Net => Focus::Plugins,
        Focus::Plugins => Focus::Console,
        Focus::Console => Focus::Net,
    }
}

/// Run the console input as `casual <args>` in a subprocess (so its output is
/// captured instead of corrupting the TUI), appending the result when done.
fn run_command(app: &mut App) {
    let line = app.input.trim().to_string();
    app.input.clear();
    if line.is_empty() {
        return;
    }
    let parts: Vec<String> = line.split_whitespace().map(String::from).collect();
    let first = parts[0].clone();

    if matches!(first.as_str(), "live" | "dash" | "proxy") {
        app.output.push(format!("$ {line}"));
        app.output
            .push(format!("  refusing to run '{first}' inside the dashboard"));
        return;
    }

    // A bare plugin name is shorthand for `plugin run <name> ...`.
    let is_plugin = app.plugins.iter().any(|(n, _, _)| n == &first);
    let args: Vec<String> = if is_plugin {
        let mut v = vec!["plugin".to_string(), "run".to_string()];
        v.extend(parts);
        v
    } else {
        parts
    };

    app.output.push(format!("$ casual {}", args.join(" ")));
    app.running += 1;
    let tx = app.tx.clone();
    thread::spawn(move || {
        let exe = std::env::current_exe().unwrap_or_else(|_| "casual".into());
        let mut lines = Vec::new();
        match std::process::Command::new(exe).args(&args).output() {
            Ok(o) => {
                for l in String::from_utf8_lossy(&o.stdout).lines() {
                    lines.push(format!("  {l}"));
                }
                for l in String::from_utf8_lossy(&o.stderr).lines() {
                    lines.push(format!("  {l}"));
                }
                if lines.is_empty() {
                    lines.push("  (no output)".into());
                }
                if !o.status.success() {
                    lines.push(format!("  [exit {}]", o.status.code().unwrap_or(-1)));
                }
            }
            Err(e) => lines.push(format!("  error: {e}")),
        }
        let _ = tx.send(lines);
    });
}

fn welcome(port: u16) -> Vec<String> {
    vec![
        "casual dash — live network + plugin console".into(),
        format!("proxy listening on http://127.0.0.1:{port}"),
        "point your browser's HTTP+HTTPS proxy there to watch traffic above.".into(),
        "".into(),
        "type a command and press Enter, e.g.:".into(),
        "  dns example.com A      hash /etc/hosts      scan .".into(),
        "Tab switches panels · q or ^C quits.".into(),
    ]
}

fn draw(f: &mut Frame, app: &App, net: &Arc<Mutex<Net>>) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(50),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    draw_header(f, rows[0], app);
    draw_network(f, rows[1], app, net);
    draw_bottom(f, rows[2], app);
    draw_footer(f, rows[3], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let line = format!(
        " casual dash    proxy → http://127.0.0.1:{}    (set as your HTTP/HTTPS proxy)",
        app.port
    );
    let p = Paragraph::new(line)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(p, area);
}

fn draw_network(f: &mut Frame, area: Rect, app: &App, net: &Arc<Mutex<Net>>) {
    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    let s = net.lock().ok();
    let (total, http, https, hostn, err) = match &s {
        Some(n) => (n.total, n.http, n.connect, n.hosts.len(), n.err.clone()),
        None => (0, 0, 0, 0, None),
    };

    let stats = match err {
        Some(e) => Paragraph::new(format!("proxy error: {e}"))
            .style(Style::default().fg(Color::Red))
            .block(Block::default().borders(Borders::ALL).title("network")),
        None => Paragraph::new(format!(
            "requests {total}   http {http}   https {https}   unique hosts {hostn}"
        ))
        .block(Block::default().borders(Borders::ALL).title("network")),
    };
    f.render_widget(stats, inner[0]);

    let rate: Vec<u64> = app.rate.iter().copied().collect();
    let spark = Sparkline::default()
        .data(&rate)
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL).title("requests/sec"));
    f.render_widget(spark, inner[1]);

    let table_rows: Vec<Row> = s
        .iter()
        .flat_map(|n| n.recent.iter())
        .map(|e| {
            let color = if e.kind == "http" {
                Color::Green
            } else {
                Color::Magenta
            };
            Row::new(vec![
                hms(e.ts_ms),
                e.kind.to_string(),
                e.method.clone(),
                format!("{}:{}", e.host, e.port),
            ])
            .style(Style::default().fg(color))
        })
        .collect();
    let table = Table::new(
        table_rows,
        [
            Constraint::Length(10),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["time", "kind", "method", "host:port"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(border("recent requests", app.focus == Focus::Net));
    f.render_widget(table, inner[2]);
}

fn draw_bottom(f: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Min(0)])
        .split(area);

    // Plugins list.
    let items: Vec<ListItem> = app
        .plugins
        .iter()
        .map(|(name, desc, _)| ListItem::new(format!("{name:<10} {desc}")))
        .collect();
    let mut state = ListState::default();
    if !app.plugins.is_empty() {
        state.select(Some(app.sel.min(app.plugins.len() - 1)));
    }
    let list = List::new(items)
        .block(border(
            "plugins  (Enter → console)",
            app.focus == Focus::Plugins,
        ))
        .highlight_style(
            Style::default()
                .bg(Color::Cyan)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, cols[0], &mut state);

    // Console: output + input line.
    let con = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(cols[1]);

    let visible = con[0].height.saturating_sub(2) as usize;
    let start = app.output.len().saturating_sub(visible.max(1));
    let lines: Vec<Line> = app.output[start..]
        .iter()
        .map(|l| {
            if l.starts_with("$ ") {
                Line::styled(l.clone(), Style::default().fg(Color::Cyan))
            } else {
                Line::raw(l.clone())
            }
        })
        .collect();
    let out = Paragraph::new(lines).block(border("console", false));
    f.render_widget(out, con[0]);

    let cursor = if app.focus == Focus::Console {
        "█"
    } else {
        ""
    };
    let busy = if app.running > 0 { "  …running" } else { "" };
    let input = Paragraph::new(format!("> {}{cursor}{busy}", app.input))
        .block(border("command", app.focus == Focus::Console));
    f.render_widget(input, con[1]);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let hint = match app.focus {
        Focus::Net => "Tab: next panel   q: quit   ^C: quit",
        Focus::Plugins => "↑/↓: select   Enter: send to console   Tab: next   q: quit",
        Focus::Console => "type a command   Enter: run   Esc: leave console   ^C: quit",
    };
    f.render_widget(
        Paragraph::new(hint).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

/// A block whose border is highlighted when its panel has focus.
fn border(title: &str, focused: bool) -> Block<'_> {
    let color = if focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .title(title)
}

fn hms(ts_ms: u128) -> String {
    let secs = (ts_ms / 1000) % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}
