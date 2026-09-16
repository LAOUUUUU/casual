//! `casual dash` (the `tui` feature) — a live, btop-style dashboard.
//!
//! Top half: a live CONNECTIONS monitor. It samples the machine's established
//! TCP connections (via `lsof`) every couple of seconds — process, local and
//! remote address — so it's populated the moment you open it, no setup needed.
//!
//! Bottom half: a PLUGINS picker (left) and a CONSOLE (right). Select a plugin
//! to drop it into the console with its usage hint, or type any casual command
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
use std::collections::{HashSet, VecDeque};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::plugin;

#[derive(Args)]
pub struct DashArgs {
    /// Seconds between connection samples.
    #[arg(short, long, default_value_t = 2)]
    pub interval: u64,
}

struct Conn {
    command: String,
    pid: String,
    laddr: String,
    raddr: String,
}

/// Shared connection state, written by the sampler thread.
#[derive(Default)]
struct NetState {
    conns: Vec<Conn>,
    history: VecDeque<u64>,
    err: Option<String>,
    samples: u64,
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
}

pub fn run(args: DashArgs) -> Result<()> {
    let interval = Duration::from_secs(args.interval.max(1));
    let net = Arc::new(Mutex::new(NetState::default()));

    // Sampler thread: refresh the connection list on an interval.
    {
        let net = Arc::clone(&net);
        thread::spawn(move || {
            loop {
                let res = sample_connections();
                if let Ok(mut s) = net.lock() {
                    match res {
                        Ok(c) => {
                            s.history.push_back(c.len() as u64);
                            if s.history.len() > 60 {
                                s.history.pop_front();
                            }
                            s.conns = c;
                            s.err = None;
                            s.samples += 1;
                        }
                        Err(e) => s.err = Some(e),
                    }
                }
                thread::sleep(interval);
            }
        });
    }

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout))?;

    let result = run_loop(&mut term, &net);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    result
}

/// Sample established TCP connections via lsof.
fn sample_connections() -> std::result::Result<Vec<Conn>, String> {
    let out = Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:ESTABLISHED"])
        .output()
        .map_err(|e| format!("could not run lsof: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut conns = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 9 {
            continue;
        }
        // The address field is the token containing "->" (local->remote).
        let Some(name) = f.iter().find(|t| t.contains("->")) else {
            continue;
        };
        let Some((l, r)) = name.split_once("->") else {
            continue;
        };
        conns.push(Conn {
            command: f[0].to_string(),
            pid: f[1].to_string(),
            laddr: l.to_string(),
            raddr: r.to_string(),
        });
    }
    Ok(conns)
}

fn run_loop<B: Backend>(term: &mut Terminal<B>, net: &Arc<Mutex<NetState>>) -> Result<()> {
    let (tx, rx) = mpsc::channel::<Vec<String>>();
    let mut app = App {
        focus: Focus::Net,
        plugins: plugin::catalog(),
        sel: 0,
        input: String::new(),
        output: welcome(),
        running: 0,
        tx,
        rx,
    };

    loop {
        while let Ok(lines) = app.rx.try_recv() {
            app.output.extend(lines);
            let cap = 1000;
            if app.output.len() > cap {
                app.output.drain(0..app.output.len() - cap);
            }
            app.running = app.running.saturating_sub(1);
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
                if let Some((name, _, usage)) = app.plugins.get(app.sel) {
                    app.output.push(format!("hint: {usage}"));
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

/// Run the console input as `casual <args>` in a subprocess (captured so it
/// can't corrupt the TUI), appending the result when it finishes.
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
        match Command::new(exe).args(&args).output() {
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

fn welcome() -> Vec<String> {
    vec![
        "casual dash — live connections + plugin console".into(),
        "the top panel lists your machine's active TCP connections.".into(),
        "".into(),
        "type a command here and press Enter, e.g.:".into(),
        "  dns example.com A      hash /etc/hosts      scan .".into(),
        "or Tab to the plugins panel and pick one.".into(),
    ]
}

fn draw(f: &mut Frame, app: &App, net: &Arc<Mutex<NetState>>) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(50),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    draw_header(f, rows[0]);
    draw_network(f, rows[1], app, net);
    draw_bottom(f, rows[2], app);
    draw_footer(f, rows[3], app);
}

fn draw_header(f: &mut Frame, area: Rect) {
    let p = Paragraph::new(" casual dash    live TCP connections + plugin console")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(p, area);
}

fn draw_network(f: &mut Frame, area: Rect, app: &App, net: &Arc<Mutex<NetState>>) {
    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    let s = net.lock().ok();

    // Stats / error line.
    let stats = match s.as_deref() {
        Some(n) if n.err.is_some() => Paragraph::new(n.err.clone().unwrap())
            .style(Style::default().fg(Color::Red))
            .block(Block::default().borders(Borders::ALL).title("connections")),
        Some(n) => {
            let hosts: HashSet<&str> = n.conns.iter().map(|c| remote_host(&c.raddr)).collect();
            let procs: HashSet<&str> = n.conns.iter().map(|c| c.command.as_str()).collect();
            let waiting = if n.samples == 0 {
                "  (sampling…)"
            } else {
                ""
            };
            Paragraph::new(format!(
                "connections {}   remote hosts {}   processes {}{waiting}",
                n.conns.len(),
                hosts.len(),
                procs.len()
            ))
            .block(Block::default().borders(Borders::ALL).title("connections"))
        }
        None => {
            Paragraph::new("").block(Block::default().borders(Borders::ALL).title("connections"))
        }
    };
    f.render_widget(stats, inner[0]);

    let history: Vec<u64> = s
        .as_deref()
        .map(|n| n.history.iter().copied().collect())
        .unwrap_or_default();
    let spark = Sparkline::default()
        .data(&history)
        .style(Style::default().fg(Color::Green))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("connection count"),
        );
    f.render_widget(spark, inner[1]);

    let table_rows: Vec<Row> = s
        .as_deref()
        .map(|n| {
            n.conns
                .iter()
                .map(|c| {
                    Row::new(vec![
                        c.command.clone(),
                        c.pid.clone(),
                        c.laddr.clone(),
                        c.raddr.clone(),
                    ])
                })
                .collect()
        })
        .unwrap_or_default();
    let table = Table::new(
        table_rows,
        [
            Constraint::Length(16),
            Constraint::Length(8),
            Constraint::Percentage(38),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["process", "pid", "local", "remote"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(border("connections (lsof)", app.focus == Focus::Net));
    f.render_widget(table, inner[2]);
}

fn draw_bottom(f: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Min(0)])
        .split(area);

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

    let con = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(cols[1]);

    let visible = con[0].height.saturating_sub(2).max(1) as usize;
    let start = app.output.len().saturating_sub(visible);
    let lines: Vec<Line> = app.output[start..]
        .iter()
        .map(|l| {
            if l.starts_with("$ ") {
                Line::styled(l.clone(), Style::default().fg(Color::Cyan))
            } else if l.starts_with("hint:") {
                Line::styled(l.clone(), Style::default().fg(Color::Yellow))
            } else {
                Line::raw(l.clone())
            }
        })
        .collect();
    f.render_widget(
        Paragraph::new(lines).block(border("console", false)),
        con[0],
    );

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

/// Strip the port from a remote address (`1.2.3.4:443` or `[::1]:443`).
fn remote_host(addr: &str) -> &str {
    match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    }
}
