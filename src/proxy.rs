//! A local HTTP(S) logging proxy.
//!
//! Point your browser/app's HTTP+HTTPS proxy at `127.0.0.1:<port>` and casual
//! logs what flows through. Plaintext HTTP is logged by method + URL (and, at
//! -v, headers) then forwarded. HTTPS (CONNECT) is logged by host:port and
//! tunneled byte-for-byte — it is NOT decrypted.
//!
//! Decrypting HTTPS (running your own CA and re-signing each site, how
//! mitmproxy/Burp work) lives behind the `intercept` cargo feature and the
//! `--intercept` flag. It only makes sense on devices you control and have
//! installed your CA on.
//!
//! Implementation is deliberately std-only: one thread per connection (capped),
//! two threads copying bytes for an established tunnel. No async runtime.

use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::{BufWriter, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

const MAX_HEAD_BYTES: usize = 64 * 1024;

#[derive(Args)]
pub struct ProxyArgs {
    /// Port to listen on (default: config `proxy_port`, else 8080).
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Address to bind (use 127.0.0.1 to stay local-only).
    #[arg(short, long, default_value = "127.0.0.1")]
    pub bind: String,

    /// Append one JSON object per request to this file (JSONL).
    #[arg(short, long)]
    pub log_file: Option<PathBuf>,

    /// Max concurrent connections before new ones get a 503 (default: config
    /// `max_conns`, else 256).
    #[arg(long)]
    pub max_conns: Option<usize>,

    /// Decrypt HTTPS via a local CA (needs `--features intercept`).
    #[arg(long)]
    pub intercept: bool,

    /// Block hosts containing this substring (repeatable); returns 403.
    #[arg(long)]
    pub block: Vec<String>,

    /// If given, allow ONLY hosts matching one of these substrings (repeatable).
    #[arg(long)]
    pub allow_only: Vec<String>,

    /// Save plain-HTTP request/response bodies into this directory.
    #[arg(long)]
    pub capture_dir: Option<PathBuf>,
}

#[derive(Serialize)]
struct LogRecord<'a> {
    ts_ms: u128,
    kind: &'a str,
    method: &'a str,
    target: &'a str,
    host: &'a str,
    port: u16,
}

struct ProxyState {
    log: Option<Mutex<BufWriter<std::fs::File>>>,
    block: Vec<String>,
    allow_only: Vec<String>,
    capture_dir: Option<PathBuf>,
    capture_seq: AtomicUsize,
}

impl ProxyState {
    /// Policy check: blocked substrings win; a non-empty allow-list means only
    /// matching hosts pass.
    fn allowed(&self, host: &str) -> bool {
        if self.block.iter().any(|b| host.contains(b.as_str())) {
            return false;
        }
        if !self.allow_only.is_empty() && !self.allow_only.iter().any(|a| host.contains(a.as_str()))
        {
            return false;
        }
        true
    }

    fn record(&self, kind: &str, method: &str, target: &str, host: &str, port: u16) {
        let Some(log) = &self.log else { return };
        let rec = LogRecord {
            ts_ms: now_ms(),
            kind,
            method,
            target,
            host,
            port,
        };
        if let Ok(line) = serde_json::to_string(&rec)
            && let Ok(mut w) = log.lock()
        {
            let _ = writeln!(w, "{line}");
            let _ = w.flush();
        }
    }
}

pub fn run(args: ProxyArgs) -> Result<()> {
    crate::notice::show();

    if args.intercept {
        #[cfg(feature = "intercept")]
        {
            return crate::intercept::run(args);
        }
        #[cfg(not(feature = "intercept"))]
        {
            anyhow::bail!(
                "--intercept needs a build with the intercept feature:\n  \
                 cargo build --release --features intercept\n\
                 then run `casual ca` once and install the printed CA cert."
            );
        }
    }

    let cfg = crate::config::load();
    let port = args.port.unwrap_or_else(|| cfg.proxy_port());
    let max_conns = args.max_conns.unwrap_or_else(|| cfg.max_conns());

    let addr = format!("{}:{}", args.bind, port);
    let listener = TcpListener::bind(&addr).with_context(|| format!("binding {addr}"))?;

    if let Some(dir) = &args.capture_dir {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating capture dir {}", dir.display()))?;
        info!("capturing plain-HTTP bodies to {}", dir.display());
    }

    let state = Arc::new(ProxyState {
        log: match &args.log_file {
            Some(path) => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .with_context(|| format!("opening log file {}", path.display()))?;
                info!("logging requests as JSONL to {}", path.display());
                Some(Mutex::new(BufWriter::new(file)))
            }
            None => None,
        },
        block: args.block.clone(),
        allow_only: args.allow_only.clone(),
        capture_dir: args.capture_dir.clone(),
        capture_seq: AtomicUsize::new(0),
    });

    info!("casual proxy listening on http://{addr}");
    info!("set that as your HTTP and HTTPS proxy. HTTPS is tunneled, not decrypted.");
    info!("use -v to also log request headers. Ctrl-C to stop.");

    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let mut client = match stream {
            Ok(c) => c,
            Err(e) => {
                warn!("accept failed: {e}");
                continue;
            }
        };

        // Connection cap: refuse rather than spawn unbounded threads.
        if active.load(Ordering::SeqCst) >= max_conns {
            warn!("at connection cap ({}), refusing", max_conns);
            let _ = client.write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
            continue;
        }

        active.fetch_add(1, Ordering::SeqCst);
        let state = Arc::clone(&state);
        let active_cl = Arc::clone(&active);
        thread::spawn(move || {
            if let Err(e) = handle(client, &state) {
                debug!("connection ended: {e}");
            }
            active_cl.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

fn handle(mut client: TcpStream, state: &ProxyState) -> Result<()> {
    // Timeout only while reading the head, so we never hang on a half-open
    // client. Cleared before tunneling so keep-alive/streaming isn't killed.
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    let head = read_head(&mut client)?;
    client.set_read_timeout(None)?;

    if head.is_empty() {
        return Ok(());
    }
    let head_str = String::from_utf8_lossy(&head);
    let first_line = head_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(&target, 443);
        if !state.allowed(&host) {
            warn!(%host, "blocked by policy");
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            return Ok(());
        }
        info!(target = %target, "HTTPS tunnel");
        state.record("connect", &method, &target, &host, port);
        let upstream =
            TcpStream::connect(&target).with_context(|| format!("connecting upstream {target}"))?;
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        tunnel(client, upstream)?;
    } else if !method.is_empty() {
        let (host, port, path) = parse_http_target(&target);
        if !state.allowed(&host) {
            warn!(%host, "blocked by policy");
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            return Ok(());
        }
        info!(%method, url = %target, "HTTP request");
        for line in head_str.lines().skip(1) {
            if line.is_empty() {
                break;
            }
            debug!("  {line}");
        }
        state.record("http", &method, &target, &host, port);
        let upstream_addr = format!("{host}:{port}");
        let mut upstream = TcpStream::connect(&upstream_addr)
            .with_context(|| format!("connecting upstream {upstream_addr}"))?;
        let rebuilt = rewrite_head(&head_str, &path);
        upstream.write_all(rebuilt.as_bytes())?;

        match capture_paths(state) {
            Some((req_path, resp_path)) => {
                tunnel_capture(client, upstream, rebuilt.as_bytes(), &req_path, &resp_path)?;
            }
            None => tunnel(client, upstream)?,
        }
    }
    Ok(())
}

/// Reserve a request/response file pair in the capture dir, if enabled.
fn capture_paths(state: &ProxyState) -> Option<(PathBuf, PathBuf)> {
    let dir = state.capture_dir.as_ref()?;
    let n = state.capture_seq.fetch_add(1, Ordering::SeqCst);
    Some((
        dir.join(format!("{n:05}.req")),
        dir.join(format!("{n:05}.resp")),
    ))
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// A single request seen by the embedded proxy, handed to a callback. Used by
/// the `dash` TUI so it can show live traffic without a separate proxy process
/// or a log file.
#[derive(Clone)]
pub struct RequestEvent {
    pub ts_ms: u128,
    pub kind: &'static str,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub target: String,
}

/// Run a minimal logging proxy that reports each request to `on_request` and
/// tunnels the bytes. No tracing/stdout output (safe to run under a TUI), no
/// policy/capture. Blocks forever; run it on its own thread.
pub fn serve_events<F>(bind: &str, port: u16, on_request: F) -> Result<()>
where
    F: Fn(RequestEvent) + Send + Sync + 'static,
{
    let listener =
        TcpListener::bind((bind, port)).with_context(|| format!("binding {bind}:{port}"))?;
    let cb: Arc<dyn Fn(RequestEvent) + Send + Sync> = Arc::new(on_request);
    for stream in listener.incoming() {
        let Ok(client) = stream else { continue };
        let cb = Arc::clone(&cb);
        thread::spawn(move || {
            let _ = handle_ev(client, cb.as_ref());
        });
    }
    Ok(())
}

fn handle_ev(mut client: TcpStream, cb: &(dyn Fn(RequestEvent) + Send + Sync)) -> Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    let head = read_head(&mut client)?;
    client.set_read_timeout(None)?;
    if head.is_empty() {
        return Ok(());
    }
    let head_str = String::from_utf8_lossy(&head);
    let first = head_str.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(&target, 443);
        cb(RequestEvent {
            ts_ms: now_ms(),
            kind: "connect",
            method,
            host: host.clone(),
            port,
            target: target.clone(),
        });
        let upstream = TcpStream::connect(&target)?;
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        tunnel(client, upstream)?;
    } else if !method.is_empty() {
        let (host, port, path) = parse_http_target(&target);
        cb(RequestEvent {
            ts_ms: now_ms(),
            kind: "http",
            method,
            host: host.clone(),
            port,
            target: target.clone(),
        });
        let mut upstream = TcpStream::connect(format!("{host}:{port}"))?;
        let rebuilt = rewrite_head(&head_str, &path);
        upstream.write_all(rebuilt.as_bytes())?;
        tunnel(client, upstream)?;
    }
    Ok(())
}

fn read_head(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") || buf.len() >= MAX_HEAD_BYTES {
            break;
        }
    }
    Ok(buf)
}

fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    }
}

pub fn parse_http_target(target: &str) -> (String, u16, String) {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_host_port(authority, 80);
    (host, port, path.to_string())
}

pub fn rewrite_head(head: &str, path: &str) -> String {
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut fp = first.split_whitespace();
    let method = fp.next().unwrap_or("GET");
    let _old_target = fp.next();
    let version = fp.next().unwrap_or("HTTP/1.1");

    let mut out = format!("{method} {path} {version}\r\n");
    for line in lines {
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}

fn tunnel(client: TcpStream, upstream: TcpStream) -> Result<()> {
    let client_read = client;
    let upstream_read = upstream.try_clone()?;
    let client_write = client_read.try_clone()?;
    let upstream_write = upstream;

    let a = thread::spawn(move || copy_dir(client_read, upstream_write));
    let b = thread::spawn(move || copy_dir(upstream_read, client_write));
    let _ = a.join();
    let _ = b.join();
    Ok(())
}

fn copy_dir(mut from: TcpStream, mut to: TcpStream) {
    let _ = std::io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
}

/// Like `tunnel`, but tees the client->upstream stream into `req_path` (seeded
/// with the already-parsed request head) and upstream->client into `resp_path`.
fn tunnel_capture(
    client: TcpStream,
    upstream: TcpStream,
    req_prefix: &[u8],
    req_path: &std::path::Path,
    resp_path: &std::path::Path,
) -> Result<()> {
    let mut req_file = std::fs::File::create(req_path).ok();
    if let Some(f) = req_file.as_mut() {
        let _ = f.write_all(req_prefix);
    }
    let resp_file = std::fs::File::create(resp_path).ok();

    let client_read = client;
    let upstream_read = upstream.try_clone()?;
    let client_write = client_read.try_clone()?;
    let upstream_write = upstream;

    let a = thread::spawn(move || tee_copy(client_read, upstream_write, req_file));
    let b = thread::spawn(move || tee_copy(upstream_read, client_write, resp_file));
    let _ = a.join();
    let _ = b.join();
    Ok(())
}

fn tee_copy(mut from: TcpStream, mut to: TcpStream, mut sink: Option<std::fs::File>) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if to.write_all(&buf[..n]).is_err() {
            break;
        }
        if let Some(s) = sink.as_mut() {
            let _ = s.write_all(&buf[..n]);
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_absolute_uri() {
        assert_eq!(
            parse_http_target("http://example.com:8080/a/b"),
            ("example.com".into(), 8080, "/a/b".into())
        );
        assert_eq!(
            parse_http_target("http://example.com/x"),
            ("example.com".into(), 80, "/x".into())
        );
        assert_eq!(
            parse_http_target("http://example.com"),
            ("example.com".into(), 80, "/".into())
        );
    }

    #[test]
    fn splits_connect_authority() {
        assert_eq!(
            split_host_port("example.com:443", 443),
            ("example.com".into(), 443)
        );
        assert_eq!(
            split_host_port("example.com", 443),
            ("example.com".into(), 443)
        );
    }

    #[test]
    fn rewrites_request_line_to_origin_form() {
        let head = "GET http://example.com/page HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let out = rewrite_head(head, "/page");
        assert!(out.starts_with("GET /page HTTP/1.1\r\n"));
        assert!(out.contains("Host: example.com\r\n"));
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn http_parsers_never_panic_on_garbage() {
        for t in [
            "",
            "http://",
            "https://:",
            "http://h:notaport/x",
            "://x",
            "http:///",
            "garbage",
            "http://[::1]:8080/y",
            ":",
        ] {
            let _ = parse_http_target(t);
        }
        for h in [
            "",
            "\r\n\r\n",
            "GET",
            "GET x",
            "GET x y z\r\n",
            "GET / HTTP/1.1\r\nno-colon-here\r\n\r\n",
        ] {
            let _ = rewrite_head(h, "/p");
        }
    }
}
