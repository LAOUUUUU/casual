//! Network diagnostics (the `net` feature): `tls`, `probe`, `replay`.
//!
//!   tls    <host[:port]>   handshake and print the server's certificate chain
//!   probe  <url>           send one HTTP(S) request; show status/headers/timing
//!   replay <log.jsonl>     re-issue requests captured by `casual proxy`
//!
//! Uses the same rustls client stack as the intercept feature. All of this is
//! for hosts you own or are authorized to test.

use anyhow::{Context, Result, bail};
use clap::Args;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Args)]
pub struct TlsArgs {
    /// host or host:port (default port 443).
    pub target: String,
    /// Print the chain as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct ProbeArgs {
    /// URL, e.g. https://example.com/ or http://host:8080/path
    pub url: String,
    /// HTTP method.
    #[arg(short, long, default_value = "GET")]
    pub method: String,
    /// Print status/headers/timing as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(serde::Serialize)]
struct CertInfo {
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    days_left: Option<i64>,
    sans: Vec<String>,
}

#[derive(serde::Serialize)]
struct ProbeResult {
    status: String,
    headers: Vec<[String; 2]>,
    connect_ms: u128,
    total_ms: u128,
}

#[derive(Args)]
pub struct ReplayArgs {
    /// A JSONL log written by `casual proxy --log-file`.
    pub file: PathBuf,
    /// Only replay the first N requests.
    #[arg(short, long)]
    pub limit: Option<usize>,
}

// --- tls --------------------------------------------------------------------

pub fn tls(args: TlsArgs) -> Result<()> {
    install_provider();
    let (host, port) = split_target(&args.target, 443);
    let cfg = build_client_config();
    let name = ServerName::try_from(host.clone()).context("invalid host")?;
    let mut conn = ClientConnection::new(cfg, name)?;
    let mut sock = TcpStream::connect((host.as_str(), port))
        .with_context(|| format!("connecting {host}:{port}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;

    // Drive the handshake to completion so peer certs are available.
    while conn.is_handshaking() {
        if conn.complete_io(&mut sock).is_err() {
            break;
        }
    }
    let certs = conn
        .peer_certificates()
        .filter(|c| !c.is_empty())
        .context("server presented no certificates")?;

    let infos: Vec<CertInfo> = certs.iter().map(|der| parse_cert(der.as_ref())).collect();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&infos)?);
        return Ok(());
    }

    println!("{host}:{port} — {} certificate(s) in chain\n", infos.len());
    for (i, info) in infos.iter().enumerate() {
        println!("[{i}] subject: {}", info.subject);
        println!("    issuer:  {}", info.issuer);
        println!("    valid:   {} -> {}", info.not_before, info.not_after);
        match info.days_left {
            Some(d) => println!("    expires in {d} days"),
            None => println!("    EXPIRED or not yet valid / unparseable"),
        }
        if !info.sans.is_empty() {
            println!("    SANs:    {}", info.sans.join(", "));
        }
        println!();
    }
    Ok(())
}

fn parse_cert(der: &[u8]) -> CertInfo {
    match x509_parser::parse_x509_certificate(der) {
        Ok((_, cert)) => {
            let sans = cert
                .subject_alternative_name()
                .ok()
                .flatten()
                .map(|san| {
                    san.value
                        .general_names
                        .iter()
                        .map(|g| format!("{g:?}"))
                        .collect()
                })
                .unwrap_or_default();
            CertInfo {
                subject: cert.subject().to_string(),
                issuer: cert.issuer().to_string(),
                not_before: cert.validity().not_before.to_string(),
                not_after: cert.validity().not_after.to_string(),
                days_left: cert.validity().time_to_expiration().map(|d| d.whole_days()),
                sans,
            }
        }
        Err(e) => CertInfo {
            subject: format!("<unparseable: {e}>"),
            issuer: String::new(),
            not_before: String::new(),
            not_after: String::new(),
            days_left: None,
            sans: Vec::new(),
        },
    }
}

// --- probe ------------------------------------------------------------------

pub fn probe(args: ProbeArgs) -> Result<()> {
    install_provider();
    let (scheme, host, port, path) = parse_url(&args.url)?;
    let started = Instant::now();

    let tcp = TcpStream::connect((host.as_str(), port))
        .with_context(|| format!("connecting {host}:{port}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    let connect_ms = started.elapsed().as_millis();

    let head = if scheme == "https" {
        let cfg = build_client_config();
        let name = ServerName::try_from(host.clone()).context("invalid host")?;
        let conn = ClientConnection::new(cfg, name)?;
        let mut tls = StreamOwned::new(conn, tcp);
        exchange(&mut tls, &host, &args.method, &path)?
    } else {
        let mut plain = tcp;
        exchange(&mut plain, &host, &args.method, &path)?
    };
    let total_ms = started.elapsed().as_millis();

    let mut lines = head.lines();
    let status = lines.next().unwrap_or("(no status line)").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push([k.trim().to_string(), v.trim().to_string()]);
        }
    }

    if args.json {
        let result = ProbeResult {
            status,
            headers,
            connect_ms,
            total_ms,
        };
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    println!("{status}");
    for [k, v] in &headers {
        println!("  {k}: {v}");
    }
    println!("\nconnect {connect_ms} ms, total {total_ms} ms");
    Ok(())
}

// --- replay -----------------------------------------------------------------

#[derive(serde::Deserialize)]
struct LogRecord {
    kind: String,
    method: String,
    target: String,
    host: String,
    port: u16,
}

pub fn replay(args: ReplayArgs) -> Result<()> {
    install_provider();
    let text = std::fs::read_to_string(&args.file)
        .with_context(|| format!("reading {}", args.file.display()))?;

    let mut done = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(limit) = args.limit
            && done >= limit
        {
            break;
        }
        let rec: LogRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => continue,
        };
        done += 1;

        let (scheme, host, port, path, method) = match rec.kind.as_str() {
            "http" => {
                let (s, h, p, path) = parse_url(&rec.target).unwrap_or((
                    "http".into(),
                    rec.host.clone(),
                    rec.port,
                    "/".into(),
                ));
                (s, h, p, path, rec.method.clone())
            }
            // We only logged host:port for TLS tunnels, so replay as GET https://host/.
            _ => (
                "https".into(),
                rec.host.clone(),
                443,
                "/".into(),
                "GET".into(),
            ),
        };

        match probe_status(&scheme, &host, port, &method, &path) {
            Ok(status) => println!("{method} {scheme}://{host}{path} -> {status}"),
            Err(e) => println!("{method} {scheme}://{host}{path} -> error: {e}"),
        }
    }
    println!("\nreplayed {done} request(s).");
    Ok(())
}

fn probe_status(scheme: &str, host: &str, port: u16, method: &str, path: &str) -> Result<String> {
    let tcp =
        TcpStream::connect((host, port)).with_context(|| format!("connecting {host}:{port}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    let head = if scheme == "https" {
        let cfg = build_client_config();
        let name = ServerName::try_from(host.to_owned()).context("invalid host")?;
        let conn = ClientConnection::new(cfg, name)?;
        let mut tls = StreamOwned::new(conn, tcp);
        exchange(&mut tls, host, method, path)?
    } else {
        let mut plain = tcp;
        exchange(&mut plain, host, method, path)?
    };
    Ok(head.lines().next().unwrap_or("(no status)").to_string())
}

// --- shared helpers ---------------------------------------------------------

fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn build_client_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Send one request (forcing Connection: close) and return the response head.
fn exchange<S: Read + Write>(
    stream: &mut S,
    host: &str,
    method: &str,
    path: &str,
) -> Result<String> {
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: casual\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut head = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = stream.read(&mut b)?;
        if n == 0 {
            break;
        }
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") || head.len() > 64 * 1024 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

fn split_target(t: &str, default_port: u16) -> (String, u16) {
    match t.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (t.to_string(), default_port),
    }
}

fn parse_url(url: &str) -> Result<(String, String, u16, String)> {
    let (scheme, rest, default_port) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r, 443)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r, 80)
    } else {
        bail!("URL must start with http:// or https://");
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_target(authority, default_port);
    Ok((scheme.to_string(), host, port, path.to_string()))
}
