//! Network diagnostics (the `net` feature): `tls`, `probe`, `replay`.
//!
//!   tls    <host[:port]>   handshake, audit TLS versions, print the cert chain
//!   probe  <url>           send one HTTP(S) request; show status/headers/timing
//!   replay <log.jsonl>     re-issue requests captured by `casual proxy`
//!
//! Shared TLS-client options (all `net` commands):
//!   --insecure        skip certificate validation (like `curl -k`), for your
//!                     own dev/staging servers with self-signed/expired certs
//!   --cacert <pem>    trust an ADDITIONAL root CA (e.g. your internal CA),
//!                     without turning validation off entirely
//!
//! All of this is for hosts you own or are authorized to test.

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Shared TLS-client options.
#[derive(Args, Clone)]
pub struct TlsOpts {
    /// Skip certificate validation (DANGER — for your own hosts only).
    #[arg(long, global = true)]
    pub insecure: bool,

    /// Trust an additional root CA certificate (PEM) on top of the built-ins.
    #[arg(long, global = true)]
    pub cacert: Option<PathBuf>,
}

#[derive(Args)]
pub struct TlsArgs {
    /// host or host:port (default port 443).
    pub target: String,
    /// Print the audit + chain as JSON.
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub tls: TlsOpts,
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
    #[command(flatten)]
    pub tls: TlsOpts,
}

#[derive(Args)]
pub struct ReplayArgs {
    /// A JSONL log written by `casual proxy --log-file`.
    pub file: PathBuf,
    /// Only replay the first N requests.
    #[arg(short, long)]
    pub limit: Option<usize>,
    #[command(flatten)]
    pub tls: TlsOpts,
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
struct TlsAudit {
    host: String,
    port: u16,
    negotiated: Option<String>,
    tls12: bool,
    tls13: bool,
    validated: bool,
    warnings: Vec<String>,
    chain: Vec<CertInfo>,
}

#[derive(serde::Serialize)]
struct ProbeResult {
    status: String,
    headers: Vec<[String; 2]>,
    connect_ms: u128,
    total_ms: u128,
}

// --- tls (audit) ------------------------------------------------------------

pub fn tls(args: TlsArgs) -> Result<()> {
    install_provider();
    let (host, port) = split_target(&args.target, 443);

    // Fetch the chain with the user's options; if validation fails and they
    // didn't ask for --insecure, retry insecurely just to display the chain.
    let (chain, negotiated, validated) = match do_handshake(&host, port, &args.tls) {
        Ok((c, v)) => (c, v, true),
        Err(_) if !args.tls.insecure => {
            let insecure = TlsOpts {
                insecure: true,
                cacert: None,
            };
            let (c, v) = do_handshake(&host, port, &insecure)
                .context("TLS handshake failed even without verification")?;
            (c, v, false)
        }
        Err(e) => return Err(e),
    };

    // Version support (probed insecurely so cert validity doesn't skew it).
    let tls12 = version_supported(&host, port, &rustls::version::TLS12);
    let tls13 = version_supported(&host, port, &rustls::version::TLS13);

    let mut warnings = Vec::new();
    if !validated {
        warnings.push("certificate did NOT validate against trusted roots (shown anyway; pass --cacert or --insecure)".into());
    }
    if let Some(leaf) = chain.first() {
        match leaf.days_left {
            Some(d) if d < 0 => warnings.push("leaf certificate is EXPIRED".into()),
            Some(d) if d < 14 => warnings.push(format!("leaf certificate expires in {d} days")),
            None => warnings.push("leaf certificate validity is unparseable".into()),
            _ => {}
        }
        if chain.len() == 1 && !leaf.subject.is_empty() && leaf.subject == leaf.issuer {
            warnings.push("leaf certificate is self-signed".into());
        }
    }
    if !tls13 {
        warnings.push("server does not support TLS 1.3".into());
    }
    if !tls12 && !tls13 {
        warnings.push("server negotiated neither TLS 1.2 nor 1.3".into());
    }

    let audit = TlsAudit {
        host: host.clone(),
        port,
        negotiated,
        tls12,
        tls13,
        validated,
        warnings,
        chain,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&audit)?);
        return Ok(());
    }

    println!("{host}:{port}");
    println!(
        "negotiated {}   validated: {}",
        audit.negotiated.as_deref().unwrap_or("?"),
        if audit.validated { "yes" } else { "NO" }
    );
    println!(
        "TLS 1.2: {}   TLS 1.3: {}   (1.0/1.1 not probed — rustls speaks 1.2/1.3)",
        yesno(audit.tls12),
        yesno(audit.tls13)
    );
    if !audit.warnings.is_empty() {
        println!("\nwarnings:");
        for w in &audit.warnings {
            println!("  ! {w}");
        }
    }
    println!("\ncertificates ({}):", audit.chain.len());
    for (i, info) in audit.chain.iter().enumerate() {
        println!("[{i}] subject: {}", info.subject);
        println!("    issuer:  {}", info.issuer);
        println!("    valid:   {} -> {}", info.not_before, info.not_after);
        match info.days_left {
            Some(d) => println!("    expires in {d} days"),
            None => println!("    validity unparseable"),
        }
        if !info.sans.is_empty() {
            println!("    SANs:    {}", info.sans.join(", "));
        }
    }
    Ok(())
}

/// Handshake and return (parsed chain, negotiated version string).
fn do_handshake(host: &str, port: u16, opts: &TlsOpts) -> Result<(Vec<CertInfo>, Option<String>)> {
    let cfg = build_client_config(opts, None)?;
    let name = ServerName::try_from(host.to_owned()).context("invalid host")?;
    let mut conn = ClientConnection::new(cfg, name)?;
    let mut sock =
        TcpStream::connect((host, port)).with_context(|| format!("connecting {host}:{port}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)
            .map_err(|e| anyhow!("TLS handshake failed: {e}"))?;
    }
    let certs = conn
        .peer_certificates()
        .filter(|c| !c.is_empty())
        .context("server presented no certificates")?;
    let chain = certs.iter().map(|d| parse_cert(d.as_ref())).collect();
    let negotiated = conn.protocol_version().map(|v| format!("{v:?}"));
    Ok((chain, negotiated))
}

/// Does the server complete a handshake pinned to exactly this TLS version?
/// Probed with verification off, since we only care about version negotiation.
fn version_supported(host: &str, port: u16, v: &'static rustls::SupportedProtocolVersion) -> bool {
    let opts = TlsOpts {
        insecure: true,
        cacert: None,
    };
    let Ok(cfg) = build_client_config(&opts, Some(&[v])) else {
        return false;
    };
    let Ok(name) = ServerName::try_from(host.to_owned()) else {
        return false;
    };
    let Ok(mut conn) = ClientConnection::new(cfg, name) else {
        return false;
    };
    let Ok(mut sock) = TcpStream::connect((host, port)) else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(8)));
    while conn.is_handshaking() {
        if conn.complete_io(&mut sock).is_err() {
            return false;
        }
    }
    true
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
        let cfg = build_client_config(&args.tls, None)?;
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

        match probe_status(&scheme, &host, port, &method, &path, &args.tls) {
            Ok(status) => println!("{method} {scheme}://{host}{path} -> {status}"),
            Err(e) => println!("{method} {scheme}://{host}{path} -> error: {e}"),
        }
    }
    println!("\nreplayed {done} request(s).");
    Ok(())
}

fn probe_status(
    scheme: &str,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    opts: &TlsOpts,
) -> Result<String> {
    let tcp =
        TcpStream::connect((host, port)).with_context(|| format!("connecting {host}:{port}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    let head = if scheme == "https" {
        let cfg = build_client_config(opts, None)?;
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

fn build_client_config(
    opts: &TlsOpts,
    versions: Option<&[&'static rustls::SupportedProtocolVersion]>,
) -> Result<Arc<ClientConfig>> {
    let builder = match versions {
        Some(v) => ClientConfig::builder_with_protocol_versions(v),
        None => ClientConfig::builder(),
    };
    let cfg = if opts.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = &opts.cacert {
            add_cacert(&mut roots, path)?;
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    Ok(Arc::new(cfg))
}

fn add_cacert(roots: &mut RootCertStore, path: &Path) -> Result<()> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let mut added = 0;
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.context("parsing --cacert PEM")?;
        if roots.add(cert).is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        bail!("no certificates found in {}", path.display());
    }
    Ok(())
}

/// A certificate verifier that accepts everything — only used behind
/// `--insecure`, for inspecting your own hosts.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
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

fn yesno(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
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
