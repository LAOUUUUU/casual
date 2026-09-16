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
    tls10: bool,
    tls11: bool,
    tls12: bool,
    tls13: bool,
    validated: bool,
    warnings: Vec<String>,
    chain: Vec<CertInfo>,
}

// Legacy TLS record/handshake versions (rustls refuses to speak these, so we
// probe them by hand on the raw wire — see legacy_version_supported).
const TLS10: u16 = 0x0301;
const TLS11: u16 = 0x0302;

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

    // Fetch the chain with the user's options; if validation fails, retry
    // insecurely just to display the chain. If even that fails (e.g. a
    // TLS 1.0/1.1-only server, which rustls can't speak), carry on with no
    // chain — the legacy probe below still reports what the server supports.
    let (chain, negotiated, validated) = match do_handshake(&host, port, &args.tls) {
        Ok((c, v)) => (c, v, true),
        Err(_) => {
            let insecure = TlsOpts {
                insecure: true,
                cacert: None,
            };
            match do_handshake(&host, port, &insecure) {
                Ok((c, v)) => (c, v, false),
                Err(_) => (Vec::new(), None, false),
            }
        }
    };

    // Version support. 1.2/1.3 via rustls; 1.0/1.1 via a raw ClientHello,
    // since rustls won't speak them. All probed independently of cert validity.
    let tls10 = legacy_version_supported(&host, port, TLS10);
    let tls11 = legacy_version_supported(&host, port, TLS11);
    let tls12 = version_supported(&host, port, &rustls::version::TLS12);
    let tls13 = version_supported(&host, port, &rustls::version::TLS13);

    let mut warnings = Vec::new();
    if chain.is_empty() {
        warnings.push("no TLS 1.2/1.3 session established — cert chain not retrieved (server may be TLS 1.0/1.1 only)".into());
    } else if !validated {
        warnings.push("certificate did NOT validate against trusted roots (shown anyway; pass --cacert or --insecure)".into());
    }
    if tls10 || tls11 {
        warnings.push("server accepts deprecated TLS 1.0/1.1 — should be disabled".into());
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
        tls10,
        tls11,
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
        "TLS 1.0: {}   1.1: {}   1.2: {}   1.3: {}",
        yesno(audit.tls10),
        yesno(audit.tls11),
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
            Some(d) if d < 0 => println!("    EXPIRED {} days ago", -d),
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
    use x509_parser::extensions::GeneralName;
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
                        .map(|g| match g {
                            GeneralName::DNSName(s) => (*s).to_string(),
                            GeneralName::URI(s) => (*s).to_string(),
                            GeneralName::RFC822Name(s) => format!("email:{s}"),
                            GeneralName::IPAddress(b) => format!("ip:{}", fmt_ip(b)),
                            other => format!("{other:?}"),
                        })
                        .collect()
                })
                .unwrap_or_default();
            // Compute days-left ourselves: x509's time_to_expiration() returns
            // None for already-expired certs, which would read as "unparseable".
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let days_left = (cert.validity().not_after.timestamp() - now) / 86_400;
            CertInfo {
                subject: cert.subject().to_string(),
                issuer: cert.issuer().to_string(),
                not_before: cert.validity().not_before.to_string(),
                not_after: cert.validity().not_after.to_string(),
                days_left: Some(days_left),
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
                rec.port,
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

/// Probe, on the raw wire, whether the server negotiates exactly this legacy
/// TLS version. We hand-craft a ClientHello advertising `version` and read the
/// ServerHello's version back (or an alert / closed connection = no).
fn legacy_version_supported(host: &str, port: u16, version: u16) -> bool {
    let hello = build_client_hello(host, version);
    let Ok(mut sock) = TcpStream::connect((host, port)) else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(8)));
    if sock.write_all(&hello).is_err() {
        return false;
    }
    // TLS record header: content_type(1) legacy_version(2) length(2).
    let mut hdr = [0u8; 5];
    if sock.read_exact(&mut hdr).is_err() {
        return false;
    }
    let content_type = hdr[0];
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    // We need a handshake record (22) whose body is a ServerHello (type 2)
    // beginning handshake_type(1) length(3) server_version(2).
    if content_type != 22 || len < 6 {
        return false;
    }
    let mut body = [0u8; 6];
    if sock.read_exact(&mut body).is_err() {
        return false;
    }
    body[0] == 2 && u16::from_be_bytes([body[4], body[5]]) == version
}

fn build_client_hello(host: &str, version: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&version.to_be_bytes()); // client_version
    body.extend_from_slice(&[0x11u8; 32]); // random (fixed is fine for a probe)
    body.push(0); // session_id length

    // A spread of classic TLS 1.0/1.1-era cipher suites + the renegotiation SCSV.
    let suites: [u16; 9] = [
        0xC014, 0xC013, 0xC00A, 0xC009, 0x0035, 0x002F, 0x000A, 0x0005, 0x00FF,
    ];
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }
    body.push(1); // one compression method
    body.push(0); // null compression

    let ext = build_extensions(host);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    // Wrap in a handshake message, then a TLS record.
    let mut hs = Vec::with_capacity(body.len() + 4);
    hs.push(1); // client_hello
    let l = body.len();
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    hs.extend_from_slice(&body);

    let mut rec = Vec::with_capacity(hs.len() + 5);
    rec.push(22); // handshake
    rec.extend_from_slice(&TLS10.to_be_bytes()); // record layer version
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn build_extensions(host: &str) -> Vec<u8> {
    let mut ext = Vec::new();

    // SNI (host_name) — skip for bare IPs.
    if !host.is_empty() && host.parse::<std::net::IpAddr>().is_err() {
        let name = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // list length
        sni.push(0); // name_type = host_name
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);
    }

    // supported_groups: secp256r1, secp384r1 (so ECDHE suites can be chosen).
    let groups: [u16; 2] = [0x0017, 0x0018];
    let mut g = Vec::new();
    g.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for x in groups {
        g.extend_from_slice(&x.to_be_bytes());
    }
    ext.extend_from_slice(&0x000au16.to_be_bytes());
    ext.extend_from_slice(&(g.len() as u16).to_be_bytes());
    ext.extend_from_slice(&g);

    // ec_point_formats: uncompressed.
    ext.extend_from_slice(&0x000bu16.to_be_bytes());
    ext.extend_from_slice(&2u16.to_be_bytes());
    ext.extend_from_slice(&[1, 0]);

    ext
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

/// Format a raw IP address from a SAN (4 bytes = IPv4, 16 = IPv6).
fn fmt_ip(b: &[u8]) -> String {
    match b.len() {
        4 => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
        16 => {
            let mut segs = Vec::with_capacity(8);
            for i in 0..8 {
                segs.push(format!(
                    "{:x}",
                    u16::from_be_bytes([b[i * 2], b[i * 2 + 1]])
                ));
            }
            segs.join(":")
        }
        _ => format!("{b:?}"),
    }
}

fn split_target(t: &str, default_port: u16) -> (String, u16) {
    // Bracketed IPv6 ([::1] / [::1]:8443) — strip the brackets.
    if let Some(rest) = t.strip_prefix('[')
        && let Some((h, tail)) = rest.split_once(']')
    {
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return (h.to_string(), port);
    }
    match t.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (t.to_string(), default_port),
    }
}

fn parse_url(url: &str) -> Result<(String, String, u16, String)> {
    if url.chars().any(|c| c.is_whitespace()) {
        bail!("URL must not contain whitespace (percent-encode spaces as %20)");
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_well_formed() {
        let rec = build_client_hello("example.com", TLS10);
        // record: handshake(22), version 0x0301, length, then handshake body
        assert_eq!(rec[0], 22);
        assert_eq!(&rec[1..3], &[0x03, 0x01]);
        let rec_len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
        assert_eq!(rec_len, rec.len() - 5);
        // handshake: client_hello(1), 3-byte length, client_version
        assert_eq!(rec[5], 1);
        assert_eq!(&rec[9..11], &[0x03, 0x01]); // advertised client_version = TLS 1.0
    }

    #[test]
    fn parses_url_variants() {
        assert_eq!(
            parse_url("https://h/p").unwrap(),
            ("https".into(), "h".into(), 443, "/p".into())
        );
        assert_eq!(
            parse_url("http://h:81").unwrap(),
            ("http".into(), "h".into(), 81, "/".into())
        );
        assert!(parse_url("ftp://x").is_err());
    }
}
