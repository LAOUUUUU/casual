//! HTTPS interception (the `intercept` feature).
//!
//! This is the real "decrypt your own TLS" mode, the mitmproxy/Burp model:
//!   1. `casual ca` makes a local Certificate Authority and you install it as
//!      trusted on the device you're inspecting.
//!   2. `casual proxy --intercept` then, for each HTTPS site, mints a leaf
//!      certificate for that hostname signed by your CA, terminates TLS toward
//!      the client, opens its own verified TLS connection to the real server,
//!      and relays the now-plaintext HTTP while logging it.
//!
//! ONLY works on devices where you installed the CA, i.e. your own. Installing
//! a CA that can decrypt traffic on a machine you don't control is exactly the
//! kind of thing the legal notice is about.
//!
//! Simplifying choice: each intercepted TLS connection carries ONE
//! request/response (we force `Connection: close`). That keeps the relay
//! trivial and correct; it's ideal for inspecting API calls and page loads,
//! and not meant to be a high-throughput proxy.

use crate::proxy::ProxyArgs;
use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use tracing::{debug, info, warn};

const MAX_HEAD: usize = 64 * 1024;

/// The CA, reconstructed so it can sign leaf certificates.
struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

pub fn run(args: ProxyArgs) -> Result<()> {
    install_crypto_provider();
    let ca = Arc::new(load_ca().context(
        "no intercept CA found. Run `casual ca` once, then install the printed certificate.",
    )?);
    let client_config = Arc::new(build_client_config());

    let port = args
        .port
        .unwrap_or_else(|| crate::config::load().proxy_port());
    let addr = format!("{}:{}", args.bind, port);
    let listener = TcpListener::bind(&addr).with_context(|| format!("binding {addr}"))?;
    info!("casual proxy (INTERCEPT) listening on http://{addr}");
    info!("HTTPS is DECRYPTED using your local CA. Devices you control only.");

    for stream in listener.incoming() {
        let client = match stream {
            Ok(c) => c,
            Err(e) => {
                warn!("accept failed: {e}");
                continue;
            }
        };
        let ca = Arc::clone(&ca);
        let cc = Arc::clone(&client_config);
        thread::spawn(move || {
            if let Err(e) = handle(client, &ca, &cc) {
                debug!("connection ended: {e}");
            }
        });
    }
    Ok(())
}

fn handle(mut client: TcpStream, ca: &Ca, client_config: &Arc<ClientConfig>) -> Result<()> {
    let head = read_head(&mut client)?;
    if head.is_empty() {
        return Ok(());
    }
    let head_str = String::from_utf8_lossy(&head);
    let first = head_str.lines().next().unwrap_or("");
    let mut it = first.split_whitespace();
    let method = it.next().unwrap_or("").to_string();
    let target = it.next().unwrap_or("").to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(&target, 443);
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        if let Err(e) = intercept_tls(client, &host, port, ca, client_config) {
            debug!("intercept {host}:{port} failed: {e}");
        }
    } else if !method.is_empty() {
        // Plain HTTP needs no decryption; forward it and log.
        forward_plain(client, &head_str, &method, &target)?;
    }
    Ok(())
}

fn intercept_tls(
    client_tcp: TcpStream,
    host: &str,
    port: u16,
    ca: &Ca,
    client_config: &Arc<ClientConfig>,
) -> Result<()> {
    // 1. Terminate TLS toward the client with a leaf cert we sign for `host`.
    let server_config = build_server_config(host, ca)?;
    let server_conn = ServerConnection::new(server_config)?;
    let mut client_tls = StreamOwned::new(server_conn, client_tcp);

    // 2. Open our own verified TLS connection to the real upstream.
    let upstream_tcp = TcpStream::connect((host, port))
        .with_context(|| format!("connecting upstream {host}:{port}"))?;
    let name = ServerName::try_from(host.to_owned()).context("invalid server name")?;
    let client_conn = ClientConnection::new(Arc::clone(client_config), name)?;
    let mut upstream_tls = StreamOwned::new(client_conn, upstream_tcp);

    // 3. Read the (decrypted) request from the client.
    let head = read_head(&mut client_tls)?;
    if head.is_empty() {
        return Ok(());
    }
    let head_str = String::from_utf8_lossy(&head);
    let first = head_str.lines().next().unwrap_or("");
    let mut it = first.split_whitespace();
    let method = it.next().unwrap_or("");
    let path = it.next().unwrap_or("");
    info!(%method, host = %host, %path, "intercepted HTTPS request");

    // 4. Forward it upstream, forcing a single request/response.
    let content_length = parse_content_length(&head_str);
    let rebuilt = force_connection_close(&head_str);
    upstream_tls.write_all(rebuilt.as_bytes())?;
    if content_length > 0 {
        copy_n(&mut client_tls, &mut upstream_tls, content_length)?;
    }
    upstream_tls.flush()?;

    // 5. Relay the whole response back to the client until upstream closes.
    io::copy(&mut upstream_tls, &mut client_tls)?;
    Ok(())
}

fn forward_plain(mut client: TcpStream, head_str: &str, method: &str, target: &str) -> Result<()> {
    let (host, port, path) = parse_http_target(target);
    info!(%method, url = %target, "HTTP request (plain)");
    let mut upstream = TcpStream::connect((host.as_str(), port))
        .with_context(|| format!("connecting {host}:{port}"))?;

    // origin-form request line
    let mut lines = head_str.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut fp = first.split_whitespace();
    let m = fp.next().unwrap_or("GET");
    let _ = fp.next();
    let v = fp.next().unwrap_or("HTTP/1.1");
    let mut rebuilt = format!("{m} {path} {v}\r\n");
    for line in lines {
        rebuilt.push_str(line);
        rebuilt.push_str("\r\n");
    }
    upstream.write_all(rebuilt.as_bytes())?;

    let mut up_read = upstream.try_clone()?;
    let mut cl_write = client.try_clone()?;
    let t = thread::spawn(move || {
        let _ = io::copy(&mut up_read, &mut cl_write);
    });
    let _ = io::copy(&mut client, &mut upstream);
    let _ = t.join();
    Ok(())
}

// --- CA + certificate machinery --------------------------------------------

fn install_crypto_provider() {
    // Idempotent; ignore the error if another thread already installed it.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn config_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join(".config/casual"))
}

fn ca_paths() -> Result<(PathBuf, PathBuf)> {
    let dir = config_dir()?;
    Ok((dir.join("ca.pem"), dir.join("ca-key.pem")))
}

fn load_ca() -> Result<Ca> {
    let (cert_path, key_path) = ca_paths()?;
    let cert_pem = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?;
    let key_pem = std::fs::read_to_string(&key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;
    let key = KeyPair::from_pem(&key_pem).context("parsing CA key")?;
    // Reconstruct the CA params from the stored cert so we can use it as issuer.
    let params = CertificateParams::from_ca_cert_pem(&cert_pem).context("parsing CA cert")?;
    let cert = params.self_signed(&key).context("rebuilding CA cert")?;
    Ok(Ca { cert, key })
}

/// Create the CA if missing, then print where it is and how to trust it.
pub fn ensure_ca_and_print() -> Result<()> {
    let (cert_path, key_path) = ca_paths()?;
    if !cert_path.exists() || !key_path.exists() {
        std::fs::create_dir_all(config_dir()?)?;
        let key = KeyPair::generate().context("generating CA key")?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "casual local CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "casual");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).context("self-signing CA")?;
        std::fs::write(&cert_path, cert.pem())?;
        std::fs::write(&key_path, key.serialize_pem())?;
        println!("created a new CA:");
    } else {
        println!("CA already exists:");
    }
    println!("  cert: {}", cert_path.display());
    println!("  key:  {}  (keep this private)", key_path.display());
    println!();
    println!("Install the cert as trusted, on THIS machine only:");
    println!("  macOS : sudo security add-trusted-cert -d -r trustRoot \\");
    println!(
        "            -k /Library/Keychains/System.keychain {}",
        cert_path.display()
    );
    println!(
        "  Linux : copy it into /usr/local/share/ca-certificates/ and run update-ca-certificates"
    );
    println!("  Firefox uses its own store: Settings > Certificates > Import.");
    println!();
    println!("Then: casual proxy --intercept   (and set 127.0.0.1:8080 as your proxy)");
    Ok(())
}

fn build_server_config(host: &str, ca: &Ca) -> Result<Arc<ServerConfig>> {
    let leaf_key = KeyPair::generate().context("generating leaf key")?;
    let mut params = CertificateParams::new(vec![host.to_string()]).context("leaf params")?;
    params.distinguished_name.push(DnType::CommonName, host);
    let leaf = params
        .signed_by(&leaf_key, &ca.cert, &ca.key)
        .context("signing leaf cert")?;

    let certs: Vec<CertificateDer<'static>> = vec![leaf.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building server config")?;
    Ok(Arc::new(config))
}

fn build_client_config() -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

// --- small HTTP helpers -----------------------------------------------------

fn read_head<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut b = [0u8; 1];
    loop {
        let n = r.read(&mut b)?;
        if n == 0 {
            break;
        }
        buf.push(b[0]);
        if buf.ends_with(b"\r\n\r\n") || buf.len() >= MAX_HEAD {
            break;
        }
    }
    Ok(buf)
}

fn copy_n<R: Read, W: Write>(r: &mut R, w: &mut W, mut n: usize) -> io::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    while n > 0 {
        let take = n.min(buf.len());
        let got = r.read(&mut buf[..take])?;
        if got == 0 {
            break;
        }
        w.write_all(&buf[..got])?;
        n -= got;
    }
    Ok(())
}

fn parse_content_length(head: &str) -> usize {
    for line in head.split("\r\n") {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:")
            && let Ok(n) = rest.trim().parse::<usize>()
        {
            return n;
        }
    }
    0
}

fn force_connection_close(head: &str) -> String {
    let mut out = String::new();
    for (i, line) in head.split("\r\n").enumerate() {
        if line.is_empty() {
            break;
        }
        if i == 0 {
            out.push_str(line);
            out.push_str("\r\n");
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("connection:") || lower.starts_with("proxy-connection:") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    }
}

fn parse_http_target(target: &str) -> (String, u16, String) {
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
