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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use tracing::{debug, info, warn};

const MAX_HEAD: usize = 64 * 1024;

/// The CA, reconstructed so it can sign leaf certificates.
struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

/// Host allow/block policy (same semantics as the plain proxy).
struct Policy {
    block: Vec<String>,
    allow: Vec<String>,
}

pub fn run(args: ProxyArgs) -> Result<()> {
    install_crypto_provider();
    let ca = Arc::new(load_ca().context(
        "no intercept CA found. Run `casual ca` once, then install the printed certificate.",
    )?);
    let client_config = Arc::new(build_client_config());
    // Same allow/block policy as the plain proxy.
    let policy = Arc::new(Policy {
        block: args.block.clone(),
        allow: args.allow_only.clone(),
    });

    let cfg = crate::config::load();
    let port = args.port.unwrap_or_else(|| cfg.proxy_port());
    let max_conns = args.max_conns.unwrap_or_else(|| cfg.max_conns());
    let addr = format!("{}:{}", args.bind, port);
    let listener = TcpListener::bind(&addr).with_context(|| format!("binding {addr}"))?;
    info!("casual proxy (INTERCEPT) listening on http://{addr}");
    info!("HTTPS is DECRYPTED using your local CA. Devices you control only.");

    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let mut client = match stream {
            Ok(c) => c,
            Err(e) => {
                warn!("accept failed: {e}");
                continue;
            }
        };
        if active.load(Ordering::SeqCst) >= max_conns {
            warn!("at connection cap ({max_conns}), refusing");
            let _ = client.write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let ca = Arc::clone(&ca);
        let cc = Arc::clone(&client_config);
        let policy = Arc::clone(&policy);
        let active_cl = Arc::clone(&active);
        thread::spawn(move || {
            if let Err(e) = handle(client, &ca, &cc, &policy) {
                debug!("connection ended: {e}");
            }
            active_cl.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

fn handle(
    mut client: TcpStream,
    ca: &Ca,
    client_config: &Arc<ClientConfig>,
    policy: &Policy,
) -> Result<()> {
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
        if !crate::proxy::host_allowed(&host, &policy.block, &policy.allow) {
            warn!(%host, "blocked by policy");
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            return Ok(());
        }
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        if let Err(e) = intercept_tls(client, &host, port, ca, client_config) {
            debug!("intercept {host}:{port} failed: {e}");
        }
    } else if !method.is_empty() {
        let (host, ..) = parse_http_target(&target);
        if !crate::proxy::host_allowed(&host, &policy.block, &policy.allow) {
            warn!(%host, "blocked by policy");
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            return Ok(());
        }
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

    // We can't relay a chunked request body (we only parse Content-Length),
    // and guessing would risk request smuggling — refuse rather than corrupt.
    if head_str.to_ascii_lowercase().contains("transfer-encoding:") {
        anyhow::bail!("chunked request bodies aren't supported in intercept mode yet");
    }

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
        // Hop-by-hop headers must not be forwarded to the origin.
        if is_hop_by_hop(&line.to_ascii_lowercase()) {
            continue;
        }
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
    // A CA key others can read can mint trusted certs — auto-tighten it (it's
    // on the user's own machine) and warn, rather than making them re-run `ca`.
    if let Some(old) = harden_key_perms(&key_path)? {
        warn!(
            "tightened CA key {} to 0600 (was {old:o})",
            key_path.display()
        );
    }
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
        write_private_key(&key_path, &key.serialize_pem())?;
        println!("created a new CA:");
    } else {
        // Existing CA: make sure the private key isn't group/world-readable.
        if let Some(old) = harden_key_perms(&key_path)? {
            println!("tightened key permissions to 0600 (was {old:o})");
        }
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
        "  Debian/Ubuntu: copy to /usr/local/share/ca-certificates/ (as .crt), then update-ca-certificates"
    );
    println!("  Fedora/RHEL  : copy to /etc/pki/ca-trust/source/anchors/, then update-ca-trust");
    println!(
        "  Arch         : copy to /etc/ca-certificates/trust-source/anchors/, then trust extract-compat"
    );
    println!("  Firefox/Chrome use their own store: import it in the browser's cert settings.");
    println!();
    println!("Then: casual proxy --intercept   (and set 127.0.0.1:8080 as your proxy)");
    Ok(())
}

/// Write a private key readable only by its owner (0600 on Unix).
fn write_private_key(path: &Path, pem: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        f.write_all(pem.as_bytes())?;
        // `.mode()` only applies when the file is newly created; enforce 0600
        // unconditionally so overwriting a pre-existing loose key still hardens.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, pem).with_context(|| format!("writing {}", path.display()))
    }
}

/// If the key is group/other-accessible, tighten it to 0600; returns the old
/// mode when it changed.
#[cfg(unix)]
fn harden_key_perms(path: &Path) -> Result<Option<u32>> {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(None);
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        return Ok(Some(mode));
    }
    Ok(None)
}
#[cfg(not(unix))]
fn harden_key_perms(_path: &Path) -> Result<Option<u32>> {
    Ok(None)
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

fn read_head<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut b = [0u8; 1];
    loop {
        let n = r.read(&mut b)?;
        if n == 0 {
            break;
        }
        buf.push(b[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        // Don't silently truncate an over-long head and forward a partial
        // request — same smuggling risk as the plain proxy.
        if buf.len() >= MAX_HEAD {
            anyhow::bail!("request head exceeded {MAX_HEAD} bytes");
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

/// RFC 7230 hop-by-hop headers, which a proxy must not forward to the origin.
fn is_hop_by_hop(line_lower: &str) -> bool {
    const H: &[&str] = &[
        "connection:",
        "proxy-connection:",
        "keep-alive:",
        "proxy-authenticate:",
        "proxy-authorization:",
        "te:",
        "trailer:",
        "transfer-encoding:",
        "upgrade:",
    ];
    H.iter().any(|h| line_lower.starts_with(h))
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
        // Drop hop-by-hop headers; we set our own Connection below.
        if is_hop_by_hop(&line.to_ascii_lowercase()) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    // Bracketed IPv6: "[::1]" or "[::1]:8080" — strip the brackets so the host
    // is a valid address for TcpStream/ServerName.
    if let Some(rest) = authority.strip_prefix('[')
        && let Some((h, tail)) = rest.split_once(']')
    {
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return (h.to_string(), port);
    }
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
