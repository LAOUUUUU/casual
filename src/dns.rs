//! `casual dns` — a tiny DNS client written straight on top of UDP, no
//! resolver crate. It builds the query packet by hand and parses the answer
//! (including name compression), which is a genuinely useful way to see how DNS
//! works on the wire. Supports A, AAAA, MX, TXT, CNAME, NS.

use anyhow::{Context, Result, bail};
use clap::Args;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

#[derive(Args)]
pub struct DnsArgs {
    /// Domain to look up.
    pub host: String,

    /// Record type: A, AAAA, MX, TXT, CNAME, NS.
    #[arg(default_value = "A")]
    pub record: String,

    /// Resolver to query (defaults to config `dns_server`, else 1.1.1.1).
    #[arg(short, long)]
    pub server: Option<String>,

    /// Print answers as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
pub struct Answer {
    pub name: String,
    pub ttl: u32,
    pub rtype: String,
    pub value: String,
}

pub fn run(args: DnsArgs) -> Result<()> {
    let qtype = qtype_from_str(&args.record)?;
    let server = args
        .server
        .clone()
        .unwrap_or_else(|| crate::config::load().dns_server());

    // Randomize the query ID by mixing several entropy sources through a
    // hasher — pid, wall clock, and a stack address (ASLR). No rand dependency.
    let id = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        std::process::id().hash(&mut h);
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
            .hash(&mut h);
        let probe = 0u8;
        (std::ptr::from_ref(&probe) as usize).hash(&mut h);
        (h.finish() & 0xFFFF) as u16
    };
    let query = build_query(id, &args.host, qtype)?;

    // Resolve the resolver up-front so we can verify the reply came from it,
    // even when --server is a hostname (not just an IP literal).
    let expected: Vec<IpAddr> = (server.as_str(), 53u16)
        .to_socket_addrs()
        .map(|it| it.map(|s| s.ip()).collect())
        .unwrap_or_default();

    let sock = UdpSocket::bind("0.0.0.0:0").context("binding UDP socket")?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    sock.send_to(&query, (server.as_str(), 53))
        .with_context(|| format!("sending query to {server}:53"))?;

    let mut buf = [0u8; 4096];
    let (n, src) = sock
        .recv_from(&mut buf)
        .context("no response from resolver")?;
    // Reject a reply that didn't come from the resolver, or whose ID doesn't
    // match the query — a spoofed reply from elsewhere shouldn't be trusted.
    if !expected.is_empty() && (!expected.contains(&src.ip()) || src.port() != 53) {
        anyhow::bail!("response came from {src}, not {server}:53 — ignoring");
    }
    if n < 2 || u16::from_be_bytes([buf[0], buf[1]]) != id {
        anyhow::bail!("response ID did not match the query — ignoring");
    }
    let msg = &buf[..n];

    let answers = parse_response(msg, &args.host)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&answers)?);
        return Ok(());
    }
    if answers.is_empty() {
        println!(
            "no {} records for {}",
            args.record.to_uppercase(),
            args.host
        );
    } else {
        for a in &answers {
            println!("{}\t{}\t{}\t{}", a.name, a.ttl, a.rtype, a.value);
        }
    }
    Ok(())
}

fn qtype_from_str(s: &str) -> Result<u16> {
    Ok(match s.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        other => bail!("unsupported record type '{other}' (A, AAAA, MX, TXT, CNAME, NS)"),
    })
}

fn type_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        _ => "?",
    }
}

pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: recursion desired
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        // DNS labels are at most 63 bytes; anything longer can't be encoded.
        if label.len() > 63 {
            bail!("DNS label '{label}' exceeds 63 bytes");
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root label
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    Ok(q)
}

pub fn parse_response(msg: &[u8], host: &str) -> Result<Vec<Answer>> {
    if msg.len() < 12 {
        bail!("short DNS response");
    }
    let rcode = msg[3] & 0x0F;
    match rcode {
        0 => {}
        3 => bail!("NXDOMAIN: {host} does not exist"),
        2 => bail!("SERVFAIL from resolver"),
        other => bail!("DNS error rcode {other}"),
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;

    let mut pos = 12;
    // Skip the question section.
    for _ in 0..qd {
        let (_, next) = read_name(msg, pos);
        pos = next + 4; // QTYPE + QCLASS
    }

    let mut out = Vec::new();
    for _ in 0..an {
        if pos >= msg.len() {
            break;
        }
        let (name, next) = read_name(msg, pos);
        pos = next;
        // Re-check bounds AFTER the name: a compressed name can leave `pos`
        // anywhere, so the fixed 10-byte record header must be validated here.
        if pos + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            break;
        }
        let rdata = &msg[pos..pos + rdlen];
        let value = render_rdata(msg, pos, rtype, rdata);
        out.push(Answer {
            name,
            ttl,
            rtype: type_name(rtype).to_string(),
            value,
        });
        pos += rdlen;
    }
    Ok(out)
}

fn render_rdata(msg: &[u8], rdata_pos: usize, rtype: u16, rdata: &[u8]) -> String {
    match rtype {
        1 if rdata.len() == 4 => Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
        28 if rdata.len() == 16 => {
            let mut seg = [0u16; 8];
            for (i, s) in seg.iter_mut().enumerate() {
                *s = u16::from_be_bytes([rdata[i * 2], rdata[i * 2 + 1]]);
            }
            Ipv6Addr::new(
                seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
            )
            .to_string()
        }
        5 | 2 => read_name(msg, rdata_pos).0,
        15 if rdata.len() >= 3 => {
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            let (name, _) = read_name(msg, rdata_pos + 2);
            format!("{pref} {name}")
        }
        16 => {
            // one or more length-prefixed strings
            let mut s = String::new();
            let mut i = 0;
            while i < rdata.len() {
                let len = rdata[i] as usize;
                i += 1;
                if i + len > rdata.len() {
                    break;
                }
                s.push_str(&String::from_utf8_lossy(&rdata[i..i + len]));
                i += len;
            }
            format!("\"{s}\"")
        }
        _ => hex(rdata),
    }
}

/// Read a (possibly compressed) domain name. Returns the name and the position
/// immediately after the name in the *original* stream (following the first
/// pointer, not the pointer target).
fn read_name(msg: &[u8], start: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut next = start;
    let mut jumped = false;
    let mut guard = 0;

    loop {
        guard += 1;
        if guard > 128 || pos >= msg.len() {
            break;
        }
        let len = msg[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= msg.len() {
                break;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | msg[pos + 1] as usize;
            if !jumped {
                next = pos + 2;
                jumped = true;
            }
            pos = ptr;
        } else if len == 0 {
            if !jumped {
                next = pos + 1;
            }
            break;
        } else {
            let s = pos + 1;
            let e = s + len as usize;
            if e > msg.len() {
                break;
            }
            labels.push(String::from_utf8_lossy(&msg[s..e]).into_owned());
            pos = e;
        }
    }
    (labels.join("."), next)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_has_one_question() {
        let q = build_query(0xABCD, "example.com", 1).unwrap();
        assert_eq!(&q[0..2], &[0xAB, 0xCD]);
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1); // QDCOUNT
        // labels: 7"example" 3"com" 0
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
    }

    #[test]
    fn parses_a_record() {
        // Build a minimal response by hand: header + question + one A answer.
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        m.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: response, RA, rcode 0
        m.extend_from_slice(&1u16.to_be_bytes()); // qd
        m.extend_from_slice(&1u16.to_be_bytes()); // an
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        // question: a.com A IN
        m.push(1);
        m.push(b'a');
        m.push(3);
        m.extend_from_slice(b"com");
        m.push(0);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        // answer: pointer to name at 12, A, IN, ttl 60, rdlen 4, 1.2.3.4
        m.extend_from_slice(&[0xC0, 12]);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&60u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[1, 2, 3, 4]);

        let answers = parse_response(&m, "a.com").unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, "a.com");
        assert_eq!(answers[0].rtype, "A");
        assert_eq!(answers[0].value, "1.2.3.4");
    }

    #[test]
    fn parser_never_panics_on_garbage() {
        // A valid-ish message, truncated at every length.
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes());
        m.extend_from_slice(&0x8180u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.push(1);
        m.push(b'a');
        m.push(0);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        for cut in 0..=m.len() {
            let _ = parse_response(&m[..cut], "x");
        }
        // Pseudo-random buffers, including compression-pointer loops.
        let mut s: u64 = 0xDEAD_BEEF;
        for _ in 0..2000 {
            let len = (s % 400) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                buf.push((s >> 33) as u8);
            }
            let _ = parse_response(&buf, "x");
        }
    }
}
