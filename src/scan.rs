//! A small "mini-AV" file scanner.
//!
//! For every file it:
//!   1. streams the bytes (bounded memory) computing a SHA-256,
//!   2. computes Shannon entropy (0..8 bits/byte) — packed/encrypted payloads
//!      sit near 8.0, which is a classic heuristic,
//!   3. matches against a JSON signature DB (known hashes + ASCII patterns).
//!
//! It ships a signature for the EICAR test string — the industry-standard,
//! completely harmless file used to test antivirus without touching malware.

use anyhow::{Context, Result};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, IsTerminal, Read};
use std::path::{Path, PathBuf};
use tracing::debug;
use walkdir::WalkDir;

/// How many bytes of a file we keep in memory for pattern matching. The hash
/// and entropy are always streamed, so only pattern search is capped.
///
/// LIMITATION: patterns are only matched within the first `MAX_PATTERN_BYTES`.
/// A file larger than this is skipped for pattern matching entirely, so a
/// byte-pattern signature can be evaded by prepending/appending padding. Hash
/// signatures still fire on the whole file. A real engine slides the window.
const MAX_PATTERN_BYTES: usize = 5 * 1024 * 1024;

#[derive(Args)]
pub struct ScanArgs {
    /// File or directory to scan (default: your home directory).
    pub path: Option<PathBuf>,

    /// Permit scanning the filesystem root `/` (slow; touches system files).
    #[arg(long)]
    pub allow_root: bool,

    /// Path to a signature DB (defaults to ./signatures.json if present).
    #[arg(short, long)]
    pub signatures: Option<PathBuf>,

    /// Entropy above this (bits/byte) is flagged suspicious (default: config
    /// `entropy_threshold`, else 7.2).
    #[arg(short, long)]
    pub entropy_threshold: Option<f64>,

    /// Print results as JSON instead of a table.
    #[arg(long)]
    pub json: bool,

    /// Also show files that came back clean.
    #[arg(short, long)]
    pub all: bool,

    /// Move files that come back MALICIOUS into this directory.
    #[arg(short, long)]
    pub quarantine: Option<PathBuf>,

    /// Don't look inside .zip archives.
    #[arg(long)]
    pub no_archives: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct SignatureDb {
    /// lowercase SHA-256 hex -> human label
    #[serde(default)]
    pub hashes: HashMap<String, String>,
    /// ASCII substrings to look for in file bytes
    #[serde(default)]
    pub patterns: Vec<PatternSig>,
}

#[derive(Debug, Deserialize)]
pub struct PatternSig {
    pub label: String,
    pub contains: String,
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub entropy: f64,
    pub verdict: Verdict,
    pub reasons: Vec<String>,
}

pub fn run(args: ScanArgs) -> Result<()> {
    let db = load_db(args.signatures.as_deref())?;
    let entropy_threshold = args
        .entropy_threshold
        .unwrap_or_else(|| crate::config::load().entropy_threshold());

    // Default to the home directory when no path is given.
    let path = match &args.path {
        Some(p) => p.clone(),
        None => {
            let home = home_dir()?;
            eprintln!(
                "no path given — scanning your home directory: {}",
                home.display()
            );
            home
        }
    };

    // Guard the filesystem root: scanning `/` is slow and hits system and
    // permission-protected files, so require an explicit opt-in.
    let canonical = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    if canonical == Path::new("/") && !args.allow_root {
        anyhow::bail!(
            "refusing to scan the filesystem root '/': it's slow and touches system files.\n\
             re-run with --allow-root to override, or give a specific path (e.g. a folder)."
        );
    }

    // Enumerate first so we can show progress and scan files in parallel.
    let files: Vec<PathBuf> = WalkDir::new(&path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    // Progress bar on stderr, so it never pollutes --json or piped output.
    // Hidden for a single file (no point) and when emitting JSON.
    let bar = if files.len() > 1 && !args.json {
        let b = ProgressBar::new(files.len() as u64);
        b.set_style(
            ProgressStyle::with_template("{spinner} {pos}/{len} scanned [{bar:30}] {msg}")
                .unwrap()
                .progress_chars("=>-"),
        );
        b
    } else {
        ProgressBar::hidden()
    };

    let scan_archives = !args.no_archives;
    let mut findings: Vec<Finding> = files
        .par_iter()
        .filter_map(|path| {
            let r = scan_file(path, &db, entropy_threshold, scan_archives);
            bar.inc(1);
            match r {
                Ok(f) => Some(f),
                Err(e) => {
                    debug!("skip {}: {e}", path.display());
                    None
                }
            }
        })
        .collect();
    bar.finish_and_clear();

    // Worst verdicts first, then noisiest entropy.
    findings.sort_by(|a, b| {
        rank(b.verdict)
            .cmp(&rank(a.verdict))
            .then(b.entropy.total_cmp(&a.entropy))
    });

    // Quarantine (before output so it happens in --json mode too; messages go
    // to stderr to keep stdout clean).
    if let Some(qdir) = &args.quarantine {
        quarantine(&findings, qdir);
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
        return Ok(());
    }

    report(&findings, args.all);
    Ok(())
}

fn quarantine(findings: &[Finding], dir: &Path) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("cannot create quarantine dir {}: {e}", dir.display());
        return;
    }
    let mut moved = 0;
    for f in findings.iter().filter(|f| f.verdict == Verdict::Malicious) {
        match move_into(&f.path, dir) {
            Ok(dest) => {
                eprintln!("quarantined {} -> {dest}", f.path);
                moved += 1;
            }
            Err(e) => eprintln!("failed to quarantine {}: {e}", f.path),
        }
    }
    eprintln!(
        "quarantined {moved} malicious file(s) into {}",
        dir.display()
    );
}

/// Extensions whose contents are *expected* to be high-entropy (already
/// compressed, encoded, or encrypted), so entropy alone tells you nothing.
fn expected_high_entropy(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "zip"
            | "gz"
            | "tgz"
            | "bz2"
            | "xz"
            | "zst"
            | "7z"
            | "rar"
            | "lz4"
            | "br"
            | "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "webp"
            | "heic"
            | "avif"
            | "tiff"
            | "ico"
            | "mp4"
            | "mov"
            | "mkv"
            | "avi"
            | "webm"
            | "m4v"
            | "mp3"
            | "aac"
            | "flac"
            | "ogg"
            | "m4a"
            | "wav"
            | "pdf"
            | "dmg"
            | "iso"
            | "pkg"
            | "apk"
            | "jar"
            | "wasm"
            | "woff"
            | "woff2"
            | "ttf"
            | "otf"
    )
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE")) // Windows
        .map(PathBuf::from)
        .context("no HOME/USERPROFILE set; pass a path to scan explicitly")
}

fn move_into(path: &str, dir: &Path) -> Result<String> {
    let src = Path::new(path);
    let base = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let mut dest = dir.join(&base);
    let mut n = 1;
    while dest.exists() {
        dest = dir.join(format!("{base}.{n}"));
        n += 1;
    }
    // Rename is atomic on the same filesystem; fall back to copy+remove across
    // devices (e.g. quarantining onto a different volume).
    if std::fs::rename(src, &dest).is_err() {
        std::fs::copy(src, &dest).with_context(|| format!("copying {path}"))?;
        std::fs::remove_file(src).with_context(|| format!("removing {path}"))?;
    }
    Ok(dest.display().to_string())
}

fn scan_file(
    path: &Path,
    db: &SignatureDb,
    entropy_threshold: f64,
    scan_archives: bool,
) -> Result<Finding> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut freq = [0u64; 256];
    let mut size: u64 = 0;
    let mut buffered: Vec<u8> = Vec::new();
    let mut overflowed = false;

    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        let bytes = &chunk[..n];
        hasher.update(bytes);
        for &b in bytes {
            freq[b as usize] += 1;
        }
        size += n as u64;
        if !overflowed {
            if buffered.len() + n <= MAX_PATTERN_BYTES {
                buffered.extend_from_slice(bytes);
            } else {
                overflowed = true;
                buffered.clear(); // too big to pattern-match; free the memory
            }
        }
    }

    let sha256 = hex(&hasher.finalize());
    let entropy = shannon_entropy(&freq, size);

    let mut reasons = Vec::new();
    let mut verdict = Verdict::Clean;

    if let Some(label) = db.hashes.get(&sha256) {
        verdict = Verdict::Malicious;
        reasons.push(format!("known signature: {label}"));
    }

    if !overflowed {
        let text = String::from_utf8_lossy(&buffered);
        for sig in &db.patterns {
            if text.contains(&sig.contains) {
                verdict = worse(verdict, Verdict::Malicious);
                reasons.push(format!("pattern match: {}", sig.label));
            }
        }
    }

    // Entropy is only a hint, and it's *expected* to be high for already
    // compressed/encoded/encrypted files (media, archives, …) — flagging those
    // is pure noise, so skip them. Even when flagged, this is never treated as
    // malicious and never quarantined.
    if size > 1024 && entropy >= entropy_threshold && !expected_high_entropy(path) {
        verdict = worse(verdict, Verdict::Suspicious);
        reasons.push(format!(
            "high entropy {entropy:.2} bits/byte — looks compressed/encrypted (not necessarily malicious)"
        ));
    }

    // Look inside zip archives (magic bytes "PK"), scanning each entry.
    if scan_archives && !overflowed && buffered.starts_with(b"PK") {
        let (arch_verdict, notes) = scan_archive(&buffered, db, entropy_threshold);
        verdict = worse(verdict, arch_verdict);
        reasons.extend(notes);
    }

    Ok(Finding {
        path: path.display().to_string(),
        size,
        sha256,
        entropy,
        verdict,
        reasons,
    })
}

/// Scan the entries of a zip archive held in memory. Returns the worst verdict
/// found and human notes for each hit.
fn scan_archive(bytes: &[u8], db: &SignatureDb, entropy_threshold: f64) -> (Verdict, Vec<String>) {
    const MAX_ENTRY: u64 = 20 * 1024 * 1024;
    let mut verdict = Verdict::Clean;
    let mut notes = Vec::new();

    let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        return (verdict, notes);
    };
    for i in 0..zip.len() {
        let Ok(mut entry) = zip.by_index(i) else {
            continue;
        };
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_string();
        // Bound the ACTUAL bytes read, not the entry's self-reported size — a
        // zip bomb claims a small size and decompresses to gigabytes. Don't
        // preallocate from the size field either.
        let mut buf = Vec::new();
        if (&mut entry).take(MAX_ENTRY).read_to_end(&mut buf).is_err() {
            continue;
        }

        let mut hasher = Sha256::new();
        hasher.update(&buf);
        let sha = hex(&hasher.finalize());
        if let Some(label) = db.hashes.get(&sha) {
            verdict = worse(verdict, Verdict::Malicious);
            notes.push(format!("archive entry '{name}': known signature {label}"));
        }
        let text = String::from_utf8_lossy(&buf);
        for sig in &db.patterns {
            if text.contains(&sig.contains) {
                verdict = worse(verdict, Verdict::Malicious);
                notes.push(format!("archive entry '{name}': pattern {}", sig.label));
            }
        }
        let mut freq = [0u64; 256];
        for &b in &buf {
            freq[b as usize] += 1;
        }
        let ent = shannon_entropy(&freq, buf.len() as u64);
        if buf.len() > 1024 && ent >= entropy_threshold && !expected_high_entropy(Path::new(&name))
        {
            verdict = worse(verdict, Verdict::Suspicious);
            notes.push(format!(
                "archive entry '{name}': high entropy {ent:.2} (compressed/encrypted, not necessarily malicious)"
            ));
        }
    }
    (verdict, notes)
}

fn load_db(explicit: Option<&Path>) -> Result<SignatureDb> {
    let path = match explicit {
        Some(p) => Some(p.to_path_buf()),
        None => {
            let default = PathBuf::from("signatures.json");
            default.exists().then_some(default)
        }
    };
    match path {
        Some(p) => {
            let text =
                std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
            let db: SignatureDb =
                serde_json::from_str(&text).with_context(|| format!("parsing {}", p.display()))?;
            debug!(
                "loaded {} hashes, {} patterns from {}",
                db.hashes.len(),
                db.patterns.len(),
                p.display()
            );
            Ok(db)
        }
        None => {
            debug!("no signature DB found; relying on entropy heuristic only");
            Ok(SignatureDb::default())
        }
    }
}

/// Shannon entropy in bits per byte, from a byte-frequency histogram.
fn shannon_entropy(freq: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    let mut h = 0.0;
    for &count in freq.iter() {
        if count == 0 {
            continue;
        }
        let p = count as f64 / total;
        h -= p * p.log2();
    }
    h
}

fn report(findings: &[Finding], show_all: bool) {
    // Color only when writing to a terminal and NO_COLOR isn't set.
    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let mut shown = 0;
    for f in findings {
        if !show_all && f.verdict == Verdict::Clean {
            continue;
        }
        shown += 1;
        let tag = tag_for(f.verdict, color);
        println!(
            "{tag} {}  ({} bytes, entropy {:.2})",
            f.path, f.size, f.entropy
        );
        for r in &f.reasons {
            println!("            - {r}");
        }
    }

    let mal = findings
        .iter()
        .filter(|f| f.verdict == Verdict::Malicious)
        .count();
    let sus = findings
        .iter()
        .filter(|f| f.verdict == Verdict::Suspicious)
        .count();
    println!(
        "\nscanned {} file(s): {} malicious, {} suspicious{}",
        findings.len(),
        mal,
        sus,
        if shown == 0 { " (all clean)" } else { "" }
    );
    if sus > 0 {
        println!(
            "note: 'suspicious' is only the high-entropy heuristic (compressed/encrypted-looking) — \
             not a virus verdict. Only signature-matched 'malicious' files are ever quarantined."
        );
    }
}

fn tag_for(verdict: Verdict, color: bool) -> String {
    let (text, code) = match verdict {
        Verdict::Malicious => ("[MALICIOUS]", "1;31"), // bold red
        Verdict::Suspicious => ("[SUSPECT ]", "33"),   // yellow
        Verdict::Clean => ("[clean    ]", "2"),        // dim
    };
    if color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn worse(a: Verdict, b: Verdict) -> Verdict {
    if rank(b) > rank(a) { b } else { a }
}

fn rank(v: Verdict) -> u8 {
    match v {
        Verdict::Clean => 0,
        Verdict::Suspicious => 1,
        Verdict::Malicious => 2,
    }
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
    fn entropy_of_uniform_is_max() {
        // Every byte value once -> 8 bits/byte exactly.
        let mut freq = [1u64; 256];
        let h = shannon_entropy(&freq, 256);
        assert!((h - 8.0).abs() < 1e-9);
        // All one value -> zero entropy.
        freq = [0u64; 256];
        freq[b'A' as usize] = 100;
        assert_eq!(shannon_entropy(&freq, 100), 0.0);
    }

    #[test]
    fn worse_picks_higher_severity() {
        assert_eq!(
            worse(Verdict::Clean, Verdict::Suspicious),
            Verdict::Suspicious
        );
        assert_eq!(
            worse(Verdict::Malicious, Verdict::Clean),
            Verdict::Malicious
        );
    }
}
