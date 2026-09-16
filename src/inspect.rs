//! `casual inspect` — static analysis of an executable.
//!
//! This is the "look at the binary for suspicious code" layer: it parses a
//! Mach-O / ELF / PE file (via `goblin`), lists what it links against and which
//! functions it imports, and flags dangerous API usage by category (code
//! injection, anti-debugging, dynamic code loading, spawning shells, input
//! capture, …).
//!
//! Big caveat, same as the scanner's entropy: importing these APIs is a *hint*,
//! not proof. Plenty of legitimate software calls `dlopen` or `posix_spawn`.
//! What matters is the combination and the context — this just surfaces them.

use anyhow::{Context, Result};
use clap::Args;
use goblin::Object;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Args)]
pub struct InspectArgs {
    /// Executable to inspect (Mach-O, ELF, or PE).
    pub path: PathBuf,
    /// Print as JSON.
    #[arg(long)]
    pub json: bool,
    /// Also list every imported symbol, not just the flagged ones.
    #[arg(short, long)]
    pub all: bool,
}

/// (substring to match in a symbol name, category, one-line reason).
const SUSPICIOUS: &[(&str, &str, &str)] = &[
    // Reading/writing another process's memory — code injection.
    (
        "task_for_pid",
        "injection",
        "obtain another process's task port",
    ),
    (
        "mach_vm_write",
        "injection",
        "write into another process's memory",
    ),
    (
        "mach_vm_protect",
        "injection",
        "change memory protections (RWX)",
    ),
    (
        "thread_create_running",
        "injection",
        "create a thread in another process",
    ),
    (
        "WriteProcessMemory",
        "injection",
        "write into another process's memory",
    ),
    (
        "CreateRemoteThread",
        "injection",
        "run code in another process",
    ),
    (
        "VirtualAllocEx",
        "injection",
        "allocate memory in another process",
    ),
    (
        "NtUnmapViewOfSection",
        "injection",
        "process hollowing primitive",
    ),
    // Anti-analysis.
    (
        "ptrace",
        "anti-debug",
        "deny/attach debugger (PT_DENY_ATTACH)",
    ),
    ("IsDebuggerPresent", "anti-debug", "detect a debugger"),
    // Loading code at runtime.
    ("dlopen", "dynamic-load", "load a library at runtime"),
    ("dlsym", "dynamic-load", "resolve a symbol at runtime"),
    (
        "NSCreateObjectFileImageFromMemory",
        "dynamic-load",
        "load a Mach-O from memory",
    ),
    ("LoadLibrary", "dynamic-load", "load a DLL at runtime"),
    // Spawning shells / other programs.
    ("execve", "exec", "replace the process image"),
    ("posix_spawn", "exec", "spawn a new process"),
    ("popen", "exec", "run a command via the shell"),
    ("WinExec", "exec", "run a program"),
    ("ShellExecute", "exec", "run a program via the shell"),
    // Watching keystrokes / the screen (macOS).
    (
        "CGEventTap",
        "input-capture",
        "tap global keyboard/mouse events",
    ),
    (
        "AXUIElement",
        "input-capture",
        "read other apps' UI via accessibility",
    ),
    // Bulk crypto — ransomware-adjacent when combined with file walking.
    ("CCCrypt", "crypto", "symmetric encryption"),
    ("CryptEncrypt", "crypto", "symmetric encryption"),
    // Persistence.
    ("SMJobBless", "persistence", "install a privileged helper"),
    (
        "SMLoginItemSetEnabled",
        "persistence",
        "auto-start at login",
    ),
];

#[derive(serde::Serialize)]
struct Flag {
    category: String,
    symbol: String,
    reason: String,
}

#[derive(serde::Serialize)]
struct Report {
    path: String,
    format: String,
    libraries: Vec<String>,
    import_count: usize,
    flagged: Vec<Flag>,
}

/// Flag imported symbols that match a known dangerous API (first match wins).
fn flag_imports(imports: &[String]) -> Vec<Flag> {
    let mut flagged = Vec::new();
    for name in imports {
        for (needle, category, reason) in SUSPICIOUS {
            if name.contains(needle) {
                flagged.push(Flag {
                    category: (*category).to_string(),
                    symbol: name.clone(),
                    reason: (*reason).to_string(),
                });
                break;
            }
        }
    }
    flagged
}

pub fn run(args: InspectArgs) -> Result<()> {
    let bytes =
        std::fs::read(&args.path).with_context(|| format!("reading {}", args.path.display()))?;

    let (format, libraries, imports) = parse(&bytes)?;
    let flagged = flag_imports(&imports);

    let report = Report {
        path: args.path.display().to_string(),
        format,
        libraries,
        import_count: imports.len(),
        flagged,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("inspect: {}", report.path);
    println!("format:  {}", report.format);
    if !report.libraries.is_empty() {
        println!("links:   {}", report.libraries.join(", "));
    }
    println!("imports: {}", report.import_count);

    if report.flagged.is_empty() {
        println!("\nno flagged APIs.");
    } else {
        // Group flags by category for a tidy report.
        let mut by_cat: BTreeMap<&str, Vec<&Flag>> = BTreeMap::new();
        for f in &report.flagged {
            by_cat.entry(f.category.as_str()).or_default().push(f);
        }
        println!("\nflagged APIs (hints, not proof — legit software uses these too):");
        for (cat, flags) in by_cat {
            println!("  [{cat}]");
            for f in flags {
                println!("    {:<32} {}", f.symbol, f.reason);
            }
        }
    }

    if args.all {
        println!("\nall imports:");
        for name in &imports {
            println!("  {name}");
        }
    }
    Ok(())
}

/// Returns (format description, linked libraries, imported symbol names).
fn parse(bytes: &[u8]) -> Result<(String, Vec<String>, Vec<String>)> {
    match Object::parse(bytes).context("parsing binary")? {
        Object::Mach(mach) => parse_mach(mach),
        Object::Elf(elf) => {
            let libs = elf.libraries.iter().map(|s| s.to_string()).collect();
            let imports = elf
                .dynsyms
                .iter()
                .filter(|s| s.is_import())
                .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
                .map(|s| s.to_string())
                .collect();
            let arch = if elf.is_64 { "64-bit" } else { "32-bit" };
            Ok((format!("ELF ({arch})"), libs, imports))
        }
        Object::PE(pe) => {
            let libs = pe
                .import_data
                .as_ref()
                .map(|d| d.import_data.iter().map(|i| i.name.to_string()).collect())
                .unwrap_or_default();
            let imports = pe.imports.iter().map(|i| i.name.to_string()).collect();
            Ok((
                format!("PE ({})", if pe.is_64 { "64-bit" } else { "32-bit" }),
                libs,
                imports,
            ))
        }
        Object::Archive(_) => anyhow::bail!("this is a static archive (.a), not an executable"),
        _ => anyhow::bail!("not a recognized executable (Mach-O / ELF / PE)"),
    }
}

fn parse_mach(mach: goblin::mach::Mach) -> Result<(String, Vec<String>, Vec<String>)> {
    use goblin::mach::{Mach, SingleArch};
    let macho = match mach {
        Mach::Binary(m) => m,
        Mach::Fat(fat) => {
            // Inspect the first Mach-O slice of a universal binary.
            let mut chosen = None;
            for i in 0..fat.narches {
                if let Ok(SingleArch::MachO(m)) = fat.get(i) {
                    chosen = Some(m);
                    break;
                }
            }
            chosen.context("universal binary had no Mach-O slice")?
        }
    };
    let arch = goblin::mach::constants::cputype::get_arch_name_from_types(
        macho.header.cputype,
        macho.header.cpusubtype,
    )
    .unwrap_or("unknown");
    let libs = macho.libs.iter().map(|s| s.to_string()).collect();
    let mut imports: Vec<String> = macho
        .imports()
        .map(|imps| imps.iter().map(|i| i.name.to_string()).collect())
        .unwrap_or_default();
    // Newer binaries use chained fixups, which goblin's bind parser doesn't
    // decode — imports() comes back empty. Fall back to the undefined symbols
    // in the symbol table, which are the external functions the binary imports.
    if imports.is_empty() {
        for sym in macho.symbols() {
            if let Ok((name, nlist)) = sym
                && nlist.is_undefined()
                && !name.is_empty()
            {
                imports.push(name.to_string());
            }
        }
        imports.sort();
        imports.dedup();
    }
    Ok((format!("Mach-O ({arch})"), libs, imports))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_dangerous_apis_and_ignores_benign() {
        let imports = vec![
            "_task_for_pid".to_string(),
            "_printf".to_string(),
            "_dlopen".to_string(),
            "_malloc".to_string(),
        ];
        let flags = flag_imports(&imports);
        assert!(
            flags
                .iter()
                .any(|f| f.symbol == "_task_for_pid" && f.category == "injection")
        );
        assert!(flags.iter().any(|f| f.category == "dynamic-load"));
        assert!(
            !flags
                .iter()
                .any(|f| f.symbol == "_printf" || f.symbol == "_malloc")
        );
    }
}
