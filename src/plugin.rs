//! The plugin system.
//!
//! A plugin is anything implementing `Plugin`. Built-in plugins are registered
//! in `registry()`. To add one: write a struct, impl `Plugin`, add it to the
//! Vec. The core never has to change.
//!
//! Two example plugins ship: `hash` and `entropy` reuse the scanner's ideas on
//! a single file; `ports` is a local TCP connect-check (for your own hosts).
//!
//! Want *dynamically loaded* plugins (drop a compiled file in a folder, no
//! recompile)? Two common routes, noted at the bottom of this file.

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A capability that can be listed and run by name.
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn usage(&self) -> &str;
    fn run(&self, args: &[String]) -> Result<()>;
}

/// Compile-time built-in plugins. Add yours here.
pub fn registry() -> Vec<Box<dyn Plugin>> {
    vec![
        Box::new(HashPlugin),
        Box::new(EntropyPlugin),
        Box::new(PortsPlugin),
    ]
}

/// Built-ins plus any dynamically-loaded plugins found on disk (native, and
/// WASM when the `wasm` feature is on).
fn all_plugins() -> Vec<Box<dyn Plugin>> {
    let mut plugins = registry();
    plugins.extend(load_dynamic());
    #[cfg(feature = "wasm")]
    plugins.extend(wasm::load());
    plugins
}

pub fn list() {
    println!("Available plugins:\n");
    for p in all_plugins() {
        println!("  {:<9} {}", p.name(), p.description());
        println!("            usage: casual plugin run {}", p.usage());
    }
    if let Some(dir) = plugin_dir() {
        println!("\n(dynamic plugins loaded from {})", dir.display());
    } else {
        println!(
            "\n(no plugin dir; set CASUAL_PLUGIN_DIR or create ~/.config/casual/plugins to load .dylib/.so plugins)"
        );
    }
}

pub fn run(name: &str, args: &[String]) -> Result<()> {
    let plugins = all_plugins();
    let plugin = plugins
        .iter()
        .find(|p| p.name() == name)
        .ok_or_else(|| anyhow!("no plugin named '{name}'. Try: casual plugin list"))?;
    plugin.run(args)
}

// --- dynamic plugin loading (native shared libraries) ----------------------

/// ABI version the host understands. A plugin must report the same number.
pub const PLUGIN_ABI_VERSION: u32 = 1;

/// The C-ABI struct a plugin returns from `casual_plugin_v1`. Keeping it a flat
/// `repr(C)` struct of pointers avoids depending on Rust's unstable layout
/// across the shared-library boundary.
#[repr(C)]
pub struct RawPlugin {
    pub abi_version: u32,
    pub name: *const c_char,
    pub description: *const c_char,
    pub usage: *const c_char,
    pub run: extern "C" fn(argc: usize, argv: *const *const c_char) -> i32,
}

struct DynPlugin {
    name: String,
    description: String,
    usage: String,
    run: extern "C" fn(usize, *const *const c_char) -> i32,
}

impl Plugin for DynPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn description(&self) -> &str {
        &self.description
    }
    fn usage(&self) -> &str {
        &self.usage
    }
    fn run(&self, args: &[String]) -> Result<()> {
        let cstrings: Vec<CString> = args
            .iter()
            .map(|a| CString::new(a.as_str()))
            .collect::<std::result::Result<_, _>>()
            .context("plugin arg contained a NUL byte")?;
        let ptrs: Vec<*const c_char> = cstrings.iter().map(|c| c.as_ptr()).collect();
        let code = (self.run)(ptrs.len(), ptrs.as_ptr());
        if code == 0 {
            Ok(())
        } else {
            bail!("plugin '{}' returned exit code {code}", self.name)
        }
    }
}

fn plugin_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("CASUAL_PLUGIN_DIR") {
        let p = PathBuf::from(dir);
        if p.is_dir() {
            return Some(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = Path::new(&home).join(".config/casual/plugins");
        if p.is_dir() {
            return Some(p);
        }
    }
    let local = PathBuf::from("plugins");
    local.is_dir().then_some(local)
}

fn load_dynamic() -> Vec<Box<dyn Plugin>> {
    let mut out: Vec<Box<dyn Plugin>> = Vec::new();
    let Some(dir) = plugin_dir() else {
        return out;
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_shared_lib(&path) {
            continue;
        }
        // SAFETY: we are loading and calling arbitrary native code. Only put
        // libraries you trust in the plugin directory. We validate the ABI
        // version before using anything the plugin returns.
        match unsafe { load_one(&path) } {
            Ok(p) => out.push(p),
            Err(e) => eprintln!("skipping plugin {}: {e}", path.display()),
        }
    }
    out
}

fn is_shared_lib(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("dylib") | Some("so") | Some("dll")
    )
}

unsafe fn load_one(path: &Path) -> Result<Box<dyn Plugin>> {
    let lib = unsafe { libloading::Library::new(path) }
        .with_context(|| format!("loading {}", path.display()))?;
    let ctor: libloading::Symbol<extern "C" fn() -> RawPlugin> =
        unsafe { lib.get(b"casual_plugin_v1") }.context("missing symbol casual_plugin_v1")?;
    let raw = ctor();
    if raw.abi_version != PLUGIN_ABI_VERSION {
        bail!(
            "plugin ABI {} != host ABI {PLUGIN_ABI_VERSION}",
            raw.abi_version
        );
    }
    let plugin = DynPlugin {
        name: cstr(raw.name)?,
        description: cstr(raw.description)?,
        usage: cstr(raw.usage)?,
        run: raw.run,
    };
    // Keep the library mapped for the process lifetime so `run` stays valid.
    std::mem::forget(lib);
    Ok(Box::new(plugin))
}

fn cstr(p: *const c_char) -> Result<String> {
    if p.is_null() {
        bail!("plugin returned a null string");
    }
    Ok(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

// --- WASM plugins (sandboxed) ----------------------------------------------

/// Sandboxed WebAssembly plugins. Unlike native plugins, a wasm plugin can do
/// nothing but compute and call the one host function we grant it (`print`) —
/// no filesystem, no network. That's the whole point: you can run plugins you
/// don't fully trust. Contract: the module imports `casual.print(ptr, len)`
/// and exports `run() -> i32` (0 = success) plus its `memory`.
#[cfg(feature = "wasm")]
mod wasm {
    use super::{Plugin, plugin_dir};
    use anyhow::{Context, Result, anyhow};
    use wasmtime::{Caller, Engine, Extern, Linker, Module, Store};

    pub fn load() -> Vec<Box<dyn Plugin>> {
        let mut out: Vec<Box<dyn Plugin>> = Vec::new();
        let Some(dir) = plugin_dir() else {
            return out;
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return out;
        };
        let engine = Engine::default();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
                continue;
            }
            match Module::from_file(&engine, &path) {
                Ok(module) => {
                    let name = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("wasm")
                        .to_string();
                    out.push(Box::new(WasmPlugin {
                        name,
                        engine: engine.clone(),
                        module,
                    }));
                }
                Err(e) => eprintln!("skipping wasm plugin {}: {e}", path.display()),
            }
        }
        out
    }

    struct WasmPlugin {
        name: String,
        engine: Engine,
        module: Module,
    }

    impl Plugin for WasmPlugin {
        fn name(&self) -> &str {
            &self.name
        }
        fn description(&self) -> &str {
            "sandboxed WASM plugin"
        }
        fn usage(&self) -> &str {
            "<name>   (runs in a wasm sandbox; no fs/network access)"
        }
        fn run(&self, _args: &[String]) -> Result<()> {
            let mut linker: Linker<()> = Linker::new(&self.engine);
            // The single host capability we grant: print bytes from guest memory.
            linker
                .func_wrap(
                    "casual",
                    "print",
                    |mut caller: Caller<'_, ()>, ptr: i32, len: i32| {
                        let Some(Extern::Memory(mem)) = caller.get_export("memory") else {
                            return;
                        };
                        let data = mem.data(&caller);
                        let (start, end) = (ptr as usize, ptr as usize + len as usize);
                        if end <= data.len() {
                            print!("{}", String::from_utf8_lossy(&data[start..end]));
                        }
                    },
                )
                .context("linking host function")?;

            let mut store = Store::new(&self.engine, ());
            let instance = linker
                .instantiate(&mut store, &self.module)
                .context("instantiating wasm module")?;
            let run = instance
                .get_typed_func::<(), i32>(&mut store, "run")
                .map_err(|_| anyhow!("wasm plugin '{}' has no `run() -> i32` export", self.name))?;
            let code = run.call(&mut store, ()).context("calling wasm run()")?;
            if code == 0 {
                Ok(())
            } else {
                anyhow::bail!("wasm plugin '{}' returned {code}", self.name)
            }
        }
    }
}

// --- built-in plugins ------------------------------------------------------

struct HashPlugin;
impl Plugin for HashPlugin {
    fn name(&self) -> &str {
        "hash"
    }
    fn description(&self) -> &str {
        "SHA-256 of a file"
    }
    fn usage(&self) -> &str {
        "hash <path>"
    }
    fn run(&self, args: &[String]) -> Result<()> {
        let path = args.first().ok_or_else(|| anyhow!("usage: hash <path>"))?;
        let mut file = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for b in digest {
            hex.push_str(&format!("{b:02x}"));
        }
        println!("{hex}  {path}");
        Ok(())
    }
}

struct EntropyPlugin;
impl Plugin for EntropyPlugin {
    fn name(&self) -> &str {
        "entropy"
    }
    fn description(&self) -> &str {
        "Shannon entropy (bits/byte) of a file"
    }
    fn usage(&self) -> &str {
        "entropy <path>"
    }
    fn run(&self, args: &[String]) -> Result<()> {
        let path = args
            .first()
            .ok_or_else(|| anyhow!("usage: entropy <path>"))?;
        let mut file = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
        let mut freq = [0u64; 256];
        let mut total = 0u64;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            for &b in &buf[..n] {
                freq[b as usize] += 1;
            }
            total += n as u64;
        }
        let h = if total == 0 {
            0.0
        } else {
            let total = total as f64;
            let mut h = 0.0;
            for &c in freq.iter() {
                if c == 0 {
                    continue;
                }
                let p = c as f64 / total;
                h -= p * p.log2();
            }
            h
        };
        println!("{h:.3} bits/byte  ({total} bytes)  {path}");
        Ok(())
    }
}

/// A local TCP connect-check. For hosts you own or are authorized to test.
struct PortsPlugin;
impl Plugin for PortsPlugin {
    fn name(&self) -> &str {
        "ports"
    }
    fn description(&self) -> &str {
        "check which TCP ports accept a connection (authorized hosts only)"
    }
    fn usage(&self) -> &str {
        "ports <host> <start> <end>   e.g. ports 127.0.0.1 1 1024"
    }
    fn run(&self, args: &[String]) -> Result<()> {
        if args.len() != 3 {
            bail!("usage: ports <host> <start> <end>");
        }
        let host = &args[0];
        let start: u16 = args[1].parse().context("start port")?;
        let end: u16 = args[2].parse().context("end port")?;
        if start > end {
            bail!("start port must be <= end port");
        }
        crate::notice::show();
        println!("checking {host} ports {start}..={end} ...");
        let mut open = 0;
        for port in start..=end {
            let addr = format!("{host}:{port}");
            // Resolve once; skip if the host is bad.
            let Some(sock) = addr.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
                bail!("cannot resolve {host}");
            };
            if TcpStream::connect_timeout(&sock, Duration::from_millis(300)).is_ok() {
                println!("  open: {port}");
                open += 1;
            }
        }
        println!("done: {open} open port(s).");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Dynamically loaded plugins (no recompile of the core):
//   A) Native shared libraries — build each plugin as a `cdylib` exporting a
//      known `extern "C"` constructor, then load *.dylib/*.so at runtime with
//      the `libloading` crate and register what they return. Fast, but the
//      plugin runs with full native trust (an unsafe FFI boundary).
//   B) WebAssembly — compile plugins to wasm and run them with `wasmtime`.
//      Slower per call, but sandboxed: a plugin can't touch the filesystem or
//      network unless you explicitly grant it. Best when plugins are untrusted.
// Start with the compile-time registry above; reach for A or B once you
// actually need third parties to ship plugins without your source.
// ---------------------------------------------------------------------------
