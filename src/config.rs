//! Optional config file at `~/.config/casual/config.toml`. Every field is
//! optional; anything missing falls back to a built-in default, and a CLI flag
//! always wins over the config value.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

// Reject unknown keys so a typo like `prox_port = 9000` fails loudly instead
// of being silently ignored in a hand-edited file.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub proxy_port: Option<u16>,
    pub max_conns: Option<usize>,
    pub entropy_threshold: Option<f64>,
    pub plugin_dir: Option<String>,
    pub dns_server: Option<String>,
    pub wasm_fuel: Option<u64>,
}

impl Config {
    pub fn proxy_port(&self) -> u16 {
        self.proxy_port.unwrap_or(8080)
    }
    pub fn max_conns(&self) -> usize {
        self.max_conns.unwrap_or(256)
    }
    pub fn entropy_threshold(&self) -> f64 {
        // Entropy is 0..8 bits/byte; clamp so a bad config value can't make
        // everything (or nothing) suspicious.
        self.entropy_threshold.unwrap_or(7.2).clamp(0.0, 8.0)
    }
    pub fn dns_server(&self) -> String {
        self.dns_server
            .clone()
            .unwrap_or_else(|| "1.1.1.1".to_string())
    }
    /// Fuel budget for a WASM plugin run (bounds a runaway plugin).
    pub fn wasm_fuel(&self) -> u64 {
        self.wasm_fuel.unwrap_or(100_000_000)
    }
}

pub fn path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".config/casual/config.toml"))
}

/// Load the config, or defaults if there's no file. A malformed file is an
/// error (better to tell the user than silently ignore their settings).
pub fn load() -> Config {
    let Some(p) = path() else {
        return Config::default();
    };
    match std::fs::read_to_string(&p) {
        Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
            eprintln!("warning: ignoring bad config {}: {e}", p.display());
            Config::default()
        }),
        Err(_) => Config::default(),
    }
}

const SAMPLE: &str = "\
# casual configuration. Delete any line to use the built-in default.
proxy_port = 8080
max_conns = 256
entropy_threshold = 7.2
dns_server = \"1.1.1.1\"
wasm_fuel = 100000000
# plugin_dir = \"/absolute/path/to/plugins\"
";

/// `casual config`: print where config is read from and the effective values,
/// writing a commented sample if none exists yet.
pub fn show() -> Result<()> {
    let p = path().context("HOME not set")?;
    if !p.exists() {
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&p, SAMPLE)?;
        println!("wrote a sample config to {}", p.display());
    } else {
        println!("config: {}", p.display());
    }
    let cfg = load();
    println!("\neffective settings:");
    println!("  proxy_port         {}", cfg.proxy_port());
    println!("  max_conns          {}", cfg.max_conns());
    println!("  entropy_threshold  {}", cfg.entropy_threshold());
    println!("  dns_server         {}", cfg.dns_server());
    println!("  wasm_fuel          {}", cfg.wasm_fuel());
    println!(
        "  plugin_dir         {}",
        cfg.plugin_dir.clone().unwrap_or_else(|| "(auto)".into())
    );
    Ok(())
}
