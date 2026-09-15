//! Optional config file at `~/.config/casual/config.toml`. Every field is
//! optional; anything missing falls back to a built-in default, and a CLI flag
//! always wins over the config value.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    pub proxy_port: Option<u16>,
    pub max_conns: Option<usize>,
    pub entropy_threshold: Option<f64>,
    pub plugin_dir: Option<String>,
    pub dns_server: Option<String>,
}

impl Config {
    pub fn proxy_port(&self) -> u16 {
        self.proxy_port.unwrap_or(8080)
    }
    pub fn max_conns(&self) -> usize {
        self.max_conns.unwrap_or(256)
    }
    pub fn entropy_threshold(&self) -> f64 {
        self.entropy_threshold.unwrap_or(7.2)
    }
    pub fn dns_server(&self) -> String {
        self.dns_server
            .clone()
            .unwrap_or_else(|| "1.1.1.1".to_string())
    }
}

pub fn path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
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
    println!(
        "  plugin_dir         {}",
        cfg.plugin_dir.clone().unwrap_or_else(|| "(auto)".into())
    );
    Ok(())
}
