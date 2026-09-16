//! `casual live` — an interactive menu, so the tool feels like an app without
//! the weight of one. It just calls the same functions the subcommands do.

use anyhow::Result;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::{learn, plugin, proxy, scan};

pub fn run() -> Result<()> {
    crate::notice::show();
    println!("casual — interactive mode. Type a number, or 'q' to quit.\n");
    loop {
        println!("  1) scan a file/folder");
        println!("  2) start the logging proxy");
        println!("  3) watch a model learn");
        println!("  4) list plugins");
        println!("  5) run a plugin");
        println!("  q) quit");
        let choice = prompt("> ")?;

        match choice.trim() {
            "1" => {
                let path = prompt("path to scan [home]: ")?;
                let p = path.trim();
                let args = scan::ScanArgs {
                    path: if p.is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(p))
                    },
                    allow_root: false,
                    signatures: None,
                    entropy_threshold: None,
                    json: false,
                    all: false,
                    quarantine: None,
                    no_archives: false,
                };
                if let Err(e) = scan::run(args) {
                    println!("error: {e}");
                }
            }
            "2" => {
                let port = prompt("port [8080]: ")?;
                let port: u16 = port.trim().parse().unwrap_or(8080);
                println!("(Ctrl-C to stop the proxy and exit)");
                let args = proxy::ProxyArgs {
                    port: Some(port),
                    bind: "127.0.0.1".to_string(),
                    log_file: None,
                    max_conns: None,
                    intercept: false,
                    block: Vec::new(),
                    allow_only: Vec::new(),
                    capture_dir: None,
                };
                proxy::run(args)?; // runs until interrupted
            }
            "3" => {
                let args = learn::LearnArgs {
                    dataset: "blobs".to_string(),
                    hidden: 0,
                    csv: None,
                    epochs: 120,
                    lr: 0.2,
                    every: 4,
                    fast: false,
                };
                if let Err(e) = learn::run(args) {
                    println!("error: {e}");
                }
            }
            "4" => plugin::list(),
            "5" => {
                let line = prompt("plugin and args (e.g. hash ./file): ")?;
                let mut parts = line.split_whitespace();
                if let Some(name) = parts.next() {
                    let rest: Vec<String> = parts.map(|s| s.to_string()).collect();
                    if let Err(e) = plugin::run(name, &rest) {
                        println!("error: {e}");
                    }
                }
            }
            "q" | "quit" | "exit" => {
                println!("bye.");
                break;
            }
            "" => {}
            other => println!("didn't understand '{other}'."),
        }
        println!();
    }
    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line)
}
