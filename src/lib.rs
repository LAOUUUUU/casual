//! casual — a modular, plugin-driven CLI toolkit.
//!
//! Pillars (each is its own module so you can grow them independently):
//!   scan   -> a small file scanner: hashing + signature DB + entropy heuristic
//!   proxy  -> a local HTTP(S) logging proxy for inspecting *your own* traffic
//!   plugin -> a plugin trait + registry; drop new capabilities in without
//!             touching the core
//!   learn  -> a live, terminal ML visualization (watch a model learn)
//!   live   -> an interactive menu that ties the above together
//!
//! Ethics/scope: the networking tools are for machines and networks you own or
//! are explicitly authorized to test. That is the whole reason they exist.
//!
//! This is the library crate; `main.rs` is a thin wrapper over [`run`]. Parser
//! modules are public so tests and fuzz targets can exercise them directly.

mod config;
#[cfg(feature = "tui")]
mod dash;
pub mod dns;
#[cfg(feature = "intercept")]
mod intercept;
mod learn;
mod live;
#[cfg(feature = "net")]
mod netcmd;
mod notice;
mod plugin;
pub mod proxy;
mod scan;

use anyhow::Result;
use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use tracing::Level;

#[derive(Parser)]
#[command(
    name = "casual",
    version,
    about = "Modular CLI: network diagnostics, logging proxy, file scanner, plugins, live ML viz.",
    long_about = None,
)]
struct Cli {
    /// Increase log detail (-v = debug, -vv = trace).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a file or directory for known signatures and suspicious entropy.
    Scan(scan::ScanArgs),

    /// Run a local HTTP(S) proxy that logs the traffic passing through it.
    Proxy(proxy::ProxyArgs),

    /// Work with plugins (list them, or run one).
    Plugin {
        #[command(subcommand)]
        cmd: PluginCmd,
    },

    /// Watch a tiny model learn, rendered live in the terminal.
    Learn(learn::LearnArgs),

    /// Interactive menu that ties everything together.
    Live,

    /// Generate a shell completion script (bash, zsh, fish, ...).
    Completions {
        /// Which shell to generate for.
        shell: clap_complete::Shell,
    },

    /// Create/print the local intercept CA (needs the `intercept` feature).
    Ca,

    /// DNS lookup over UDP (record type A, AAAA, MX, TXT, CNAME, NS).
    Dns(dns::DnsArgs),

    /// Show the effective configuration and where it is read from.
    Config,

    /// Render a man page to stdout.
    Man,

    /// Inspect a server's TLS certificate chain (needs the `net` feature).
    #[cfg(feature = "net")]
    Tls(netcmd::TlsArgs),

    /// Send one HTTP(S) request, print status/headers/timing (`net` feature).
    #[cfg(feature = "net")]
    Probe(netcmd::ProbeArgs),

    /// Replay requests from a proxy JSONL log (needs the `net` feature).
    #[cfg(feature = "net")]
    Replay(netcmd::ReplayArgs),

    /// Live TUI dashboard tailing a proxy log (needs the `tui` feature).
    #[cfg(feature = "tui")]
    Dash(dash::DashArgs),
}

#[derive(Subcommand)]
enum PluginCmd {
    /// List every registered plugin.
    List,
    /// Run a plugin by name, passing the rest of the args to it.
    Run {
        name: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

/// Parse arguments and dispatch. The binary's `main` just calls this.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    match cli.command {
        Command::Scan(args) => scan::run(args),
        Command::Proxy(args) => proxy::run(args),
        Command::Plugin { cmd } => match cmd {
            PluginCmd::List => {
                plugin::list();
                Ok(())
            }
            PluginCmd::Run { name, args } => plugin::run(&name, &args),
        },
        Command::Learn(args) => learn::run(args),
        Command::Live => live::run(),
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
        Command::Ca => {
            #[cfg(feature = "intercept")]
            {
                intercept::ensure_ca_and_print()
            }
            #[cfg(not(feature = "intercept"))]
            {
                anyhow::bail!(
                    "`casual ca` needs a build with the intercept feature:\n  cargo build --release --features intercept"
                )
            }
        }
        Command::Dns(args) => dns::run(args),
        Command::Config => config::show(),
        Command::Man => {
            clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout())?;
            Ok(())
        }
        #[cfg(feature = "net")]
        Command::Tls(args) => netcmd::tls(args),
        #[cfg(feature = "net")]
        Command::Probe(args) => netcmd::probe(args),
        #[cfg(feature = "net")]
        Command::Replay(args) => netcmd::replay(args),
        #[cfg(feature = "tui")]
        Command::Dash(args) => dash::run(args),
    }
}

fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .without_time()
        .init();
}
