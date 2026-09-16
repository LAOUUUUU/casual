# casual

[![CI](https://github.com/LAOUUUUU/casual/actions/workflows/ci.yml/badge.svg)](https://github.com/LAOUUUUU/casual/actions/workflows/ci.yml)

A small, modular, plugin-driven CLI toolkit in Rust. One tiny default binary,
no async runtime, no GUI framework — built to be cheap to run and easy to
extend. Heavier capabilities (HTTPS interception, a TLS client, a TUI, a WASM
runtime) are opt-in cargo features, so the base build stays lean.

```
casual scan   <path>          # mini-AV: hash + signature DB + entropy heuristic
casual proxy  [--port 8080]   # local HTTP(S) logging proxy for YOUR traffic
casual dns    <host> [type]   # DNS over UDP, by hand (A/AAAA/MX/TXT/CNAME/NS)
casual plugin list|run ...    # native + WASM plugins (built-ins: hash/entropy/ports)
casual learn                  # watch a model learn, live in the terminal
casual live                   # interactive menu
casual config                 # show effective settings + write a sample
casual completions <shell>    # shell tab-completion script
casual man                    # render a man page

# opt-in features:
casual tls   <host>           # (--features net)  inspect a cert chain
casual probe <url>            # (--features net)  one request: status/headers/timing
casual replay <log.jsonl>     # (--features net)  re-issue captured requests
casual dash  [log.jsonl]      # (--features tui)  live dashboard tailing a proxy log
casual proxy --intercept      # (--features intercept)  decrypt your own HTTPS
```

Add `-v` (or `-vv`) to any command for more logging.

## ⚠️ Legal notice

These tools inspect networks, traffic, and files. Pointing them at any system
or network you do **not** own — or lack explicit written permission to test —
may be **illegal** where you live (computer-misuse, unauthorized-access, and
wiretap laws all apply). Whether you follow those rules is your choice, and the
consequences are yours alone. Provided as-is, with no warranty. The same notice
prints to your terminal whenever the network-touching commands run.

## Install

```bash
cargo build --release                         # lean default build
cargo build --release --features net,tui      # add the diagnostics + dashboard
cargo install --path .                         # put `casual` on your PATH
casual completions zsh > ~/.zfunc/_casual
```

Feature flags: `net` (tls/probe/replay), `tui` (dash), `intercept` (HTTPS
decryption), `wasm` (sandboxed plugins). Combine freely, e.g.
`--features net,tui,wasm`.

## Commands

### scan — a mini antivirus
Streams each file for a SHA-256, computes Shannon entropy (packed/encrypted
data sits near 8.0 bits/byte), matches a JSON signature DB, **looks inside .zip
archives**, runs in parallel with a progress bar, and colours verdicts
(respecting `NO_COLOR`).

```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
casual scan /tmp/eicar.txt
casual scan ~/Downloads --json > report.jsonl
casual scan ~/Downloads --quarantine ~/.casual-quarantine   # move MALICIOUS files
casual scan big.iso --no-archives                            # skip zip inspection
```

### proxy — a local logging proxy
Point your browser/app's HTTP+HTTPS proxy at `127.0.0.1:8080`.

```bash
casual proxy --log-file traffic.jsonl        # one JSON object per request
casual proxy --max-conns 128                  # cap concurrent connections
casual proxy --block ads. --block tracker.    # 403 hosts matching a substring
casual proxy --allow-only mycorp.com          # whitelist mode
casual proxy --capture-dir ./cap              # save plain-HTTP bodies to files
```

HTTPS (CONNECT) is tunneled and logged by host — not decrypted (see *intercept*).

### dns — DNS on the wire
A hand-rolled UDP DNS client (builds the packet, parses compression) — a good
way to actually see how DNS works.

```bash
casual dns example.com A
casual dns example.com MX
casual dns example.com TXT --server 8.8.8.8
casual dns example.com A --json         # structured output for scripts
```

`--json` is also on `tls` and `probe`.

### plugin — native and sandboxed
Built-ins: `hash`, `entropy`, `ports`. Drop a compiled library into your plugin
dir and it loads automatically:

- **Native** (`.dylib`/`.so`/`.dll`) — full trust, fastest. See `example-plugin/`.
- **WASM** (`.wasm`, needs `--features wasm`) — sandboxed: the plugin can only
  compute and call the one `print` host function; no filesystem, no network.
  See `example-wasm-plugin/`.

```bash
# native
cd example-plugin && cargo build --release
cp target/release/libcasual_plugin_hello.dylib ~/.config/casual/plugins/
casual plugin run hello world

# wasm (sandboxed)
rustup target add wasm32-unknown-unknown
cd example-wasm-plugin && cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/casual_wasm_hello.wasm ~/.config/casual/plugins/
casual plugin run casual_wasm_hello
```

Plugin dir: `$CASUAL_PLUGIN_DIR`, else `~/.config/casual/plugins`, else `./plugins`.

> Native plugins run arbitrary native code with full trust — only load ones you
> trust. WASM plugins are sandboxed and safe to run even when you don't.

### learn — watch a model learn
```bash
casual learn                             # two blobs, one neuron
casual learn --dataset xor               # a single neuron FAILS (~50%)
casual learn --dataset xor --hidden 6    # a hidden layer SUCCEEDS (~100%)
casual learn --csv points.csv            # your own data: rows of  x,y,label
```

### config
`casual config` writes a sample `~/.config/casual/config.toml` (if absent) and
prints the effective settings. CLI flags always override the file.

## Opt-in features

### net — tls / probe / replay
```bash
cargo build --release --features net
casual tls example.com          # audit: negotiated version, TLS 1.2/1.3 support,
                                #        cert chain, expiry + self-signed warnings
casual probe https://example.com/
casual replay traffic.jsonl     # re-issue what the proxy captured
```

**Shared TLS options** (on `tls`, `probe`, `replay`) — for your own hosts:
```bash
casual probe https://selfsigned.local/ --insecure   # skip cert validation (curl -k)
casual tls internal.corp --cacert my-root-ca.pem     # trust an extra root CA
```

`casual tls` doubles as a mini SSL audit: it flags expired/soon-to-expire and
self-signed certs and probes **all four protocol versions** — TLS 1.2/1.3 via
rustls, and TLS 1.0/1.1 via a hand-crafted ClientHello on the raw wire (rustls
refuses to speak them), warning when a server still accepts the deprecated ones.
Decrypting your own HTTPS traffic in full is the `intercept` feature below.

```
$ casual tls github.com
negotiated TLSv1_3   validated: yes
TLS 1.0: no   1.1: no   1.2: yes   1.3: yes
```

### tui — the live dashboard
```bash
cargo build --release --features tui
casual proxy --log-file traffic.jsonl   # terminal 1
casual dash traffic.jsonl               # terminal 2 — live table + counters
```

### intercept — decrypt your own HTTPS
Runs a local CA and re-signs each site (mitmproxy/Burp model). Only works on
devices where **you** install the CA.

```bash
cargo build --release --features intercept
casual ca                        # creates + prints how to trust the CA
casual proxy --intercept         # HTTPS is now decrypted and logged
```

## Layout

```
src/
  lib.rs       CLI wiring + dispatch (the library crate)
  main.rs      thin binary wrapper over casual::run()
  scan.rs      parallel scanner (SHA-256, entropy, signatures, zip, colour)
  proxy.rs     std-thread HTTP(S) proxy (JSONL log, conn cap, block, capture)
  dns.rs       hand-rolled UDP DNS client
  plugin.rs    Plugin trait + registry + native + WASM loaders
  learn.rs     live logistic-regression / MLP visualization
  live.rs      interactive menu
  config.rs    ~/.config/casual/config.toml
  notice.rs    the legal notice
  netcmd.rs    tls/probe/replay        (feature = "net")
  dash.rs      live TUI dashboard       (feature = "tui")
  intercept.rs HTTPS interception       (feature = "intercept")
  plugin.rs::wasm  sandboxed WASM host  (feature = "wasm")
example-plugin/       native plugin example
example-wasm-plugin/  sandboxed WASM plugin example
fuzz/                 cargo-fuzz targets for the DNS + HTTP parsers
packaging/casual.rb   Homebrew formula template
signatures.json       sample signature DB (ships with EICAR)
.github/workflows/    ci.yml (fmt/clippy/test) + release.yml (tagged binaries)
```

## Hardening

The DNS and HTTP parsers are hand-rolled, so they're the highest-risk code.
They have in-tree tests that feed them truncated and random bytes and fail on
any panic (`cargo test`). `fuzz/` holds `cargo-fuzz` targets for continuous
fuzzing — `cargo +nightly fuzz run dns_parse`. (The v0.4 DNS out-of-bounds fix
was first caught by exactly that test.)

## Not yet: YARA

The scanner uses a JSON signature DB. Full **YARA** rule support is the natural
upgrade — either the pure-Rust `yara-x` crate or the `yara` C bindings — left
out for now to keep the default build lean (both drag in large dependencies).
