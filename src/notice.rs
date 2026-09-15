//! One place for the legal notice, printed before the network-touching tools
//! run (proxy, port checks, interactive mode).

pub const DISCLAIMER: &str = "\
────────────────────────────────────────────────────────────────
 casual — legal notice
 These tools inspect networks, traffic, and files. Pointing them
 at any system or network you do NOT own — or lack explicit
 written permission to test — may be illegal where you live
 (computer-misuse, unauthorized-access, and wiretap laws all
 apply). Whether you follow those rules is your choice, and the
 consequences are yours alone. Provided as-is, no warranty.
────────────────────────────────────────────────────────────────";

/// Print the disclaimer to stderr (so it never pollutes piped/JSON output).
pub fn show() {
    eprintln!("{DISCLAIMER}");
}
