//! A minimal casual WASM plugin.
//!
//! Contract with the host:
//!   * it imports `casual.print(ptr, len)` — the ONLY thing it can do besides
//!     compute; no filesystem, no network, no syscalls.
//!   * it exports `run() -> i32` (0 = success) and its linear `memory`.

#[link(wasm_import_module = "casual")]
unsafe extern "C" {
    fn print(ptr: *const u8, len: usize);
}

fn emit(s: &str) {
    unsafe { print(s.as_ptr(), s.len()) }
}

#[unsafe(no_mangle)]
pub extern "C" fn run() -> i32 {
    emit("hello from a sandboxed WASM plugin!\n");
    // Prove it's really executing code, not just printing a literal:
    let sum: u32 = (1..=100).sum();
    emit(&format!("  (1 + 2 + ... + 100 = {sum}, computed inside the sandbox)\n"));
    0
}
