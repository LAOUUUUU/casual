//! Thin binary wrapper. All logic lives in the library crate so tests and fuzz
//! targets can reach it; see `src/lib.rs`.

fn main() -> anyhow::Result<()> {
    casual::run()
}
