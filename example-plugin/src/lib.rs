//! A minimal casual plugin, compiled as a C-ABI shared library.
//!
//! The host (casual) looks for one exported symbol, `casual_plugin_v1`, which
//! returns a flat struct describing the plugin and a function pointer to run
//! it. That's the whole contract — no Rust ABI dependency across the boundary.

use std::os::raw::c_char;

/// Must match `casual::plugin::RawPlugin` field-for-field.
#[repr(C)]
pub struct RawPlugin {
    pub abi_version: u32,
    pub name: *const c_char,
    pub description: *const c_char,
    pub usage: *const c_char,
    pub run: extern "C" fn(argc: usize, argv: *const *const c_char) -> i32,
}

extern "C" fn run(argc: usize, argv: *const *const c_char) -> i32 {
    println!("hello from a dynamically-loaded casual plugin!");
    for i in 0..argc {
        // SAFETY: the host passes `argc` valid, NUL-terminated C strings.
        let ptr = unsafe { *argv.add(i) };
        if !ptr.is_null() {
            let s = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_string_lossy();
            println!("  arg[{i}] = {s}");
        }
    }
    0 // 0 = success
}

/// The single exported entry point. `c"..."` literals are NUL-terminated and
/// `'static`, so the pointers stay valid for the life of the library.
#[unsafe(no_mangle)]
pub extern "C" fn casual_plugin_v1() -> RawPlugin {
    RawPlugin {
        abi_version: 1,
        name: c"hello".as_ptr(),
        description: c"example dynamically-loaded plugin".as_ptr(),
        usage: c"hello [args...]".as_ptr(),
        run,
    }
}
