//! Embed the actual toolchain identity at build time, so `kernel_ref` can
//! bind to it: the same kernel source built by a different rustc is a
//! different enforcement binary, and runtime evidence must be able to tell
//! them apart.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    // `--verbose` includes release, commit hash, and host triple — the full
    // identity, not just a version number.
    let version = std::process::Command::new(&rustc)
        .args(["--version", "--verbose"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().replace('\n', "; "))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-toolchain".to_string());
    println!("cargo:rustc-env=KERNEL_RUSTC_VERSION={version}");
}
