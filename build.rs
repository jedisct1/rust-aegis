use std::env;
use std::process::Command;

fn has_clang() -> bool {
    Command::new("clang")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Returns true when host and target differ (cross-compilation).
fn is_cross_compiling() -> bool {
    let host = env::var("HOST").unwrap_or_default();
    let target = env::var("TARGET").unwrap_or_default();
    !host.is_empty() && !target.is_empty() && host != target
}

fn main() {
    let pure_rust = env::var("CARGO_FEATURE_PURE_RUST").is_ok();
    if pure_rust {
        return;
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("No target arch");
    if arch == "wasm32" {
        let src_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-lib=static=aegis");
        println!("cargo:rustc-link-search=native={}/wasm-libs", src_dir);
        return;
    }
    let mut build = cc::Build::new();
    let cross = is_cross_compiling();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env == "msvc" {
        // On MSVC targets, use the cc crate's proper API for preferring clang-cl.
        // Manually setting compiler("clang") on MSVC targets causes malformed
        // command lines (the -x flag is generated without its language argument).
        build.prefer_clang_cl_over_msvc(true);
    } else if !cross && has_clang() {
        // Only force host clang for native builds. When cross-compiling (e.g.
        // for Android via NDK), let the `cc` crate auto-detect the correct
        // toolchain from CC_<target> / CFLAGS_<target> environment variables.
        build.compiler("clang");
    }
    build
        .opt_level(3)
        .flag_if_supported("-Wno-unused-command-line-argument")
        .flag_if_supported("-Wno-unknown-pragmas");
    if !cross {
        // -mtune=native is only valid when compiling for the host architecture.
        build.flag_if_supported("-mtune=native");
    }
    build
        .flag_if_supported("-mcrypto")
        .flag_if_supported("-mneon")
        .flag_if_supported("-maes")
        .include("src/c/libaegis/src/include")
        .file("src/c/libaegis/src/aegis128l/aegis128l.c")
        .file("src/c/libaegis/src/aegis128l/aegis128l_aesni.c")
        .file("src/c/libaegis/src/aegis128l/aegis128l_altivec.c")
        .file("src/c/libaegis/src/aegis128l/aegis128l_neon_aes.c")
        .file("src/c/libaegis/src/aegis128l/aegis128l_neon_sha3.c")
        .file("src/c/libaegis/src/aegis128l/aegis128l_soft.c")
        .file("src/c/libaegis/src/aegis128x2/aegis128x2.c")
        .file("src/c/libaegis/src/aegis128x2/aegis128x2_aesni.c")
        .file("src/c/libaegis/src/aegis128x2/aegis128x2_altivec.c")
        .file("src/c/libaegis/src/aegis128x2/aegis128x2_neon_aes.c")
        .file("src/c/libaegis/src/aegis128x2/aegis128x2_avx2.c")
        .file("src/c/libaegis/src/aegis128x2/aegis128x2_soft.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4_aesni.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4_altivec.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4_neon_aes.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4_avx2.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4_avx512.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4_soft.c")
        .file("src/c/libaegis/src/aegis256/aegis256.c")
        .file("src/c/libaegis/src/aegis256/aegis256_aesni.c")
        .file("src/c/libaegis/src/aegis256/aegis256_altivec.c")
        .file("src/c/libaegis/src/aegis256/aegis256_neon_aes.c")
        .file("src/c/libaegis/src/aegis256/aegis256_soft.c")
        .file("src/c/libaegis/src/aegis256x2/aegis256x2.c")
        .file("src/c/libaegis/src/aegis256x2/aegis256x2_aesni.c")
        .file("src/c/libaegis/src/aegis256x2/aegis256x2_altivec.c")
        .file("src/c/libaegis/src/aegis256x2/aegis256x2_neon_aes.c")
        .file("src/c/libaegis/src/aegis256x2/aegis256x2_avx2.c")
        .file("src/c/libaegis/src/aegis256x2/aegis256x2_soft.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4_aesni.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4_altivec.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4_neon_aes.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4_avx2.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4_avx512.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4_soft.c")
        .file("src/c/libaegis/src/common/common.c")
        .file("src/c/libaegis/src/common/cpu.c")
        .file("src/c/libaegis/src/common/softaes.c");
    if env::var("CARGO_FEATURE_RAF_CORE").is_ok() {
        build
            .file("src/c/libaegis/src/common/keccak.c")
            .file("src/c/libaegis/src/raf/raf.c")
            .file("src/c/libaegis/src/raf/raf_merkle.c")
            .file("src/c/libaegis/src/raf/raf_aegis128l.c")
            .file("src/c/libaegis/src/raf/raf_aegis128x2.c")
            .file("src/c/libaegis/src/raf/raf_aegis128x4.c")
            .file("src/c/libaegis/src/raf/raf_aegis256.c")
            .file("src/c/libaegis/src/raf/raf_aegis256x2.c")
            .file("src/c/libaegis/src/raf/raf_aegis256x4.c");
    }
    build.compile("aegis");
}
