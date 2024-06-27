use std::env;

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
    cc::Build::new()
        .opt_level(3)
        .flag_if_supported("-Wno-unused-command-line-argument")
        .flag_if_supported("-Wno-unknown-pragmas")
        .flag_if_supported("-mtune=native")
        .flag_if_supported("-maes")
        .flag_if_supported("-mcrypto")
        .flag_if_supported("-mneon")
        .flag_if_supported("-maes")
        .include("src/c/libaegis/src/include")
        .file("src/c/libaegis/src/aegis128l/aegis128l.c")
        .file("src/c/libaegis/src/aegis128l/aegis128l_aesni.c")
        .file("src/c/libaegis/src/aegis128l/aegis128l_armcrypto.c")
        .file("src/c/libaegis/src/aegis128l/aegis128l_soft.c")
        .file("src/c/libaegis/src/aegis128x2/aegis128x2.c")
        .file("src/c/libaegis/src/aegis128x2/aegis128x2_aesni.c")
        .file("src/c/libaegis/src/aegis128x2/aegis128x2_armcrypto.c")
        .file("src/c/libaegis/src/aegis128x2/aegis128x2_avx2.c")
        .file("src/c/libaegis/src/aegis128x2/aegis128x2_soft.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4_aesni.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4_armcrypto.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4_avx2.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4_avx512.c")
        .file("src/c/libaegis/src/aegis128x4/aegis128x4_soft.c")
        .file("src/c/libaegis/src/aegis256/aegis256.c")
        .file("src/c/libaegis/src/aegis256/aegis256_aesni.c")
        .file("src/c/libaegis/src/aegis256/aegis256_armcrypto.c")
        .file("src/c/libaegis/src/aegis256/aegis256_soft.c")
        .file("src/c/libaegis/src/aegis256x2/aegis256x2.c")
        .file("src/c/libaegis/src/aegis256x2/aegis256x2_aesni.c")
        .file("src/c/libaegis/src/aegis256x2/aegis256x2_armcrypto.c")
        .file("src/c/libaegis/src/aegis256x2/aegis256x2_avx2.c")
        .file("src/c/libaegis/src/aegis256x2/aegis256x2_soft.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4_aesni.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4_armcrypto.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4_avx2.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4_avx512.c")
        .file("src/c/libaegis/src/aegis256x4/aegis256x4_soft.c")
        .file("src/c/libaegis/src/common/common.c")
        .file("src/c/libaegis/src/common/cpu.c")
        .file("src/c/libaegis/src/common/softaes.c")
        .compile("aegis_aesni");
}
