use std::env;

fn main() {
    let pure_rust = env::var("CARGO_FEATURE_PURE_RUST").is_ok();
    if pure_rust {
        return;
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("No target arch");
    match &*arch {
        "x86_64" | "aarch64" => {},
        _ => return
    }
    cc::Build::new()
        .opt_level(3)
        .flag_if_supported("-Wno-unknown-pragmas")
        .flag_if_supported("-mtune=native")
        .flag_if_supported("-mneon")
        .flag_if_supported("-maes")
        .flag_if_supported("-msse4.1")
        .file("src/c/aegis128l.c")
        .compile("aegis_aesni");
}
