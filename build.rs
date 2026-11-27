//! Build script (adapted from AutoTyper).
//!
//! * Decodes the app icon into raw RGBA (32 px for the tray, 48 px for the window) so the
//!   binary needs no image decoder at run time.
//! * On Windows targets, embeds the icon, version info and the application manifest
//!   (`assets/polytunnel.manifest`) as resources. This needs `rc.exe` from the Windows SDK.

use std::{env, fs, path::PathBuf};

const ICON: &str = "assets/polytunnel.ico";
const MANIFEST: &str = "assets/polytunnel.manifest";

fn main() {
    println!("cargo:rerun-if-changed={ICON}");
    println!("cargo:rerun-if-changed={MANIFEST}");

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let file = fs::File::open(ICON).expect("open the app icon");
    let dir = ico::IconDir::read(file).expect("parse the app icon");
    for size in [32u32, 48] {
        let entry = dir
            .entries()
            .iter()
            .find(|e| e.width() == size)
            .unwrap_or_else(|| panic!("{ICON} has no {size}x{size} image"));
        let image = entry.decode().expect("decode an icon image");
        fs::write(out.join(format!("icon{size}.rgba")), image.rgba_data())
            .expect("write the decoded icon");
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        windows_resources();
    }
}

#[cfg(windows)]
fn windows_resources() {
    let mut res = winresource::WindowsResource::new();
    res.set_icon(ICON)
        .set_manifest_file(MANIFEST)
        .set("FileDescription", "Polytunnel")
        .set("ProductName", "Polytunnel")
        .set("InternalName", "polytunnel")
        .set("OriginalFilename", "polytunnel.exe")
        .set("LegalCopyright", "MIT License");
    res.compile()
        .expect("embed Windows resources (needs rc.exe from the Windows SDK)");
}

#[cfg(not(windows))]
fn windows_resources() {
    // Cross-compiling Windows binaries from another OS is not supported: the resources
    // (icon, manifest) would be missing. Build Windows releases on Windows.
    println!("cargo:warning=building a Windows binary without icon/manifest resources");
}
