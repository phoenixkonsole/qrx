fn main() {
    // Keep support for service-only maintenance builds that deliberately skip
    // Tauri bundle validation. The unified release build performs the normal
    // Tauri build after all target-suffixed sidecars have been staged.
    println!("cargo:rerun-if-env-changed=QRX_BUILD_SERVICE_ONLY");
    if std::env::var_os("QRX_BUILD_SERVICE_ONLY").is_some() {
        return;
    }

    tauri_build::build();
}
