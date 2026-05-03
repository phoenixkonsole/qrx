
mod commands;
mod qrx_bridge;

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::run_qrx_cli,
            commands::start_qrxd
        ])
        .run(tauri::generate_context!())
        .expect("error while running QRX wallet");
}
