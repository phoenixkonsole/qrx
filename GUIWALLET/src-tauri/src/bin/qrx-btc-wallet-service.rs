#[path = "../btc_wallet_service.rs"]
mod btc_wallet_service;

use serde_json::{json, Value};
use std::{env, io::{self, Read}, path::PathBuf};

fn main() {
    let args=env::args().skip(1).collect::<Vec<_>>();
    let data_dir=args.windows(2).find(|w|w[0]=="--data-dir").map(|w|PathBuf::from(&w[1]));
    let Some(data_dir)=data_dir else { eprintln!("qrx-btc-wallet-service: --data-dir is required");std::process::exit(2) };
    let mut input=String::new();
    if let Err(e)=io::stdin().read_to_string(&mut input){eprintln!("qrx-btc-wallet-service: {e}");std::process::exit(2)}
    let result=(|| -> Result<Value,String>{
        let request:Value=serde_json::from_str(&input).map_err(|e|format!("invalid stdin JSON: {e}"))?;
        btc_wallet_service::Service::new(data_dir)?.execute(request)
    })();
    match result {
        Ok(value)=>println!("{}",json!({"ok":true,"result":value})),
        Err(error)=>{println!("{}",json!({"ok":false,"error":error}));std::process::exit(1)}
    }
}
