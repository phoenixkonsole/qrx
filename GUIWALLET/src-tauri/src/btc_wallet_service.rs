use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use bdk::{
    bitcoin::{Address, Network},
    blockchain::{Blockchain, ElectrumBlockchain},
    database::MemoryDatabase,
    electrum_client::Client as ElectrumClient,
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        DerivableKey, ExtendedKey, GeneratableKey, GeneratedKey,
    },
    miniscript::Segwitv0,
    wallet::AddressIndex,
    FeeRate, SignOptions, SyncOptions, Wallet,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Serialize, Deserialize)]
struct WalletFile {
    network: String,
    encrypted_mnemonic: String,
    nonce: String,
    kdf: String,
    kdf_salt: String,
    descriptor: String,
    change_descriptor: String,
    mnemonic_note: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyWalletFile {
    network: String,
    mnemonic: String,
    descriptor: String,
    change_descriptor: String,
    mnemonic_note: String,
}

pub struct Service {
    data_dir: PathBuf,
}

impl Service {
    pub fn new(data_dir: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(data_dir.join("btc-light")).map_err(|e| e.to_string())?;
        fs::create_dir_all(data_dir.join("settings")).map_err(|e| e.to_string())?;
        Ok(Self { data_dir })
    }

    fn wallet_dir(&self) -> PathBuf { self.data_dir.join("btc-light") }
    fn wallet_file(&self) -> PathBuf { self.wallet_dir().join("btc_wallet.json") }
    fn setting(&self, name: &str) -> PathBuf { self.data_dir.join("settings").join(name) }

    fn read_setting(&self, name: &str, default: &str) -> String {
        fs::read_to_string(self.setting(name)).ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).unwrap_or_else(|| default.to_owned())
    }

    fn write_setting(&self, name: &str, value: &str) -> Result<(), String> {
        atomic_private_write(&self.setting(name), value.trim().as_bytes())
    }

    fn mode(&self) -> String { self.read_setting("btc_mode.txt", "electrum") }

    fn endpoints(&self) -> Vec<String> {
        let mode = self.mode();
        parse_endpoint_list(&self.read_setting("btc_endpoints.txt", &default_endpoints(&mode).join("\n")), &mode)
    }

    fn active_endpoint(&self) -> String {
        choose_active_endpoint(&self.endpoints()).0
    }

    fn require_passphrase(request: &Value) -> Result<String, String> {
        let pass = request.get("passphrase").and_then(Value::as_str).unwrap_or("").to_owned();
        if pass.is_empty() { Err("BTC wallet passphrase is required".into()) } else { Ok(pass) }
    }

    fn wallet_from_words(words: &str, passphrase: &str, note: &str) -> Result<WalletFile, String> {
        let mnemonic = Mnemonic::parse_in(Language::English, words).map_err(|e| e.to_string())?;
        let _ = descriptors(mnemonic)?;
        let (encrypted_mnemonic, nonce, kdf_salt) = encrypt(words, passphrase)?;
        Ok(WalletFile {
            network: "bitcoin".into(), encrypted_mnemonic, nonce,
            kdf: "argon2id:v=19,m=65536,t=3,p=1".into(), kdf_salt,
            descriptor: String::new(), change_descriptor: String::new(), mnemonic_note: note.into(),
        })
    }

    fn create_wallet(&self, passphrase: &str) -> Result<WalletFile, String> {
        let generated: GeneratedKey<Mnemonic, Segwitv0> = Mnemonic::generate((WordCount::Words12, Language::English)).map_err(|e| format!("{e:?}"))?;
        let (words, _descriptor, _change_descriptor) = descriptors(generated.into_key())?;
        let (encrypted_mnemonic, nonce, kdf_salt) = encrypt(&words, passphrase)?;
        Ok(WalletFile {
            network: "bitcoin".into(), encrypted_mnemonic, nonce,
            kdf: "argon2id:v=19,m=65536,t=3,p=1".into(), kdf_salt,
            descriptor: String::new(), change_descriptor: String::new(),
            mnemonic_note: "BTC mnemonic is encrypted locally with Argon2id + AES-256-GCM.".into(),
        })
    }

    fn save_wallet(&self, wallet: &WalletFile) -> Result<(), String> {
        atomic_private_write(&self.wallet_file(), serde_json::to_string_pretty(wallet).map_err(|e| e.to_string())?.as_bytes())
    }

    fn ensure_wallet(&self, passphrase: &str) -> Result<WalletFile, String> {
        let path = self.wallet_file();
        if !path.exists() {
            let wallet = self.create_wallet(passphrase)?; self.save_wallet(&wallet)?; return Ok(wallet);
        }
        let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        if let Ok(mut wallet) = serde_json::from_str::<WalletFile>(&text) {
            decrypt(&wallet, passphrase)?;
            if wallet.descriptor.contains("xprv")||wallet.descriptor.contains("tprv")||wallet.change_descriptor.contains("xprv")||wallet.change_descriptor.contains("tprv") {
                wallet.descriptor.clear();wallet.change_descriptor.clear();self.save_wallet(&wallet)?;
            }
            return Ok(wallet);
        }
        if let Ok(legacy) = serde_json::from_str::<LegacyWalletFile>(&text) {
            let wallet = Self::wallet_from_words(&legacy.mnemonic, passphrase, "Migrated from the plaintext development wallet into the shared encrypted BDK service.")?;
            self.save_wallet(&wallet)?; return Ok(wallet);
        }
        Err("Unsupported or damaged BTC wallet file; no replacement was written".into())
    }

    fn open_wallet(&self, passphrase: &str, endpoint: &str) -> Result<(Wallet<MemoryDatabase>, ElectrumBlockchain), String> {
        let file = self.ensure_wallet(passphrase)?;
        let words=decrypt(&file, passphrase)?;let mnemonic=Mnemonic::parse_in(Language::English,&words).map_err(|e|e.to_string())?;let (_words,descriptor,change_descriptor)=descriptors(mnemonic)?;
        let wallet = Wallet::new(&descriptor, Some(&change_descriptor), Network::Bitcoin, MemoryDatabase::default()).map_err(|e| e.to_string())?;
        let client = ElectrumClient::new(&normalize_electrum(endpoint)).map_err(|e| e.to_string())?;
        Ok((wallet, ElectrumBlockchain::from(client)))
    }

    fn status(&self, request: &Value, force_sync: bool) -> Result<Value, String> {
        if let Some(raw) = request.get("endpoint").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
            let mode = self.mode(); let endpoints = parse_endpoint_list(raw, &mode);
            self.write_setting("btc_endpoints.txt", &endpoints.join("\n"))?;
        }
        let mode = self.mode(); let endpoints = self.endpoints();
        let (active, health) = choose_active_endpoint(&endpoints);
        let mut confirmed=0u64; let mut trusted=0u64; let mut untrusted=0u64; let mut immature=0u64; let mut synced=false;
        if mode == "electrum" {
            if let Some(pass) = request.get("passphrase").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                let (wallet, blockchain) = self.open_wallet(pass, &active)?;
                wallet.sync(&blockchain, SyncOptions::default()).map_err(|e| e.to_string())?;
                let b=wallet.get_balance().map_err(|e| e.to_string())?;
                confirmed=b.confirmed;trusted=b.trusted_pending;untrusted=b.untrusted_pending;immature=b.immature;synced=true;
            } else if force_sync { return Err("BTC wallet passphrase is required for sync".into()); }
        }
        let total=confirmed.saturating_add(trusted).saturating_add(untrusted).saturating_add(immature);
        Ok(json!({"mode":mode,"balance":format!("{:.8} BTC",total as f64/100_000_000.0),"confirmed_sats":confirmed,"trusted_pending_sats":trusted,"untrusted_pending_sats":untrusted,"immature_sats":immature,"endpoint":endpoints.first().cloned().unwrap_or_else(||active.clone()),"active_endpoint":active,"endpoints":endpoints,"endpoint_health":health,"fallback_enabled":true,"privacy_level":if mode=="neutrino"{"enhanced-local-filter-checks"}else{"medium-server-assisted"},"neutrino_ready":mode=="neutrino","full_node_required":false,"synced":synced,"explanation":"Tauri and CLI use the same encrypted BDK wallet service and key store.","disclaimer":"Non-custodial software. Public endpoints can observe network metadata."}))
    }

    pub fn execute(&self, request: Value) -> Result<Value, String> {
        let operation=request.get("operation").and_then(Value::as_str).ok_or_else(||"operation is required".to_string())?;
        match operation {
            "status" | "balance" => self.status(&request, false),
            "sync" => self.status(&request, true),
            "test-endpoints" => {
                let mode=self.mode();let raw=request.get("endpoint").and_then(Value::as_str).map(str::to_owned).unwrap_or_else(||self.endpoints().join("\n"));
                Ok(serde_json::to_value(parse_endpoint_list(&raw,&mode).iter().map(|e|test_endpoint(e)).collect::<Vec<_>>()).map_err(|e|e.to_string())?)
            }
            "set-mode" => {
                let mode=match request.get("mode").and_then(Value::as_str).unwrap_or("electrum") {"electrum"=>"electrum","esplora"=>"esplora","neutrino"=>"neutrino",_=>return Err("mode must be electrum, esplora or neutrino".into())};
                self.write_setting("btc_mode.txt",mode)?;
                let endpoints=request.get("endpoint").and_then(Value::as_str).map(|r|parse_endpoint_list(r,mode)).unwrap_or_else(||default_endpoints(mode));
                self.write_setting("btc_endpoints.txt",&endpoints.join("\n"))?;self.status(&json!({}),false)
            }
            "start-neutrino" => { self.write_setting("btc_mode.txt","neutrino")?;self.write_setting("btc_endpoints.txt",&default_endpoints("neutrino").join("\n"))?;self.status(&json!({}),false) }
            "init" => {
                let pass=Self::require_passphrase(&request)?;let endpoint=self.active_endpoint();let (wallet,_)=self.open_wallet(&pass,&endpoint)?;
                let address=wallet.get_address(AddressIndex::Peek(0)).map_err(|e|e.to_string())?.address.to_string();
                Ok(json!({"status":"bdk-wallet-ready","network":"bitcoin","address":address,"warning":"The recovery phrase is encrypted with Argon2id + AES-256-GCM."}))
            }
            "backup" => { let pass=Self::require_passphrase(&request)?;let wallet=self.ensure_wallet(&pass)?;Ok(json!({"status":"backup-phrase-decrypted","mnemonic":decrypt(&wallet,&pass)?,"warning":"Keep these words offline. Anyone with them can spend the BTC."})) }
            "restore" => {
                let pass=Self::require_passphrase(&request)?;let words=request.get("mnemonic").and_then(Value::as_str).unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ");
                if words.is_empty(){return Err("recovery phrase is required".into())}let overwrite=request.get("overwrite").and_then(Value::as_bool).unwrap_or(false);
                if self.wallet_file().exists()&&!overwrite{return Err("BTC wallet already exists; use overwrite only after backing it up".into())}
                let wallet=Self::wallet_from_words(&words,&pass,"Restored through the shared encrypted BDK wallet service.")?;self.save_wallet(&wallet)?;let _=fs::remove_file(self.wallet_dir().join("address_index.txt"));
                let (bdk,_)=self.open_wallet(&pass,&self.active_endpoint())?;let address=bdk.get_address(AddressIndex::Peek(0)).map_err(|e|e.to_string())?.address.to_string();
                Ok(json!({"status":"btc-wallet-restored","network":"bitcoin","first_address":address,"warning":"Restored. Run sync to recover history and balance."}))
            }
            "reset" => {
                if request.get("confirm").and_then(Value::as_str)!=Some("DELETE BTC WALLET"){return Err("Type DELETE BTC WALLET to confirm reset".into())}
                if self.wallet_file().exists(){fs::remove_file(self.wallet_file()).map_err(|e|e.to_string())?;}let _=fs::remove_file(self.wallet_dir().join("address_index.txt"));
                Ok(Value::String("Local encrypted BTC wallet removed. Funds remain on Bitcoin and require the recovery phrase.".into()))
            }
            "new-address" => {
                let pass=Self::require_passphrase(&request)?;let (wallet,_)=self.open_wallet(&pass,&self.active_endpoint())?;let index=self.reserve_address_index()?;
                let address=wallet.get_address(AddressIndex::Peek(index)).map_err(|e|e.to_string())?.address.to_string();
                Ok(json!({"address":address,"status":"bdk-address","note":"Generated by the shared Tauri/CLI BDK descriptor wallet."}))
            }
            "list-addresses" => {
                let pass=Self::require_passphrase(&request)?;let (wallet,_)=self.open_wallet(&pass,&self.active_endpoint())?;
                let reserved=fs::read_to_string(self.wallet_dir().join("address_index.txt")).ok().and_then(|s|s.trim().parse::<u32>().ok()).unwrap_or(0);
                let count=std::cmp::max(1,reserved);let mut out=Vec::new();
                for index in 0..count {out.push(wallet.get_address(AddressIndex::Peek(index)).map_err(|e|e.to_string())?.address.to_string());}
                Ok(serde_json::to_value(out).map_err(|e|e.to_string())?)
            }
            "send" => {
                let pass=Self::require_passphrase(&request)?;let amount=request.get("amount_sats").and_then(Value::as_u64).unwrap_or(0);if amount==0{return Err("amount_sats must be greater than zero".into())}
                let recipient=request.get("to_address").and_then(Value::as_str).unwrap_or("").trim();let endpoint=self.active_endpoint();let (wallet,blockchain)=self.open_wallet(&pass,&endpoint)?;wallet.sync(&blockchain,SyncOptions::default()).map_err(|e|e.to_string())?;
                let address=Address::from_str(recipient).map_err(|e|e.to_string())?.require_network(Network::Bitcoin).map_err(|e|e.to_string())?;let mut builder=wallet.build_tx();builder.add_recipient(address.script_pubkey(),amount);
                if let Some(rate)=request.get("fee_rate_sat_vb").and_then(Value::as_f64).filter(|r|*r>0.0){builder.fee_rate(FeeRate::from_sat_per_vb(rate as f32));}
                let (mut psbt,_)=builder.finish().map_err(|e|e.to_string())?;if !wallet.sign(&mut psbt,SignOptions::default()).map_err(|e|e.to_string())?{return Err("could not finalize BTC transaction".into())}
                let tx=psbt.extract_tx();blockchain.broadcast(&tx).map_err(|e|e.to_string())?;Ok(json!({"txid":tx.txid().to_string(),"amount_sats":amount,"recipient":recipient,"endpoint":endpoint}))
            }
            _ => Err(format!("unknown BTC wallet operation: {operation}")),
        }
    }

    fn reserve_address_index(&self) -> Result<u32,String> {
        let lock=self.wallet_dir().join("address_index.lock");let mut acquired=false;
        for _ in 0..100 { if fs::create_dir(&lock).is_ok(){acquired=true;break} thread::sleep(Duration::from_millis(10)); }
        if !acquired{return Err("BTC address index is busy".into())}
        let path=self.wallet_dir().join("address_index.txt");let current=fs::read_to_string(&path).ok().and_then(|s|s.trim().parse().ok()).unwrap_or(1);
        let result=atomic_private_write(&path,(current+1).to_string().as_bytes()).map(|_|current);let _=fs::remove_dir(&lock);result
    }
}

fn atomic_private_write(path:&Path,bytes:&[u8])->Result<(),String>{
    if let Some(parent)=path.parent(){fs::create_dir_all(parent).map_err(|e|e.to_string())?;}let tmp=path.with_extension(format!("tmp-{}-{}",std::process::id(),rand::random::<u64>()));
    let mut options=OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
    let mut file=options.open(&tmp).map_err(|e|e.to_string())?;file.write_all(bytes).and_then(|_|file.sync_all()).map_err(|e|e.to_string())?;drop(file);
    #[cfg(not(windows))]
    fs::rename(&tmp,path).map_err(|e|e.to_string())?;
    #[cfg(windows)]
    {
        let backup=path.with_extension(format!("replace-backup-{}",std::process::id()));
        if path.exists(){fs::rename(path,&backup).map_err(|e|e.to_string())?;}
        if let Err(error)=fs::rename(&tmp,path){if backup.exists(){let _=fs::rename(&backup,path);}return Err(error.to_string())}
        if backup.exists(){let _=fs::remove_file(backup);}
    }
    #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;fs::set_permissions(path,fs::Permissions::from_mode(0o600)).map_err(|e|e.to_string())?;}Ok(())
}

fn derive_key(passphrase:&str,salt:&[u8])->Result<[u8;32],String>{let params=Params::new(64*1024,3,1,Some(32)).map_err(|e|e.to_string())?;let argon=Argon2::new(Algorithm::Argon2id,Version::V0x13,params);let mut key=[0u8;32];argon.hash_password_into(passphrase.as_bytes(),salt,&mut key).map_err(|e|e.to_string())?;Ok(key)}
fn encrypt(words:&str,passphrase:&str)->Result<(String,String,String),String>{let mut salt=[0u8;16];rand::thread_rng().fill_bytes(&mut salt);let key=derive_key(passphrase,&salt)?;let cipher=Aes256Gcm::new_from_slice(&key).map_err(|e|e.to_string())?;let mut nonce=[0u8;12];rand::thread_rng().fill_bytes(&mut nonce);let encrypted=cipher.encrypt(Nonce::from_slice(&nonce),words.as_bytes()).map_err(|e|e.to_string())?;Ok((general_purpose::STANDARD.encode(encrypted),general_purpose::STANDARD.encode(nonce),general_purpose::STANDARD.encode(salt)))}
fn decrypt(wallet:&WalletFile,passphrase:&str)->Result<String,String>{let salt=general_purpose::STANDARD.decode(&wallet.kdf_salt).map_err(|e|e.to_string())?;let key=derive_key(passphrase,&salt)?;let cipher=Aes256Gcm::new_from_slice(&key).map_err(|e|e.to_string())?;let nonce=general_purpose::STANDARD.decode(&wallet.nonce).map_err(|e|e.to_string())?;let data=general_purpose::STANDARD.decode(&wallet.encrypted_mnemonic).map_err(|e|e.to_string())?;String::from_utf8(cipher.decrypt(Nonce::from_slice(&nonce),data.as_ref()).map_err(|_|"wrong BTC wallet passphrase".to_string())?).map_err(|e|e.to_string())}
fn descriptors(mnemonic:Mnemonic)->Result<(String,String,String),String>{let words=mnemonic.to_string();let xkey:ExtendedKey=mnemonic.into_extended_key().map_err(|e|e.to_string())?;let xprv=xkey.into_xprv(Network::Bitcoin).ok_or_else(||"mnemonic did not produce xprv".to_string())?;Ok((words,format!("wpkh({xprv}/84h/0h/0h/0/*)"),format!("wpkh({xprv}/84h/0h/0h/1/*)")))}

fn default_endpoints(mode:&str)->Vec<String>{match mode{"esplora"=>vec!["https://blockstream.info/api".into(),"https://mempool.space/api".into()],"neutrino"=>vec!["neutrino://bitcoin-p2p-mainnet".into()],_=>vec!["ssl://electrum.blockstream.info:50002".into(),"ssl://electrum.emzy.de:50002".into(),"ssl://electrum.bitaroo.net:50002".into()]}}
fn normalize_endpoint(raw:&str,mode:&str)->Option<String>{let mut s=raw.trim().trim_matches(',').trim().to_owned();if s.is_empty()||s.starts_with('#'){return None}if !s.contains("://"){s=if mode=="esplora"{format!("https://{s}")}else{format!("ssl://{s}")};}Some(s)}
fn parse_endpoint_list(raw:&str,mode:&str)->Vec<String>{let mut out=Vec::new();for part in raw.split(|c|c=='\n'||c==','||c==';'){if let Some(ep)=normalize_endpoint(part,mode){if !out.contains(&ep){out.push(ep)}}}if out.is_empty(){default_endpoints(mode)}else{out}}
fn normalize_electrum(endpoint:&str)->String{if endpoint.contains("://"){endpoint.trim().to_owned()}else{format!("ssl://{}",endpoint.trim())}}
fn test_endpoint(endpoint:&str)->Value{let started=Instant::now();if endpoint.starts_with("http"){return json!({"endpoint":endpoint,"status":"configured","latency_ms":null,"note":"HTTP endpoint configured"})}if endpoint.starts_with("neutrino://"){return json!({"endpoint":endpoint,"status":"prepared","latency_ms":null,"note":"Neutrino is prepared but not bundled"})}let host=endpoint.trim_start_matches("ssl://").trim_start_matches("tcp://");let host=if host.contains(':'){host.to_owned()}else{format!("{host}:50002")};let ok=host.to_socket_addrs().ok().map(|a|a.into_iter().any(|x|TcpStream::connect_timeout(&x,Duration::from_millis(1200)).is_ok())).unwrap_or(false);json!({"endpoint":endpoint,"status":if ok{"reachable"}else{"unreachable"},"latency_ms":started.elapsed().as_millis(),"note":if ok{"TCP connection succeeded"}else{"No endpoint accepted a connection"}})}
fn choose_active_endpoint(endpoints:&[String])->(String,Vec<Value>){let mut health=Vec::new();let mut active=endpoints.first().cloned().unwrap_or_else(||"not-configured".into());for ep in endpoints{let h=test_endpoint(ep);let ok=matches!(h.get("status").and_then(Value::as_str),Some("reachable")|Some("configured")|Some("prepared"));health.push(h);if ok{active=ep.clone();break}}for ep in endpoints.iter().skip(health.len()){health.push(json!({"endpoint":ep,"status":"fallback-standby","latency_ms":null,"note":"Earlier endpoint selected"}))}(active,health)}
