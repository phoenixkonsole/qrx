# QRX 0.0.7 – Kraken KDF build fix

The legacy embedded BTC/BDK wallet cleanup removed `derive_btc_key`, but the encrypted Kraken credential vault still depended on the same Argon2id KDF helper. This caused Tauri builds to fail with `E0425` at the Kraken credential encrypt/decrypt paths.

Fix:
- restored the KDF as a generic `derive_secret_key` helper rather than reintroducing BTC wallet code;
- Kraken credential encryption/decryption now call `derive_secret_key`;
- Argon2 imports remain intentional and are used by the Kraken vault;
- no legacy embedded BTC wallet implementation was re-enabled.

KDF parameters remain unchanged: Argon2id, 64 MiB memory, 3 iterations, parallelism 1, 32-byte output.
