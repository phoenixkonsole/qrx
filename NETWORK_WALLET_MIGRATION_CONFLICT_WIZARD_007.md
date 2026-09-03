# QRX 0.0.7 – Network Wallet Migration Conflict Wizard

QRX 0.0.7 uses network-independent QUB wallet identities under `~/.qrx/wallets/<name>`.

This patch removes the former implicit Alpha preference from legacy migration.

## Safe migration rules

- An existing shared identity always wins; it is never overwritten.
- Former per-network stores (`mainnet`, `alpha`, `testnet`, `regtest`) are scanned without network preference.
- If all discovered copies of the same wallet name resolve to one QUB address, QRX may copy the most complete candidate (hybrid keys/recovery/version) into the shared store.
- If different QUB addresses exist under the same legacy wallet name, automatic migration stops.
- No legacy source is deleted, merged, renamed or overwritten.
- The GUI exposes a Migration Conflict Wizard where the user explicitly selects the source network/identity.
- If a shared wallet with that name already exists, conflicting legacy identities can only be imported under a new wallet name.

This preserves Mainnet-only wallets and prevents an Alpha wallet from silently replacing them.
