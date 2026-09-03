# QRX 0.0.7 — QUB/BTC Address Book + Unified Send/Receive

## Added
- Chain-aware local address book stored at `~/.qrx/addressbook.json` (mode 0600 on Unix).
- QUB and BTC contacts are explicitly labelled and filtered by chain.
- Contact address pinning: an existing contact cannot silently change chain/address; create a new contact instead.
- Duplicate chain+address entries are rejected.
- JSON export/import; imports add only new addresses and never overwrite an existing contact.
- Send view now switches between QUB and BTC.
- Receive view now switches between QUB and BTC.
- QUB send supports address-book selection, review/confirmation, memo and optional save-after-success.
- BTC send supports address-book selection, review/confirmation, sat amount, fee rate and optional save-after-success.
- QUB Receive shows existing wallet addresses first and can generate additional addresses.
- BTC Receive derives and lists existing descriptor addresses first and can generate additional addresses.
- Receive QR codes remain generated locally inside Tauri.
- BTC wallet password is kept distinct from the QUB wallet session passphrase.

## Safety
- Address book stores public addresses only; never private keys, mnemonics or wallet passphrases.
- QUB/BTC chain types are never mixed in Send pickers.
- BTC contacts are validated as Bitcoin mainnet addresses.
- QUB contacts must use the `qrx1...` format.
- Send always presents a final transaction review before broadcast.
