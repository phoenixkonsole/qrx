# QRX 0.0.7 Wallet Manager – Inspect & Import

This patch adds a read-only wallet inspector and safe wallet/key-set import UI.

Safety invariants:
- Existing wallet directories are never overwritten.
- Hybrid key-set import only targets a new wallet name.
- Key-set import requires address.txt plus Ed25519 and ML-DSA65 private/public PEM files.
- Existing legacy wallets are inspected in place and retain the pre-0.0.7 safety-backup requirement.
- Private-key PEM headers are inspected to report encrypted vs unencrypted key protection; passphrases are never persisted by the GUI.
- Data directory and control-socket paths are surfaced from daemon health instead of left blank after a successful status refresh.
