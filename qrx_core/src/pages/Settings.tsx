
import type { WalletConfig } from "../types";

export function SettingsPage(props: {
  config: WalletConfig;
  setConfig: (cfg: WalletConfig) => void;
  save: () => void;
}) {
  const cfg = props.config;
  return (
    <div className="stack">
      <div className="card">
        <h2 className="section-title">Settings</h2>
        <div className="two-col">
          <div>
            <label>Network</label>
            <select value={cfg.network} onChange={(e) => props.setConfig({ ...cfg, network: e.target.value as WalletConfig["network"] })}>
              <option value="alpha">alpha</option>
              <option value="testnet">testnet</option>
              <option value="regtest">regtest</option>
              <option value="mainnet">mainnet</option>
            </select>
          </div>
          <div>
            <label>Wallet name</label>
            <input value={cfg.wallet} onChange={(e) => props.setConfig({ ...cfg, wallet: e.target.value })} placeholder="default" />
          </div>
        </div>
        <div style={{ marginTop: 12 }}>
          <label>Data directory (optional)</label>
          <input value={cfg.datadir || ""} onChange={(e) => props.setConfig({ ...cfg, datadir: e.target.value })} placeholder="leave empty for QRX default" />
        </div>
        <div style={{ marginTop: 12 }}>
          <label>qrx-cli path override (optional)</label>
          <input value={cfg.cliPath || ""} onChange={(e) => props.setConfig({ ...cfg, cliPath: e.target.value })} placeholder="custom qrx-cli path" />
        </div>
        <div style={{ marginTop: 12 }}>
          <label>qrxd path override (optional)</label>
          <input value={cfg.daemonPath || ""} onChange={(e) => props.setConfig({ ...cfg, daemonPath: e.target.value })} placeholder="custom qrxd path" />
        </div>
        <div className="toolbar">
          <button onClick={props.save}>Save settings</button>
        </div>
      </div>
    </div>
  );
}
