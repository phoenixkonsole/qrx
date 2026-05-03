
export function Dashboard(props: {
  balance: string;
  walletInfo: string;
  stakingInfo: string;
  tokenomics: string;
  onRefresh: () => void;
  onStartDaemon: () => void;
}) {
  return (
    <div className="stack">
      <div className="hero">
        <h2>Welcome to QRX Wallet</h2>
        <p className="muted">
          Lightweight desktop wallet with direct QRX Core integration. Start the daemon,
          refresh state and manage alpha funds in a modern UI.
        </p>
        <div className="toolbar">
          <button onClick={props.onStartDaemon}>Start daemon</button>
          <button className="secondary" onClick={props.onRefresh}>Refresh data</button>
        </div>
        <div className="warning">
          QRX is currently in alpha / pre-genesis. Expect resets, breaking changes and incomplete features.
        </div>
      </div>

      <div className="grid">
        <div className="card">
          <div className="metric-label">Balance</div>
          <div className="metric-value mono">{props.balance || "—"}</div>
        </div>
        <div className="card">
          <div className="metric-label">Wallet status</div>
          <div className="metric-value">Ready</div>
        </div>
        <div className="card">
          <div className="metric-label">Core mode</div>
          <div className="metric-value">CLI bridge</div>
        </div>
        <div className="card">
          <div className="metric-label">Security mode</div>
          <div className="metric-value">Local-only</div>
        </div>
      </div>

      <div className="split">
        <div className="card">
          <h3 className="section-title">Wallet Info</h3>
          <pre>{props.walletInfo || "No data yet."}</pre>
        </div>
        <div className="stack">
          <div className="card">
            <h3 className="section-title">Staking Info</h3>
            <pre>{props.stakingInfo || "No data yet."}</pre>
          </div>
          <div className="card">
            <h3 className="section-title">Tokenomics</h3>
            <pre>{props.tokenomics || "No data yet."}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}
