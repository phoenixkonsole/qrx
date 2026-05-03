
export function ReceivePage(props: { address: string; onGenerate: () => Promise<void> }) {
  return (
    <div className="stack">
      <div className="card">
        <h2 className="section-title">Receive QUB</h2>
        <p className="muted">Generate a fresh address from your current QRX wallet.</p>
        <div className="toolbar">
          <button onClick={props.onGenerate}>Generate new address</button>
        </div>
        <div className="card" style={{ marginTop: 12, padding: 14 }}>
          <div className="metric-label">Current receive address</div>
          <div className="metric-value mono" style={{ fontSize: 18 }}>{props.address || "No address generated yet."}</div>
        </div>
      </div>
    </div>
  );
}
