
import { useState } from "react";

export function SendPage(props: { onSend: (address: string, amount: string, memo: string) => Promise<void>; output: string }) {
  const [address, setAddress] = useState("");
  const [amount, setAmount] = useState("");
  const [memo, setMemo] = useState("wallet payment");

  return (
    <div className="stack">
      <div className="card">
        <h2 className="section-title">Send QUB</h2>
        <div className="two-col">
          <div>
            <label>Recipient address</label>
            <input value={address} onChange={(e) => setAddress(e.target.value)} placeholder="QRX..." />
          </div>
          <div>
            <label>Amount</label>
            <input value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="10.0" />
          </div>
        </div>
        <div style={{ marginTop: 12 }}>
          <label>Memo</label>
          <input value={memo} onChange={(e) => setMemo(e.target.value)} placeholder="optional memo" />
        </div>
        <div className="toolbar">
          <button onClick={() => props.onSend(address, amount, memo)}>Send transaction</button>
        </div>
        <div className="warning">
          Always test with small amounts first while QRX remains in alpha.
        </div>
      </div>

      <div className="card">
        <h3 className="section-title">Last send result</h3>
        <pre>{props.output || "No send result yet."}</pre>
      </div>
    </div>
  );
}
