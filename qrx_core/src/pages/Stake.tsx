
import { useState } from "react";

export function StakePage(props: {
  onStake: (amount: string) => Promise<void>;
  onDelegate: (validator: string, amount: string) => Promise<void>;
  onValidatorSet: () => Promise<void>;
  output: string;
}) {
  const [stakeAmount, setStakeAmount] = useState("");
  const [delegateValidator, setDelegateValidator] = useState("");
  const [delegateAmount, setDelegateAmount] = useState("");

  return (
    <div className="stack">
      <div className="card">
        <h2 className="section-title">Stake & Delegate</h2>
        <div className="two-col">
          <div>
            <label>Stake amount</label>
            <input value={stakeAmount} onChange={(e) => setStakeAmount(e.target.value)} placeholder="1000" />
            <div className="toolbar">
              <button onClick={() => props.onStake(stakeAmount)}>Stake</button>
            </div>
          </div>
          <div>
            <label>Validator set</label>
            <div className="toolbar">
              <button className="secondary" onClick={props.onValidatorSet}>Load validator set</button>
            </div>
          </div>
        </div>

        <div className="two-col" style={{ marginTop: 12 }}>
          <div>
            <label>Validator address</label>
            <input value={delegateValidator} onChange={(e) => setDelegateValidator(e.target.value)} placeholder="validator id / address" />
          </div>
          <div>
            <label>Delegate amount</label>
            <input value={delegateAmount} onChange={(e) => setDelegateAmount(e.target.value)} placeholder="500" />
          </div>
        </div>

        <div className="toolbar">
          <button onClick={() => props.onDelegate(delegateValidator, delegateAmount)}>Delegate</button>
        </div>
      </div>

      <div className="card">
        <h3 className="section-title">Staking output</h3>
        <pre>{props.output || "No staking action yet."}</pre>
      </div>
    </div>
  );
}
