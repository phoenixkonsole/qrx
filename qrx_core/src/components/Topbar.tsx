
import type { WalletConfig } from "../types";

export function Topbar(props: { config: WalletConfig }) {
  return (
    <div className="topbar">
      <div className="badge">
        <span className="dot" />
        Alpha wallet • pre-genesis • use only for testing
      </div>
      <div className="badge">
        {props.config.network} • wallet: {props.config.wallet}
      </div>
    </div>
  );
}
