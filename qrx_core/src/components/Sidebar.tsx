
import type { NavPage } from "../types";

const items: { key: NavPage; label: string }[] = [
  { key: "dashboard", label: "Dashboard" },
  { key: "send", label: "Send" },
  { key: "receive", label: "Receive" },
  { key: "activity", label: "Activity" },
  { key: "stake", label: "Stake" },
  { key: "settings", label: "Settings" }
];

export function Sidebar(props: { page: NavPage; setPage: (page: NavPage) => void }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">QRX</div>
        <div className="brand-text">
          <h1>QRX Wallet</h1>
          <p>Desktop Alpha Wallet</p>
        </div>
      </div>
      <nav className="nav">
        {items.map((item) => (
          <button
            key={item.key}
            className={props.page === item.key ? "active" : ""}
            onClick={() => props.setPage(item.key)}
          >
            {item.label}
          </button>
        ))}
      </nav>
    </aside>
  );
}
