
import { useEffect, useMemo, useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { Topbar } from "./components/Topbar";
import { Dashboard } from "./pages/Dashboard";
import { SendPage } from "./pages/Send";
import { ReceivePage } from "./pages/Receive";
import { ActivityPage } from "./pages/Activity";
import { StakePage } from "./pages/Stake";
import { SettingsPage } from "./pages/Settings";
import type { NavPage, WalletConfig } from "./types";
import {
  getBalance,
  getHistory,
  getNewAddress,
  getStakingInfo,
  getWalletInfo,
  sendToAddress,
  stake,
  delegate,
  tokenomics,
  validatorSet,
  startDaemon
} from "./api/qrx";

const defaultConfig: WalletConfig = {
  network: "alpha",
  wallet: "default",
  datadir: ""
};

export default function App() {
  const [page, setPage] = useState<NavPage>("dashboard");
  const [config, setConfig] = useState<WalletConfig>(() => {
    const raw = localStorage.getItem("qrx_wallet_config");
    if (!raw) return defaultConfig;
    try { return JSON.parse(raw); } catch { return defaultConfig; }
  });

  const [balance, setBalance] = useState("");
  const [walletInfo, setWalletInfo] = useState("");
  const [stakingInfo, setStakingInfo] = useState("");
  const [tokenomicsText, setTokenomicsText] = useState("");
  const [receiveAddress, setReceiveAddress] = useState("");
  const [historyText, setHistoryText] = useState("");
  const [sendOutput, setSendOutput] = useState("");
  const [stakeOutput, setStakeOutput] = useState("");

  async function refreshDashboard() {
    try {
      const [bal, winfo, sinfo, tok] = await Promise.all([
        getBalance(config),
        getWalletInfo(config),
        getStakingInfo(config),
        tokenomics(config)
      ]);
      setBalance(bal);
      setWalletInfo(winfo);
      setStakingInfo(sinfo);
      setTokenomicsText(tok);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setWalletInfo(msg);
    }
  }

  async function handleGenerateAddress() {
    try {
      setReceiveAddress(await getNewAddress(config));
    } catch (err) {
      setReceiveAddress(String(err));
    }
  }

  async function handleLoadHistory() {
    try {
      setHistoryText(await getHistory(config, undefined, "25"));
    } catch (err) {
      setHistoryText(String(err));
    }
  }

  async function handleSend(address: string, amount: string, memo: string) {
    try {
      setSendOutput(await sendToAddress(config, address, amount, memo));
      await refreshDashboard();
    } catch (err) {
      setSendOutput(String(err));
    }
  }

  async function handleStake(amount: string) {
    try {
      setStakeOutput(await stake(config, amount));
      await refreshDashboard();
    } catch (err) {
      setStakeOutput(String(err));
    }
  }

  async function handleDelegate(validator: string, amount: string) {
    try {
      setStakeOutput(await delegate(config, validator, amount));
      await refreshDashboard();
    } catch (err) {
      setStakeOutput(String(err));
    }
  }

  async function handleValidatorSet() {
    try {
      setStakeOutput(await validatorSet(config));
    } catch (err) {
      setStakeOutput(String(err));
    }
  }

  async function handleStartDaemon() {
    try {
      const out = await startDaemon(config);
      setWalletInfo(out + "\n\n" + walletInfo);
    } catch (err) {
      setWalletInfo(String(err));
    }
  }

  function saveSettings() {
    localStorage.setItem("qrx_wallet_config", JSON.stringify(config));
  }

  useEffect(() => {
    refreshDashboard();
  }, []);

  const pageNode = useMemo(() => {
    switch (page) {
      case "dashboard":
        return (
          <Dashboard
            balance={balance}
            walletInfo={walletInfo}
            stakingInfo={stakingInfo}
            tokenomics={tokenomicsText}
            onRefresh={refreshDashboard}
            onStartDaemon={handleStartDaemon}
          />
        );
      case "send":
        return <SendPage onSend={handleSend} output={sendOutput} />;
      case "receive":
        return <ReceivePage address={receiveAddress} onGenerate={handleGenerateAddress} />;
      case "activity":
        return <ActivityPage history={historyText} onLoad={handleLoadHistory} />;
      case "stake":
        return <StakePage onStake={handleStake} onDelegate={handleDelegate} onValidatorSet={handleValidatorSet} output={stakeOutput} />;
      case "settings":
        return <SettingsPage config={config} setConfig={setConfig} save={saveSettings} />;
      default:
        return null;
    }
  }, [page, balance, walletInfo, stakingInfo, tokenomicsText, sendOutput, receiveAddress, historyText, stakeOutput, config]);

  return (
    <div className="app-shell">
      <Sidebar page={page} setPage={setPage} />
      <main className="content">
        <Topbar config={config} />
        {pageNode}
      </main>
    </div>
  );
}
