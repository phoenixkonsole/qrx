
export type WalletConfig = {
  network: "alpha" | "testnet" | "regtest" | "mainnet";
  wallet: string;
  datadir?: string;
  cliPath?: string;
  daemonPath?: string;
};

export type NavPage = "dashboard" | "send" | "receive" | "activity" | "stake" | "settings";
