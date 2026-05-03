
import { invoke } from "@tauri-apps/api/core";
import type { WalletConfig } from "../types";

export async function qrxCommand(command: string, args: string[], config: WalletConfig) {
  return invoke<string>("run_qrx_cli", { command, args, config });
}

export async function startDaemon(config: WalletConfig) {
  return invoke<string>("start_qrxd", { config });
}

export async function stopDaemon(config: WalletConfig) {
  return qrxCommand("stop", [], config);
}

export async function getInfo(config: WalletConfig) {
  return qrxCommand("getinfo", [], config);
}

export async function getBlockCount(config: WalletConfig) {
  return qrxCommand("getblockcount", [], config);
}

export async function getWalletInfo(config: WalletConfig) {
  return qrxCommand("getwalletinfo", [], config);
}

export async function getStakingInfo(config: WalletConfig) {
  return qrxCommand("getstakinginfo", [], config);
}

export async function getBalance(config: WalletConfig, address?: string) {
  return qrxCommand("getbalance", address ? [address] : [], config);
}

export async function getNewAddress(config: WalletConfig) {
  return qrxCommand("getnewaddress", [], config);
}

export async function getHistory(config: WalletConfig, address?: string, limit?: string) {
  const args = [];
  if (address) args.push(address);
  if (limit) args.push(limit);
  return qrxCommand("history", args, config);
}

export async function sendToAddress(config: WalletConfig, address: string, amount: string, memo?: string) {
  const args = [address, amount];
  if (memo) args.push(memo);
  return qrxCommand("sendtoaddress", args, config);
}

export async function stake(config: WalletConfig, amount: string) {
  return qrxCommand("stake", [amount], config);
}

export async function delegate(config: WalletConfig, validator: string, amount: string) {
  return qrxCommand("delegate", [validator, amount], config);
}

export async function validatorSet(config: WalletConfig) {
  return qrxCommand("validator-set", [], config);
}

export async function tokenomics(config: WalletConfig) {
  return qrxCommand("tokenomics", [], config);
}
