import { Tx } from "@ts-bitcoin/core";
import { PreviousOutput } from "bitcoin-ef/dist/typescript-npm-package.esm";

export interface IWalletProps {
  seedWords?: string;
  payPk?: string;
  ordPk?: string;
}

export interface IUtxo {
  txid: string;
  vout: number;
  satoshis: number;
  script: string;
}

export interface IFile {
  name?: string;
  content: ArrayBuffer;
  contentType: string;
}

export interface IBsv20SendCtx {
  tx: Tx;
  parents: PreviousOutput[];
  balance: bigint;
  // utxos: IUtxo[];
  // tokens: IBsv20[];
}

export interface IFeeConfig {
  address: string;
  purchase: number;
  mintAddress: string;
  inscription: number;
  mine: number;
  mineAddress: string;
}

export interface OpNSData {
  outpoint: string;
  txid: string;
  vout: number;
  genesis: string;
  domain: string;
  rawtx: string;
  created: string;
}

export interface TxResponse {
  txid: string;
  rawtx: string;
}
