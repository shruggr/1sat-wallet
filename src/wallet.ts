import {
  Address,
  Bip32,
  Bip39,
  Bn,
  Bsm,
  Hash,
  KeyPair,
  OpCode,
  PrivKey,
  Script,
  Sig,
  Tx,
  TxIn,
  TxOut,
} from "@ts-bitcoin/core";
import { Buffer } from "buffer";
import { EventEmitter } from "events";
import { PreviousOutput } from "bitcoin-ef/dist/typescript-npm-package.esm";
import {
  IBsv20SendCtx,
  IFile,
  IUtxo,
  IWalletProps,
  TxResponse,
} from "./interfaces";
import "cross-fetch/polyfill";
import { Txo } from "./models/txo";

const SATS_PER_KB = 1;
const INPUT_SIZE = 147;
const OUTPUT_SIZE = 34;
const SIG_SIZE = 71;
const DUST = 10;
const SPLIT_SATS = 100000;
const MAX_SPLITS = 3;
const OUTPUT_FEE = Math.ceil((OUTPUT_SIZE * SATS_PER_KB) / 1000);
const oLockPrefix = Buffer.from(
  "2097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c0000",
  "hex"
);
const oLockSuffix = Buffer.from(
  "615179547a75537a537a537a0079537a75527a527a7575615579008763567901c161517957795779210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce081059795679615679aa0079610079517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e81517a75615779567956795679567961537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00517951796151795179970079009f63007952799367007968517a75517a75517a7561527a75517a517951795296a0630079527994527a75517a6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f7754537993527993013051797e527e54797e58797e527e53797e52797e57797e0079517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a756100795779ac517a75517a75517a75517a75517a75517a75517a75517a75517a7561517a75517a756169587951797e58797eaa577961007982775179517958947f7551790128947f77517a75517a75618777777777777777777767557951876351795779a9876957795779ac777777777777777767006868",
  "hex"
);

const API = "https://v3.ordinals.gorillapool.io";

export class OneSatWallet extends EventEmitter {
  private seedWords?: string;
  private payKp: KeyPair;
  private ordKp: KeyPair;
  private payAdd: Address;
  private ordAdd: Address;
  private _utxos = new Map<string, Map<string, IUtxo>>();

  public payAddress: string;
  public ordAddress: string;
  public lock: string;

  constructor(props: IWalletProps) {
    super();
    if (!props.seedWords) {
      if (!props.payPk || !props.ordPk)
        throw new Error("Must provide seed or payPk and ordPk");
      this.payKp = KeyPair.fromPrivKey(PrivKey.fromWif(props.payPk));
      this.ordKp = KeyPair.fromPrivKey(PrivKey.fromWif(props.ordPk));
    } else {
      this.seedWords = props.seedWords;
      const bip39 = Bip39.fromString(props.seedWords);
      const bip32 = Bip32.fromSeed(bip39.toSeed());
      this.payKp = KeyPair.fromPrivKey(bip32.derive("m/0/0").privKey);
      this.ordKp = KeyPair.fromPrivKey(bip32.privKey);
    }
    this.payAdd = Address.fromPubKey(this.payKp.pubKey!);
    this.ordAdd = Address.fromPubKey(this.ordKp.pubKey!);
    this.payAddress = this.payAdd.toString();
    this.ordAddress = this.ordAdd.toString();
    this.lock = Hash.sha256(this.ordAdd.toTxOutScript().toBuffer())
      .reverse()
      .toString("hex");
  }

  backup(): IWalletProps {
    return {
      seedWords: this.seedWords,
      payPk: this.payKp.privKey.toWif(),
      ordPk: this.ordKp.privKey.toWif(),
    };
  }

  static addressToLock(address: Address): string {
    return Hash.sha256(address.toTxOutScript().toBuffer())
      .reverse()
      .toString("hex");
  }

  async balance(): Promise<number> {
    const url = `https://api.whatsonchain.com/v1/bsv/main/address/${this.payAddress}/balance`;
    const resp = await fetch(url);
    const data = await resp.json();
    return parseInt(data.confirmed, 10) + parseInt(data.unconfirmed, 10);
  }

  async refresh(address: string): Promise<void> {
    this._utxos.delete(address);
  }

  async utxos(address: string): Promise<IUtxo[]> {
    const script = Address.fromString(address).toTxOutScript().toHex();
    let utxos = this._utxos.get(script);
    if (!utxos) {
      const resp = await fetch(
        `https://api.whatsonchain.com/v1/bsv/main/address/${address}/unspent`
      );
      const data = await resp.json();
      utxos = new Map<string, IUtxo>();
      data.forEach((utxo: any) => {
        utxos!.set(`${utxo.tx_hash}:${utxo.tx_pos}`, {
          txid: utxo.tx_hash,
          vout: utxo.tx_pos,
          satoshis: utxo.value,
          script,
        });
      });
      this._utxos.set(script, utxos);
    }
    return [...utxos.values()];
  }

  async bsv20Utxos(tick: string): Promise<Txo[]> {
    const r = await fetch(
      `${API}/api/bsv20/${this.ordAdd.toString()}/tick/${encodeURIComponent(
        tick
      )}`
    );
    return r.json();
  }

  async broadcast(tx: Tx, parents: PreviousOutput[]): Promise<TxResponse> {
    const resp = await fetch(`${API}/api/tx`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        rawtx: tx.toBuffer().toString("base64"),
        parents: parents.map((p) => ({
          lockingScript: p.lockingScript.toString("base64"),
          satoshis: p.satoshis,
        })),
      }),
    });
    if (!resp.ok) {
      console.error("Broadcast error:", resp.status, resp.statusText, await resp.text());
      throw new Error(`${resp.status} ${resp.statusText}`);
    }

    const txid = tx.id();
    tx.txIns.forEach((txIn, vin) => {
      const utxos = this._utxos.get(parents[vin].lockingScript.toString("hex"));
      if (utxos) {
        utxos.delete(
          `${txIn.txHashBuf.reverse().toString("hex")}:${txIn.txOutNum}`
        );
      }
    });
    tx.txOuts.forEach((txOut, vout) => {
      const scriptHex = txOut.script.toHex();
      if (scriptHex.length > 50) return;

      let utxos = this._utxos.get(scriptHex);
      if (!utxos) {
        utxos = new Map<string, IUtxo>();
        this._utxos.set(scriptHex, utxos);
      }
      utxos.set(`${txid}:${vout}`, {
        txid,
        vout,
        satoshis: txOut.valueBn.toNumber(),
        script: this.payAdd.toTxOutScript().toHex(),
      });
    });

    return { txid, rawtx: tx.toHex() };
  }

  async sendPayment(toAddress: string, sats: number): Promise<string> {
    const tx = new Tx();
    tx.addTxOut(new Bn(sats), Address.fromString(toAddress).toTxOutScript());
    return (await this.fundAndBroadcast(tx, [])).txid;
  }

  buildSigma(tx: Tx, script: Script, vin = 0): Script {
    const outpoint = Buffer.alloc(36);
    if (tx.txIns[vin]) {
      Buffer.from(tx.txIns[vin].txHashBuf).reverse().copy(outpoint, 0);
      outpoint.writeUInt32LE(tx.txIns[vin].txOutNum, 32);
    }
    const inputHash = Hash.sha256(outpoint);
    const outputHash = Hash.sha256(script.toBuffer());
    const messageHash = Hash.sha256(Buffer.concat([inputHash, outputHash]));
    const sig = Bsm.sign(messageHash, this.ordKp);

    const signedScript = Script.fromBuffer(script.toBuffer());
    if (script.chunks.find((c) => c.opCodeNum === OpCode.OP_RETURN)) {
      signedScript.writeBuffer(Buffer.from("|"));
    } else {
      signedScript.writeOpCode(OpCode.OP_RETURN);
    }
    signedScript
      .writeBuffer(Buffer.from("SIGMA"))
      .writeBuffer(Buffer.from("BSM"))
      .writeBuffer(Buffer.from(this.ordAdd.toString()))
      .writeBuffer(Buffer.from(sig, "base64"))
      .writeBuffer(Buffer.from(vin.toString()));

    return signedScript;
  }

  async fundTx(
    tx: Tx,
    parents: PreviousOutput[],
    utxos?: IUtxo[]
  ): Promise<void> {
    if (!utxos) utxos = await this.utxos(this.payAdd.toString());
    let size = tx.toBuffer().length;
    let fee = Math.ceil((size * SATS_PER_KB) / 1000);
    let satsIn = parents.reduce((sum, utxo) => sum + utxo.satoshis, 0);
    let satsOut = tx.txOuts.reduce(
      (sum, txOut) => sum + txOut.valueBn.toNumber(),
      0
    );
    const inCount = parents.length;

    for (const utxo of utxos) {
      if (satsIn >= satsOut + fee) break;
      tx.addTxIn(
        Buffer.from(utxo.txid, "hex").reverse(),
        utxo.vout,
        new Script(),
        TxIn.SEQUENCE_FINAL
      );
      parents.push({
        lockingScript: this.payAdd.toTxOutScript().toBuffer(),
        satoshis: utxo.satoshis,
      });
      satsIn += utxo.satoshis;
      size += INPUT_SIZE;
      fee = Math.ceil((size * SATS_PER_KB) / 1000);
    }
    if (satsIn < satsOut + fee) throw new Error("Insufficient funds");

    let change = satsIn - satsOut - fee;
    while (change > DUST) {
      if (change > SPLIT_SATS + OUTPUT_FEE && tx.txOuts.length < MAX_SPLITS) {
        tx.addTxOut(new Bn(SPLIT_SATS), this.payAdd.toTxOutScript());
        satsOut += SPLIT_SATS;
        size += OUTPUT_SIZE;
        fee = Math.ceil((size * SATS_PER_KB) / 1000);
        change = satsIn - satsOut - fee - OUTPUT_FEE;
      } else {
        size += OUTPUT_SIZE;
        fee = Math.ceil((size * SATS_PER_KB) / 1000) + OUTPUT_FEE;
        tx.addTxOut(
          new Bn(satsIn - satsOut - fee),
          this.payAdd.toTxOutScript()
        );
        satsOut += change;
        change = 0;
      }
    }

    for (let vin = inCount; vin < parents.length; vin++) {
      const { satoshis } = parents[vin];
      const sig = tx.sign(
        this.payKp,
        Sig.SIGHASH_ALL | Sig.SIGHASH_FORKID,
        vin,
        this.payAdd.toTxOutScript(),
        new Bn(satoshis)
      );
      tx.txIns[vin].setScript(
        new Script()
          .writeBuffer(sig.toTxFormat())
          .writeBuffer(this.payKp.pubKey.toBuffer())
      );
    }
  }

  async fundAndBroadcast(
    tx: Tx,
    parents: PreviousOutput[],
    utxos?: IUtxo[]
  ): Promise<TxResponse> {
    await this.fundTx(tx, parents, utxos);
    return this.broadcast(tx, parents);
  }

  async loadOrdinal(outpoint: string): Promise<Txo> {
    const url = `${API}/api/inscriptions/${outpoint}?script=true`;
    console.log("loadOrdinal", url);
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`);
    const data = await resp.json();
    console.log("loadOrdinal", data);
    return data;
  }

  buildOrdinalScript(file: IFile, map?: { [key: string]: string }, lock?: Script): Script {
    lock = lock ? lock.clone() : this.ordAdd.toTxOutScript();
    
    const outScript = lock
      .writeOpCode(OpCode.OP_FALSE)
      .writeOpCode(OpCode.OP_IF)
      .writeBuffer(Buffer.from("ord"))
      .writeOpCode(OpCode.OP_1)
      .writeBuffer(Buffer.from(file.contentType))
      .writeOpCode(OpCode.OP_0)
      .writeBuffer(Buffer.from(file.content))
      .writeOpCode(OpCode.OP_ENDIF);

    if (map) {
      outScript
        .writeOpCode(OpCode.OP_RETURN)
        .writeBuffer(Buffer.from("1PuQa7K62MiKCtssSLKy1kh56WWU7MtUR5"))
        .writeBuffer(Buffer.from("SET"));

      Object.entries(map).forEach(([key, value]) => {
        outScript
          .writeBuffer(Buffer.from(key))
          .writeBuffer(Buffer.from(value));
      });
    }
    return outScript
  }

  async inscribeOrdinal(
    file: IFile,
    map: { [key: string]: string }
  ): Promise<string> {
    const utxos = await this.utxos(this.payAdd.toString());
    const mintTx = new Tx();
    const parents: PreviousOutput[] = [];

    const utxo = utxos.shift();
    if (!utxo) throw new Error("Insufficient funds");
    mintTx.addTxIn(
      Buffer.from(utxo.txid, "hex").reverse(),
      utxo.vout,
      new Script(),
      TxIn.SEQUENCE_FINAL
    );
    parents.push({
      lockingScript: this.payAdd.toTxOutScript().toBuffer(),
      satoshis: utxo.satoshis,
    });

    const unsignedScript = this.buildOrdinalScript(file, map);

    let signedScript = this.buildSigma(mintTx, unsignedScript, 0);
    mintTx.addTxOut(new Bn(1), signedScript);

    const sig = mintTx.sign(
      this.payKp,
      Sig.SIGHASH_SINGLE | Sig.SIGHASH_ANYONECANPAY | Sig.SIGHASH_FORKID,
      0,
      this.payAdd.toTxOutScript(),
      new Bn(utxo.satoshis)
    );

    mintTx.txIns[0].setScript(
      new Script()
        .writeBuffer(sig.toTxFormat())
        .writeBuffer(this.payKp.pubKey.toBuffer())
    );

    return (await this.fundAndBroadcast(mintTx, parents, utxos)).txid;
  }

  async sendOrdinal(outpoint: string, toAddress: string): Promise<string> {
    const ordinal = await this.loadOrdinal(outpoint);
    const sendTx = new Tx();
    sendTx.addTxIn(
      Buffer.from(ordinal.txid, "hex").reverse(),
      ordinal.vout,
      new Script(),
      TxIn.SEQUENCE_FINAL
    );
    sendTx.addTxOut(new Bn(1), Address.fromString(toAddress).toTxOutScript());
    const parents: PreviousOutput[] = [
      {
        lockingScript: Buffer.from(ordinal.script!, "base64"),
        satoshis: 1,
      },
    ];

    const sig = sendTx.sign(
      this.ordKp,
      Sig.SIGHASH_SINGLE | Sig.SIGHASH_ANYONECANPAY | Sig.SIGHASH_FORKID,
      0,
      Script.fromBuffer(Buffer.from(ordinal.script!, "base64")),
      new Bn(1)
    );
    sendTx.txIns[0].setScript(
      new Script()
        .writeBuffer(sig.toTxFormat())
        .writeBuffer(this.ordKp.pubKey.toBuffer())
    );

    return (await this.fundAndBroadcast(sendTx, parents)).txid;
  }

  async listOrdinal(outpoint: string, price: number): Promise<string> {
    const ordinal = await this.loadOrdinal(outpoint);
    const listTx = new Tx();
    const script = Script.fromBuffer(Buffer.from(ordinal.script!, "base64"));
    listTx.addTxIn(
      Buffer.from(ordinal.txid, "hex").reverse(),
      ordinal.vout,
      new Script(),
      TxIn.SEQUENCE_FINAL
    );
    const parents: PreviousOutput[] = [
      {
        lockingScript: script.toBuffer(),
        satoshis: 1,
      },
    ];

    const payOut = TxOut.fromProperties(
      new Bn(price),
      this.payAdd.toTxOutScript()
    );

    listTx.addTxOut(
      new Bn(1),
      new Script()
        .writeScript(Script.fromBuffer(oLockPrefix))
        .writeBuffer(this.ordAdd.hashBuf)
        .writeBuffer(payOut.toBuffer())
        .writeScript(Script.fromBuffer(oLockSuffix))
    );

    const sig = listTx.sign(
      this.ordKp,
      Sig.SIGHASH_SINGLE | Sig.SIGHASH_ANYONECANPAY | Sig.SIGHASH_FORKID,
      0,
      script,
      new Bn(1)
    );
    listTx.txIns[0].setScript(
      new Script()
        .writeBuffer(sig.toTxFormat())
        .writeBuffer(this.ordKp.pubKey.toBuffer())
    );

    return (await this.fundAndBroadcast(listTx, parents)).txid;
  }

  async delistOrdinal(outpoint: string): Promise<string> {
    const ordinal = await this.loadOrdinal(outpoint);

    const delistTx = new Tx();
    delistTx.addTxIn(
      Buffer.from(ordinal.txid, "hex").reverse(),
      ordinal.vout,
      new Script(),
      TxIn.SEQUENCE_FINAL
    );
    const script = Script.fromBuffer(Buffer.from(ordinal.script!, "base64"));
    const parents: PreviousOutput[] = [
      {
        lockingScript: script.toBuffer(),
        satoshis: 1,
      },
    ];
    delistTx.addTxOut(new Bn(1), this.ordAdd.toTxOutScript());

    const sig = delistTx.sign(
      this.ordKp,
      Sig.SIGHASH_SINGLE | Sig.SIGHASH_ANYONECANPAY | Sig.SIGHASH_FORKID,
      0,
      script,
      new Bn(1)
    );

    delistTx.txIns[0].setScript(
      new Script()
        .writeBuffer(sig.toTxFormat())
        .writeBuffer(this.ordKp.pubKey.toBuffer())
        .writeOpCode(OpCode.OP_1)
    );

    return (await this.fundAndBroadcast(delistTx, parents)).txid;
  }

  async purchaseListing(outpoint: string): Promise<string> {
    const ordinal = await this.loadOrdinal(outpoint);
    const lockScript = Script.fromBuffer(
      Buffer.from(ordinal.script!, "base64")
    );
    const payOut = TxOut.fromBuffer(Buffer.from(ordinal.data!.list!.payout, "base64"));

    const purchaseTx = new Tx();
    purchaseTx.addTxIn(
      Buffer.from(ordinal.txid, "hex").reverse(),
      ordinal.vout,
      new Script(),
      TxIn.SEQUENCE_FINAL
    );

    const parents: PreviousOutput[] = [
      {
        lockingScript: lockScript.toBuffer(),
        satoshis: 1,
      },
    ];

    purchaseTx.addTxOut(new Bn(1), this.ordAdd.toTxOutScript());

    purchaseTx.addTxOut(payOut);

    const preimage = purchaseTx.sighashPreimage(
      Sig.SIGHASH_ALL | Sig.SIGHASH_ANYONECANPAY | Sig.SIGHASH_FORKID,
      0,
      lockScript,
      new Bn(1),
      Tx.SCRIPT_ENABLE_SIGHASH_FORKID
    );
    const script = new Script().writeBuffer(purchaseTx.txOuts[0].toBuffer());

    if (purchaseTx.txOuts[2]) {
      script.writeBuffer(purchaseTx.txOuts[2].toBuffer());
    } else {
      script.writeOpCode(OpCode.OP_0);
    }
    script.writeBuffer(preimage).writeOpCode(OpCode.OP_0);

    purchaseTx.txIns[0].setScript(script);

    const size = purchaseTx.toBuffer().length + INPUT_SIZE;
    const satsOut = purchaseTx.txOuts.reduce(
      (acc, toOut) => acc + toOut.valueBn.toNumber(),
      0
    );
    const sats = satsOut + Math.ceil((size / 1000) * SATS_PER_KB) + 10;

    console.log("preFunding", purchaseTx.toHex());
    const fundTxid = await this.sendPayment(this.payAdd.toString(), sats);

    purchaseTx.addTxIn(
      Buffer.from(fundTxid, "hex").reverse(),
      0,
      new Script(),
      TxIn.SEQUENCE_FINAL
    );
    parents.push({
      lockingScript: this.payAdd.toTxOutScript().toBuffer(),
      satoshis: sats,
    });

    const sig = purchaseTx.sign(
      this.payKp,
      Sig.SIGHASH_ALL | Sig.SIGHASH_FORKID,
      1,
      this.payAdd.toTxOutScript(),
      new Bn(sats)
    );

    purchaseTx.txIns[1].setScript(
      new Script()
        .writeBuffer(sig.toTxFormat())
        .writeBuffer(this.payKp.pubKey.toBuffer())
    );

    return (await this.broadcast(purchaseTx, parents)).txid;
  }

  async buildBsv20SendCtx(
    ticker: string,
    amount: number
  ): Promise<IBsv20SendCtx> {
    const ctx: IBsv20SendCtx = {
      tx: new Tx(),
      parents: [],
      balance: BigInt(0),
    };

    const tokens: Txo[] = [];
    const bsv20Utxos = await this.bsv20Utxos(ticker);

    for (const bsv20 of bsv20Utxos) {
      if (bsv20.data?.list) continue;
      tokens.push(bsv20);
      ctx.balance += BigInt(bsv20.data!.bsv20!.amt);
      if (ctx.balance >= amount) break;
    }
    if (ctx.balance < amount) throw new Error("Insufficient balance");

    const url = `${API}/api/txos/outpoints?script=true`;
    const body = JSON.stringify(tokens.map((t) => `${t.txid}_${t.vout}`));
    // console.log('Request:', url, body);
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`);
    const utxos: Txo[] = await resp.json();
    utxos.forEach((u) => {
      ctx.tx.addTxIn(
        Buffer.from(u.txid, "hex").reverse(),
        u.vout,
        new Script()
          .writeBuffer(Buffer.alloc(SIG_SIZE))
          .writeBuffer(this.ordKp.pubKey.toBuffer()),
        TxIn.SEQUENCE_FINAL
      );
      ctx.parents.push({
        lockingScript: Buffer.from(u.script!, "base64"),
        satoshis: u.satoshis,
      });
    });
    return ctx;
  }

  async listBsv20(
    tick: string,
    amount: number,
    price: number
  ): Promise<string> {
    const {
      tx: listTx,
      balance,
      parents,
    } = await this.buildBsv20SendCtx(tick, amount);
    const tokensCount = parents.length;

    const payOut = TxOut.fromProperties(
      new Bn(price),
      this.payAdd.toTxOutScript()
    );
    listTx.addTxOut(
      new Bn(1),
      new Script()
        .writeScript(Script.fromBuffer(oLockPrefix))
        .writeBuffer(this.ordAdd.hashBuf)
        .writeBuffer(payOut.toBuffer())
        .writeScript(Script.fromBuffer(oLockSuffix))
        .writeOpCode(OpCode.OP_FALSE)
        .writeOpCode(OpCode.OP_IF)
        .writeBuffer(Buffer.from("ord"))
        .writeOpCode(OpCode.OP_1)
        .writeBuffer(Buffer.from("application/bsv-20"))
        .writeOpCode(OpCode.OP_0)
        .writeBuffer(
          Buffer.from(
            JSON.stringify({
              p: "bsv-20",
              op: "transfer",
              tick,
              amt: amount.toString(),
            })
          )
        )
        .writeOpCode(OpCode.OP_ENDIF)
    );

    const change = balance - BigInt(amount);
    if (change > 0) {
      listTx.addTxOut(
        new Bn(1),
        this.ordAdd
          .toTxOutScript()
          .writeOpCode(OpCode.OP_FALSE)
          .writeOpCode(OpCode.OP_IF)
          .writeBuffer(Buffer.from("ord"))
          .writeOpCode(OpCode.OP_1)
          .writeBuffer(Buffer.from("application/bsv-20"))
          .writeOpCode(OpCode.OP_0)
          .writeBuffer(
            Buffer.from(
              JSON.stringify({
                p: "bsv-20",
                op: "transfer",
                tick,
                amt: change.toString(),
              })
            )
          )
          .writeOpCode(OpCode.OP_ENDIF)
      );
    }

    await this.fundTx(listTx, parents);
    parents.slice(0, tokensCount).forEach((p, i) => {
      const sig = listTx.sign(
        this.ordKp,
        Sig.SIGHASH_ALL | Sig.SIGHASH_ANYONECANPAY | Sig.SIGHASH_FORKID,
        i,
        Script.fromBuffer(p.lockingScript as Buffer),
        new Bn(p.satoshis)
      );
      listTx.txIns[i].setScript(
        new Script()
          .writeBuffer(sig.toTxFormat())
          .writeBuffer(this.ordKp.pubKey.toBuffer())
      );
    });
    return (await this.broadcast(listTx, parents)).txid;
  }

  async sendBsv20(tick: string, amount: number, to: string): Promise<string> {
    const {
      tx: sendTx,
      balance,
      parents,
    } = await this.buildBsv20SendCtx(tick, amount);
    const tokensCount = parents.length;
    sendTx.addTxOut(
      new Bn(1),
      Address.fromString(to)
        .toTxOutScript()
        .writeOpCode(OpCode.OP_FALSE)
        .writeOpCode(OpCode.OP_IF)
        .writeBuffer(Buffer.from("ord"))
        .writeOpCode(OpCode.OP_1)
        .writeBuffer(Buffer.from("application/bsv-20"))
        .writeOpCode(OpCode.OP_0)
        .writeBuffer(
          Buffer.from(
            JSON.stringify({
              p: "bsv-20",
              op: "transfer",
              tick,
              amt: amount.toString(),
            })
          )
        )
        .writeOpCode(OpCode.OP_ENDIF)
    );

    const change = balance - BigInt(amount);
    if (change > 0) {
      sendTx.addTxOut(
        new Bn(1),
        this.ordAdd
          .toTxOutScript()
          .writeOpCode(OpCode.OP_FALSE)
          .writeOpCode(OpCode.OP_IF)
          .writeBuffer(Buffer.from("ord"))
          .writeOpCode(OpCode.OP_1)
          .writeBuffer(Buffer.from("application/bsv-20"))
          .writeOpCode(OpCode.OP_0)
          .writeBuffer(
            Buffer.from(
              JSON.stringify({
                p: "bsv-20",
                op: "transfer",
                tick,
                amt: change.toString(),
              })
            )
          )
          .writeOpCode(OpCode.OP_ENDIF)
      );
    }

    await this.fundTx(sendTx, parents);
    parents.slice(0, tokensCount).forEach((p, i) => {
      const sig = sendTx.sign(
        this.ordKp,
        Sig.SIGHASH_ALL | Sig.SIGHASH_ANYONECANPAY | Sig.SIGHASH_FORKID,
        i,
        Script.fromBuffer(p.lockingScript as Buffer),
        new Bn(p.satoshis)
      );
      sendTx.txIns[i].setScript(
        new Script()
          .writeBuffer(sig.toTxFormat())
          .writeBuffer(this.ordKp.pubKey.toBuffer())
      );
    });
    return (await this.broadcast(sendTx, parents)).txid;
  }

  async delistBsv20(outpoint: string): Promise<string> {
    const ordinal = await this.loadOrdinal(outpoint);
    const bsv20 = await this.loadOrdinal(outpoint);

    const delistTx = new Tx();
    delistTx.addTxIn(
      Buffer.from(ordinal.txid, "hex").reverse(),
      ordinal.vout,
      new Script(),
      TxIn.SEQUENCE_FINAL
    );
    const script = Script.fromBuffer(Buffer.from(ordinal.script!, "base64"));
    const parents: PreviousOutput[] = [
      {
        lockingScript: script.toBuffer(),
        satoshis: 1,
      },
    ];
    delistTx.addTxOut(
      new Bn(1),
      this.ordAdd
        .toTxOutScript()
        .writeOpCode(OpCode.OP_FALSE)
        .writeOpCode(OpCode.OP_IF)
        .writeBuffer(Buffer.from("ord"))
        .writeOpCode(OpCode.OP_1)
        .writeBuffer(Buffer.from("application/bsv-20"))
        .writeOpCode(OpCode.OP_0)
        .writeBuffer(
          Buffer.from(
            JSON.stringify({
              p: "bsv-20",
              op: "transfer",
              tick: bsv20.data!.bsv20!.tick,
              amt: bsv20.data!.bsv20!.toString(),
            })
          )
        )
        .writeOpCode(OpCode.OP_ENDIF)
    );

    const sig = delistTx.sign(
      this.ordKp,
      Sig.SIGHASH_SINGLE | Sig.SIGHASH_ANYONECANPAY | Sig.SIGHASH_FORKID,
      0,
      script,
      new Bn(1)
    );

    delistTx.txIns[0].setScript(
      new Script()
        .writeBuffer(sig.toTxFormat())
        .writeBuffer(this.ordKp.pubKey.toBuffer())
        .writeOpCode(OpCode.OP_1)
    );

    return (await this.fundAndBroadcast(delistTx, parents)).txid;
  }

  async purchaseBsv20(outpoint: string): Promise<string> {
    const ordinal = await this.loadOrdinal(outpoint);
    const bsv20 = await this.loadOrdinal(outpoint);
    const lockScript = Script.fromBuffer(
      Buffer.from(ordinal.script!, "base64")
    );
    const payOut = TxOut.fromBuffer(Buffer.from(ordinal.data!.list!.payout, "base64"));

    const purchaseTx = new Tx();
    purchaseTx.addTxIn(
      Buffer.from(ordinal.txid, "hex").reverse(),
      ordinal.vout,
      new Script(),
      TxIn.SEQUENCE_FINAL
    );

    const parents: PreviousOutput[] = [
      {
        lockingScript: lockScript.toBuffer(),
        satoshis: 1,
      },
    ];

    purchaseTx.addTxOut(
      new Bn(1),
      this.ordAdd
        .toTxOutScript()
        .writeOpCode(OpCode.OP_FALSE)
        .writeOpCode(OpCode.OP_IF)
        .writeBuffer(Buffer.from("ord"))
        .writeOpCode(OpCode.OP_1)
        .writeBuffer(Buffer.from("application/bsv-20"))
        .writeOpCode(OpCode.OP_0)
        .writeBuffer(
          Buffer.from(
            JSON.stringify({
              p: "bsv-20",
              op: "transfer",
              tick: bsv20.data!.bsv20!.tick,
              amt: bsv20.data!.bsv20!.amt.toString(),
            })
          )
        )
        .writeOpCode(OpCode.OP_ENDIF)
    );

    purchaseTx.addTxOut(payOut);

    const preimage = purchaseTx.sighashPreimage(
      Sig.SIGHASH_ALL | Sig.SIGHASH_ANYONECANPAY | Sig.SIGHASH_FORKID,
      0,
      lockScript,
      new Bn(1),
      Tx.SCRIPT_ENABLE_SIGHASH_FORKID
    );
    const script = new Script().writeBuffer(purchaseTx.txOuts[0].toBuffer());

    if (purchaseTx.txOuts[2]) {
      script.writeBuffer(purchaseTx.txOuts[2].toBuffer());
    } else {
      script.writeOpCode(OpCode.OP_0);
    }
    script.writeBuffer(preimage).writeOpCode(OpCode.OP_0);

    purchaseTx.txIns[0].setScript(script);

    const size = purchaseTx.toBuffer().length + INPUT_SIZE;
    const satsOut = purchaseTx.txOuts.reduce(
      (acc, toOut) => acc + toOut.valueBn.toNumber(),
      0
    );
    const sats = satsOut + Math.ceil((size / 1000) * SATS_PER_KB) + 10;

    console.log("preFunding", purchaseTx.toHex());
    const fundTxid = await this.sendPayment(this.payAdd.toString(), sats);

    purchaseTx.addTxIn(
      Buffer.from(fundTxid, "hex").reverse(),
      0,
      new Script(),
      TxIn.SEQUENCE_FINAL
    );
    parents.push({
      lockingScript: this.payAdd.toTxOutScript().toBuffer(),
      satoshis: sats,
    });

    const sig = purchaseTx.sign(
      this.payKp,
      Sig.SIGHASH_ALL | Sig.SIGHASH_FORKID,
      1,
      this.payAdd.toTxOutScript(),
      new Bn(sats)
    );

    purchaseTx.txIns[1].setScript(
      new Script()
        .writeBuffer(sig.toTxFormat())
        .writeBuffer(this.payKp.pubKey.toBuffer())
    );

    return (await this.broadcast(purchaseTx, parents)).txid;
  }
}
