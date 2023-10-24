import { Sigma } from "./sigma";

export class InscriptionData {
    type?: string = '';
    data?: Buffer = Buffer.alloc(0);
}

export class Origin {
    outpoint = '';
    data?: TxoData;
    num?: number;
}

export enum Bsv20Status {
    Invalid = -1,
    Pending = 0,
    Valid = 1
}

export class TxoData {
    types?: string[];
    insc?: File;
    map?: {[key: string]:any};
    b?: File;
    sigma?: Sigma[];
    list?: {
        price: number;
        payout: string;
    };
    bsv20?: {
        id?:  string;
        p: string;
        op: string;
        tick?: string;
        amt: string;
        status?: Bsv20Status 
    };
}

export interface Inscription {
    json?: any;
    text?: string;
    words?: string[];
    file: File;
}
export class Txo {
    txid: string = '';
    vout: number = 0;
    outpoint: string = '';
    satoshis: number = 0;
    accSats: number = 0;
    owner?: string;
    script?: string;
    spend?: string;
    origin?: Origin;
    height: number = 0;
    idx: number = 0;
    data?: TxoData;
}