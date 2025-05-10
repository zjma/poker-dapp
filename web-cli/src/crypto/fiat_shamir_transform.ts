import { sha3_512 } from '@noble/hashes/sha3';
import { Element, Scalar, scalarFromBigEndianBytesModQ } from './group';
import { bytesToHex } from '@noble/hashes/utils';

export type Transcript = {
    recorded: Uint8Array;
};

export function newTranscript(): Transcript {
    return { recorded: new Uint8Array(0) };
}

export function appendGroupElement(trx: Transcript, element: Element): void {
    appendRawBytes(trx, element.bytes);
}

export function appendRawBytes(trx: Transcript, raw: Uint8Array): void {
    let new_bytes = new Uint8Array(trx.recorded.length + raw.length);
    new_bytes.set(trx.recorded);
    new_bytes.set(raw, trx.recorded.length);
    trx.recorded = new_bytes;
}

export function hashToScalar(trx: Transcript): Scalar {
    const digest = sha3_512(trx.recorded);
    console.log(bytesToHex(digest));
    const modq = scalarFromBigEndianBytesModQ(digest);
    console.log(bytesToHex(modq.bytes));
    return modq;
}
