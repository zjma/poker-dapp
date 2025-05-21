import { sha3_512 } from '@noble/hashes/sha3';
import { Element, Scalar } from './group';
import { Serializer } from '@aptos-labs/ts-sdk';

export class Transcript {
    recorded: Uint8Array;

    constructor() {
        this.recorded = new Uint8Array(0);
    }

    appendGroupElement(element: Element): void {
        const serializer = new Serializer();
        element.encode(serializer);
        this.appendRawBytes(serializer.toUint8Array());
    }
    
    appendRawBytes(raw: Uint8Array): void {
        let new_bytes = new Uint8Array(this.recorded.length + raw.length);
        new_bytes.set(this.recorded);
        new_bytes.set(raw, this.recorded.length);
        this.recorded = new_bytes;
    }

    hashToScalar(): Scalar {
        const digest = sha3_512(this.recorded);
        return Scalar.fromBigEndianBytesModQ(digest);
    }

    clone(): Transcript {
        const clone = new Transcript();
        clone.recorded = this.recorded.slice();
        return clone;
    }
};
