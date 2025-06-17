import { Deserializer, Serializer } from '@aptos-labs/ts-sdk';
import { Transcript } from './fiat_shamir_transform';
import * as Group from './group';
import { bytesToHex } from '@noble/hashes/utils';

export class Proof {
    t0: Group.Element;
    t1: Group.Element;
    s: Group.Scalar;

    constructor(t0: Group.Element, t1: Group.Element, s: Group.Scalar) {
        this.t0 = t0;
        this.t1 = t1;
        this.s = s;
    }

    static decode(deserializer: Deserializer): Proof {
        const t0 = Group.Element.decode(deserializer);
        const t1 = Group.Element.decode(deserializer);
        const s = Group.Scalar.decode(deserializer);
        return new Proof(t0, t1, s);
    }

    encode(serializer: Serializer): void {
        this.t0.encode(serializer);
        this.t1.encode(serializer);
        this.s.encode(serializer);
    }

    toHex(): string {
        const serializer = new Serializer();
        this.encode(serializer);
        return bytesToHex(serializer.toUint8Array());
    }
}

export function prove(trx: Transcript, b0: Group.Element, p0: Group.Element, b1: Group.Element, p1: Group.Element, s: Group.Scalar): Proof {
    trx.appendGroupElement(b0);
    trx.appendGroupElement(p0);
    trx.appendGroupElement(b1);
    trx.appendGroupElement(p1);
    const r = Group.Scalar.rand();
    const t0 = b0.scale(r);
    const t1 = b1.scale(r);
    trx.appendGroupElement(t0);
    trx.appendGroupElement(t1);
    const c = trx.hashToScalar();
    const s_prime = c.mul(s).add(r);
    return new Proof(t0, t1, s_prime);
}