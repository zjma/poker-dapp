import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Element, Scalar, msm } from "./group";

export class Context {
    bases: Element[];
    constructor(bases: Element[]) {
        this.bases = bases;
    }

    static decode(deserializer: Deserializer): Context {
        const numBases = deserializer.deserializeUleb128AsU32();
        const bases = new Array<Element>(numBases);
        for (let i = 0; i < numBases; i++) {
            bases[i] = Element.decode(deserializer);
        }
        return new Context(bases);
    }

    encode(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.bases.length);
        for (let i = 0; i < this.bases.length; i++) {
            this.bases[i].encode(serializer);
        }
    }

    commit(r: Scalar, vec: Scalar[]): Element {
        const numPaddingZeros = this.bases.length - 1 - vec.length;
        const scalars = [r, ...vec, ...Array(numPaddingZeros).fill(Scalar.fromU64(BigInt(0)))];
        return msm(this.bases, scalars);
    }
}
