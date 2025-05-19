import { Element, Scalar } from './group';
import { Deserializer, Serializer } from '@aptos-labs/ts-sdk';

export class Proof {
    t: Element;
    s: Scalar;

    constructor(t: Element, s: Scalar) {
        this.t = t;
        this.s = s;
    }

    static decode(deserializer: Deserializer): Proof {
        const t = Element.decode(deserializer);
        const s = Scalar.decode(deserializer);
        return new Proof(t, s);
    }

    encode(serializer: Serializer): void {
        this.t.encode(serializer);
        this.s.encode(serializer);
    }
};
