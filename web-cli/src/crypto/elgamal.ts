import { Deserializer, Serializer } from '@aptos-labs/ts-sdk';
import { Element, Scalar } from './group';

export class Ciphertext {
    encBase: Element;
    c0: Element;
    c1: Element;

    constructor(encBase: Element, c0: Element, c1: Element) {
        this.encBase = encBase;
        this.c0 = c0;
        this.c1 = c1;
    }

    static decode(deserializer: Deserializer): Ciphertext {
        const encBase = Element.decode(deserializer);
        const c0 = Element.decode(deserializer);
        const c1 = Element.decode(deserializer);
        return new Ciphertext(encBase, c0, c1);
    }

    encode(serializer: Serializer): void {
        this.encBase.encode(serializer);
        this.c0.encode(serializer);
        this.c1.encode(serializer);
    }

    add(other: Ciphertext): Ciphertext {
        return new Ciphertext(this.encBase, this.c0.add(other.c0), this.c1.add(other.c1));
    }

    scale(scalar: Scalar): Ciphertext {
        return new Ciphertext(this.encBase, this.c0.scale(scalar), this.c1.scale(scalar));
    }
};

export class DecKey {
    encBase: Element;
    privateScalar: Scalar;

    constructor(encBase: Element, privateScalar: Scalar) {
        this.encBase = encBase;
        this.privateScalar = privateScalar;
    }

    static decode(deserializer: Deserializer): DecKey {
        const encBase = Element.decode(deserializer);
        const privateScalar = Scalar.decode(deserializer);
        return new DecKey(encBase, privateScalar);
    }

    encode(serializer: Serializer): void {
        this.encBase.encode(serializer);
        this.privateScalar.encode(serializer);
    }
};

export class EncKey {
    encBase: Element;
    publicPoint: Element;

    constructor(encBase: Element, publicPoint: Element) {
        this.encBase = encBase;
        this.publicPoint = publicPoint;
    }

    static decode(deserializer: Deserializer): EncKey {
        const encBase = Element.decode(deserializer);
        const publicPoint = Element.decode(deserializer);
        return new EncKey(encBase, publicPoint);
    }

    encode(serializer: Serializer): void {
        this.encBase.encode(serializer);
        this.publicPoint.encode(serializer);
    }
};

export function enc(
    ek: EncKey,
    randomizer: Scalar,
    ptxt: Element
): Ciphertext {
    return new Ciphertext(
        ek.encBase,
        ek.encBase.scale(randomizer),
        ptxt.add(ek.publicPoint.scale(randomizer))
    );
}

export function dec(dk: DecKey, ciph: Ciphertext): Element {
    const unblinder = ciph.c0.scale(dk.privateScalar);
    return ciph.c1.sub(unblinder);
}

export function weirdMultiExp(
    ciphs: Ciphertext[],
    scalars: Scalar[]
): Ciphertext {
    let acc = new Ciphertext(
        ciphs[0].encBase,
        Element.groupIdentity(),
        Element.groupIdentity(),
    );
    for (let i = 0; i < ciphs.length; i++) {
        acc = acc.add(ciphs[i].scale(scalars[i]));
    }
    return acc;
}
