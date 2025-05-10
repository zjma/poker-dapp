import { Element, Scalar, decodeElement, decodeScalar, dummyElement, dummyScalar, elementAdd, elementSub, encodeElement, groupIdentity, scaleElement } from './group';

export type Ciphertext = {
    enc_base: Element;
    c_0: Element;
    c_1: Element;
};

export type DecKey = {
    enc_base: Element;
    private_scalar: Scalar;
};

export type EncKey = {
    enc_base: Element;
    public_point: Element;
};

export function makeEncKey(enc_base: Element, public_point: Element): EncKey {
    return { enc_base, public_point };
}

export function makeCiphertext(
    enc_base: Element,
    c_0: Element,
    c_1: Element
): Ciphertext {
    return { enc_base, c_0, c_1 };
}

export function enc(
    ek: EncKey,
    randomizer: Scalar,
    ptxt: Element
): Ciphertext {
    return {
        enc_base: ek.enc_base,
        c_0: scaleElement(ek.enc_base, randomizer),
        c_1: elementAdd(
            ptxt,
            scaleElement(ek.public_point, randomizer)
        )
    };
}

export function dec(dk: DecKey, ciph: Ciphertext): Element {
    const unblinder = scaleElement(ciph.c_0, dk.private_scalar);
    return elementSub(ciph.c_1, unblinder);
}

export function ciphertextAdd(a: Ciphertext, b: Ciphertext): Ciphertext {
    return {
        enc_base: a.enc_base,
        c_0: elementAdd(a.c_0, b.c_0),
        c_1: elementAdd(a.c_1, b.c_1)
    };
}

export function ciphertextMul(a: Ciphertext, s: Scalar): Ciphertext {
    return {
        enc_base: a.enc_base,
        c_0: scaleElement(a.c_0, s),
        c_1: scaleElement(a.c_1, s)
    };
}

export function weirdMultiExp(
    ciphs: Ciphertext[],
    scalars: Scalar[]
): Ciphertext {
    let acc = makeCiphertext(
        ciphs[0].enc_base,
        groupIdentity(),
        groupIdentity(),
    );
    for (let i = 0; i < ciphs.length; i++) {
        acc = ciphertextAdd(acc, ciphertextMul(ciphs[i], scalars[i]));
    }
    return acc;
}

export function dummyEncKey(): EncKey {
    return {enc_base: dummyElement(), public_point: dummyElement()};
}

export function dummyDecKey(): DecKey {
    return {enc_base: dummyElement(), private_scalar: dummyScalar()};
}

export function encodeEncKey(ek: EncKey): Uint8Array {
    const buf = new Uint8Array(ek.enc_base.bytes.length + ek.public_point.bytes.length);
    buf.set(ek.enc_base.bytes, 0);
    buf.set(ek.public_point.bytes, ek.enc_base.bytes.length);
    return buf;
}

export function decodeEncKey(buf: Uint8Array): {errors: number[], encKey: EncKey, remainder: Uint8Array} {
    var {errors, element: encBase, remaining} = decodeElement(buf);
    if (errors.length > 0) {
        errors.push(172708);
        return {errors, encKey: dummyEncKey(), remainder: buf};
    }
    var {errors, element: publicPoint, remaining} = decodeElement(remaining);
    if (errors.length > 0) {
        errors.push(172709);
        return {errors, encKey: dummyEncKey(), remainder: buf};
    }
    return {errors: [], encKey: {enc_base: encBase, public_point: publicPoint}, remainder: remaining};
}

export function decodeDecKey(buf: Uint8Array): {errors: number[], decKey: DecKey, remainder: Uint8Array} {
    var {errors, element: enc_base, remaining} = decodeElement(buf);
    if (errors.length > 0) {
        errors.push(240835);
        return {errors, decKey: dummyDecKey(), remainder: buf};
    }
    var {errors, scalar: private_scalar, remainder: remainder} = decodeScalar(remaining);
    if (errors.length > 0) {
        errors.push(240836);
        return {errors, decKey: dummyDecKey(), remainder: buf};
    }
    return {errors: [], decKey: {enc_base, private_scalar}, remainder};
}

export function encodeCiphertext(obj: Ciphertext): Uint8Array {
    const parts = [
      encodeElement(obj.enc_base),
      encodeElement(obj.c_0),
      encodeElement(obj.c_1),
    ];
  
    const totalLength = parts.reduce((sum, p) => sum + p.length, 0);
    const result = new Uint8Array(totalLength);
  
    let offset = 0;
    for (const part of parts) {
      result.set(part, offset);
      offset += part.length;
    }
  
    return result;
  }
  