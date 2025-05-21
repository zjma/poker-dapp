import { describe, it, expect } from 'vitest';
import { Transcript } from './fiat_shamir_transform';
import { Element, Scalar } from './group';
import { Deserializer, Serializer } from '@aptos-labs/ts-sdk';

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
}

function decodeElement(hex: string): Element {
    const bytes = hexToBytes(hex);
    const deserializer = new Deserializer(bytes);
    const ret = Element.decode(deserializer);
    expect(deserializer.remaining()).toEqual(0);
    return ret;
}

function encodeScalar(scalar: Scalar): string {
    const serializer = new Serializer();
    scalar.encode(serializer);
    return Buffer.from(serializer.toUint8Array()).toString('hex');
}

describe('Fiat Shamir Transform', () => {
    it('should do thing 1', () => {
    });
});
