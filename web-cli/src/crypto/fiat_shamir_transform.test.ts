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
        const trx = new Transcript();
        const element = decodeElement('3085ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a87209');
        trx.appendGroupElement(element);
        const scalar = trx.hashToScalar();
        expect(encodeScalar(scalar)).toEqual('20fe9b7b3d64c296e0e570363f091afb5be6422b9a8d3ff853b317e7662c2a3b61');
    });
});
