import { describe, it, expect } from 'vitest';
import { 
    Element, 
    Scalar, 
} from './group';
import { Deserializer, Serializer } from '@aptos-labs/ts-sdk';

describe('Group Operations', () => {
    it('should do thing 1', () => {
        const deserializer = new Deserializer(Buffer.from('3085ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a87209', 'hex'));
        const a = Element.decode(deserializer);
        expect(deserializer.remaining()).toEqual(0);

        const deserializer2 = new Deserializer(Buffer.from('20e57e6c4d3f6c645d69549f0c62aebfb77ebbcf29d2a8f0cd597d4ecd8ed56458', 'hex'));
        const b = Scalar.decode(deserializer2);
        expect(deserializer2.remaining()).toEqual(0);

        const c = a.scale(b);
        const serializer = new Serializer();
        c.encode(serializer);
        const cBytes = serializer.toUint8Array();
        expect(bytesToHex(cBytes)).toEqual('30ac39b219f3915eb90a4917931abbd5cf57709473bbc57f2169a311de51b397b882c29a1ba8fbf581ca12c388d69eecec');
    });
    it('should do thing 2', () => {
        const a = Scalar.fromBigEndianBytesModQ(Buffer.from('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'hex'));
        const serializer = new Serializer();
        a.encode(serializer);
        const aBytes = serializer.toUint8Array();
        expect(bytesToHex(aBytes)).toEqual('206c9cf2f390e999c9235c9287cbed6c2b8f3954729614d30511ff599fd9d94807');
    });
}); 

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
}

