import { describe, it, expect } from 'vitest';
import { 
    Element, 
    Scalar, 
} from './group';
import { Deserializer, Serializer } from '@aptos-labs/ts-sdk';

describe('Group Operations', () => {
    it('should do thing 1', () => {
        const deserializer = new Deserializer(Buffer.from('20082267b53c21c9593128b9b0b511ec91423ef8dbc658eaa95f5be1418250e210', 'hex'));
        const a = Element.decode(deserializer);
        expect(deserializer.remaining()).toEqual(0);

        const deserializer2 = new Deserializer(Buffer.from('20437fd90bce77f32ad3dc57758bd1ccdf1ddc1c1229b41718833f54d476c9c600', 'hex'));
        const b = Scalar.decode(deserializer2);
        expect(deserializer2.remaining()).toEqual(0);

        const c = a.scale(b);
        const serializer = new Serializer();
        c.encode(serializer);
        const cBytes = serializer.toUint8Array();
        expect(bytesToHex(cBytes)).toEqual('20424a085adc2d55d4602fe1a7c36a90353df303544233002a97eea89f24fac727');

        const bSqr = b.mul(b);
        const serializer2 = new Serializer();
        bSqr.encode(serializer2);
        const bSqrBytes = serializer2.toUint8Array();
        expect(bytesToHex(bSqrBytes)).toEqual('209f1b909b70c1cfbd1f67555bfff89effec9a26401f8bc27d0f0c4ed8efa6a902');
    });
}); 

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
}

