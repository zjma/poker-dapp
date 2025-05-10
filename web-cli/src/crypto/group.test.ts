import { describe, it, expect } from 'vitest';
import { 
    Element, 
    Scalar, 
    randElement, 
    randScalar, 
    groupIdentity, 
    elementAdd, 
    elementSub, 
    scaleElement, 
    scalarFromU64, 
    scalarAdd, 
    scalarMul, 
    scalarNeg, 
    msm, 
    decodeElement,
    decodeScalar,
    encodeElement,
    scalarFromBigEndianBytesModQ,
    encodeScalar
} from './group';
import { hexToBytes } from '@noble/hashes/utils';

describe('Group Operations', () => {
    it('should do thing 1', () => {
        const { element: a } = decodeElement(Buffer.from('85ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a87209', 'hex'));
        const { scalar: b } = decodeScalar(Buffer.from('e57e6c4d3f6c645d69549f0c62aebfb77ebbcf29d2a8f0cd597d4ecd8ed56458', 'hex'));
        const c = scaleElement(a, b);
        const cBytes = encodeElement(c);
        expect(bytesToHex(cBytes)).toEqual('ac39b219f3915eb90a4917931abbd5cf57709473bbc57f2169a311de51b397b882c29a1ba8fbf581ca12c388d69eecec');
    });
    it('should do thing 2', () => {
        let a = scalarFromBigEndianBytesModQ(hexToBytes('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'));
        expect(encodeScalar(a)).toEqual(hexToBytes('6c9cf2f390e999c9235c9287cbed6c2b8f3954729614d30511ff599fd9d94807'));
    });
}); 

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
}

