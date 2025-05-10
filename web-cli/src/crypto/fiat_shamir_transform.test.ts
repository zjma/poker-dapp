import { describe, it, expect } from 'vitest';
import { newTranscript, appendGroupElement, hashToScalar } from './fiat_shamir_transform';
import { decodeElement, encodeScalar } from './group';

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
}

describe('Fiat Shamir Transform', () => {
    it('should do thing 1', () => {
        const trx = newTranscript();
        const { element } = decodeElement(hexToBytes('85ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a87209'));
        appendGroupElement(trx, element);
        const scalar = hashToScalar(trx);
        expect(encodeScalar(scalar)).toEqual(hexToBytes('7c2b9ef979a61164ba8db00715cbc18eb4a501682b47467a69b7295e5ce9a532'));
    });
});
