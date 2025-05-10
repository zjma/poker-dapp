import { describe, it, expect, beforeEach } from 'vitest';
import { Element, Scalar, decodeElement, decodeScalar, msm, randElement, randScalar } from './group';
import {
    makeEncKey,
    makeCiphertext,
    enc,
    dec,
    ciphertextAdd,
    ciphertextMul,
    weirdMultiExp,
    encodeEncKey,
    type EncKey,
    type DecKey,
    type Ciphertext,
    decodeEncKey,
    decodeDecKey,
    encodeCiphertext
} from './elgamal';

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
}

describe('ElGamal Encryption', () => {
    let encBase: Element;
    let privateKey: Scalar;
    let publicPoint: Element;
    let encKey: EncKey;
    let decKey: DecKey;

    beforeEach(() => {
        // Initialize test values
        encBase = randElement();
        privateKey = randScalar();
        publicPoint = randElement();
        encKey = makeEncKey(encBase, publicPoint);
        decKey = { enc_base: encBase, private_scalar: privateKey };
    });

    it('should do thing 1', () => {
        var { errors, decKey, remainder } = decodeDecKey(hexToBytes('85ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a87209e57e6c4d3f6c645d69549f0c62aebfb77ebbcf29d2a8f0cd597d4ecd8ed56458'));
        expect(errors).toEqual([]);
        expect(remainder).toEqual(new Uint8Array([]));
        var { errors, encKey, remainder } = decodeEncKey(hexToBytes('85ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a87209ac39b219f3915eb90a4917931abbd5cf57709473bbc57f2169a311de51b397b882c29a1ba8fbf581ca12c388d69eecec'));
        expect(errors).toEqual([]);
        expect(remainder).toEqual(new Uint8Array([]));
        var msgs = [
            decodeElement(hexToBytes('b2a87401bbed626666c5bab7d0a6503c04cbb7a91bb42a68f5f52370993658d8bd54e23cd7ae7ddd9a78eec823c0fdc1')).element,
            decodeElement(hexToBytes('a9e85bd1b4f17ef0aadee7a420873ab8c4568c56f91686cd6cc03ab43ade4bf3d2c4a011667ade42c5dad1a8d32d8bf3')).element,
            decodeElement(hexToBytes('92d67fcaac2fc24a4a92a4035fb4d2a64b0cdd5f3e80fb2ddfff640717eaf444fae9da821fac35e922e7014f6bbfacfe')).element,
        ];
        var randomizers = [
            decodeScalar(hexToBytes('23bcb6a5ec8328bb3772930f2e5f48df3ede9ee6ddabcdefbfe15cb029980311')).scalar,
            decodeScalar(hexToBytes('4c55876a65167a1f9d901f3b7e28985f1353f4bc1e36e7c11be7d416fba70c5b')).scalar,
            decodeScalar(hexToBytes('41535947e0e5039cea76bc4960c8e25b1c36f717d16e19a00593a8f7bc5e842c')).scalar,
        ];
        var ciphertexts = msgs.map((msg, i) => enc(encKey, randomizers[i], msg));
        expect(ciphertexts.map(c => encodeCiphertext(c)))
        .toEqual([
            hexToBytes('85ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a87209b9536b2486ae358dab0a9dacc8f13e2ae81f697cbc61fafdd69fdf1700f22e47131669f7d863dfd62d6b2d72435d3c3480e52b0f02060e5759da9de3a3730c34a793b46abfd69126bcfc8e149bcc87f9418f50147c5afc6fd8b798c6cc2839db'),
            hexToBytes('85ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a87209af43c90d15a93fb90b1c50e0efb82e6ee3880df2faf02974a5095e9f081685a2fb2510fbfacdc6e594227ec58814cbeb915c208d825f43a651357ad79c16b54c6b03bbfd18fdffe77c35f633115242a7f950d06acc2ad80f2e97213b6e8c5f36'),
            hexToBytes('85ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a8720990b9bb8cd9e07b645c02a23b5d2ed6d62b6cb3d23ce5feab388a32998af46796e1187cab958dccf636a2da036303eda0add4dff914615d8f2be34ac3b18df7e9a2518d090e56568e4d87635488b34eb98d700c8b1678d753807c9c90dee4e357'),
        ]);
        var scalars = [
            decodeScalar(hexToBytes('77a12ffe50a80a9b612082659e5e4be42bb5c31e0756b1d16daad362a45d1a1e')).scalar,
            decodeScalar(hexToBytes('661d4aa3cd47a14001e59941fcdde6bf2363b80a23a9bd882bf7295ab93df830')).scalar,
            decodeScalar(hexToBytes('37c6dae837463cdc2cba312af112f80f0338ce65a19d01af79277a0d552aaa03')).scalar,
        ];
        var agg_ciphertext = weirdMultiExp(ciphertexts, scalars);
        expect(encodeCiphertext(agg_ciphertext)).toEqual(hexToBytes('85ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a87209a731430a7615e658deabf07e50abd6fb2e9eae331ff8fa9c6757a44785c7c3466d471f52f53ed267ba9e97e3ff2f8040900933813d16c18444e2e7b2e5fc0926cf6650650cbb59b361725674c97dc72cacabb2e2a3e64533a7ad327332c6760a'));
        var agg_msg = dec(decKey, agg_ciphertext);
        expect(agg_msg).toEqual(msm(msgs, scalars));
    });
}); 