import { Element, Scalar, elementAdd, scaleElement } from './group';
import { Ciphertext, ciphertextAdd, ciphertextMul, makeCiphertext } from './elgamal';
import { hashToScalar, newTranscript } from './fiat_shamir_transform';

export type ReencryptionKey = {
    enc_base: Element;
    reenc_key: Element;
};

export type ReencryptionProof = {
    enc_base: Element;
    reenc_key: Element;
    proof: Uint8Array;
};

export function makeReencryptionKey(
    enc_base: Element,
    reenc_key: Element
): ReencryptionKey {
    return { enc_base, reenc_key };
}

export function reencrypt(
    rk: ReencryptionKey,
    ciph: Ciphertext
): Ciphertext {
    const transcript = newTranscript();
    const randomizer = hashToScalar(transcript);
    const reenc = scaleElement(rk.reenc_key, randomizer);
    return {
        enc_base: ciph.enc_base,
        c_0: ciph.c_0,
        c_1: elementAdd(ciph.c_1, reenc)
    };
}

export function reencryptWithProof(
    rk: ReencryptionKey,
    ciph: Ciphertext
): ReencryptionProof {
    const transcript = newTranscript();
    const randomizer = hashToScalar(transcript);
    const reenc = scaleElement(rk.reenc_key, randomizer);
    // TODO: Implement proof generation
    const proof = new Uint8Array(0);
    return {
        enc_base: rk.enc_base,
        reenc_key: reenc,
        proof
    };
}

export function encodeReencryption(rk: ReencryptionKey): Uint8Array {
    const buf = new Uint8Array(rk.enc_base.bytes.length + rk.reenc_key.bytes.length);
    buf.set(rk.enc_base.bytes, 0);
    buf.set(rk.reenc_key.bytes, rk.enc_base.bytes.length);
    return buf;
}

export function encodeReencryptionProof(proof: ReencryptionProof): Uint8Array {
    const buf = new Uint8Array(
        proof.enc_base.bytes.length +
        proof.reenc_key.bytes.length +
        proof.proof.length
    );
    let offset = 0;
    buf.set(proof.enc_base.bytes, offset);
    offset += proof.enc_base.bytes.length;
    buf.set(proof.reenc_key.bytes, offset);
    offset += proof.reenc_key.bytes.length;
    buf.set(proof.proof, offset);
    return buf;
} 