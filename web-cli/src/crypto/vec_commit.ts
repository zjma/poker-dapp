import { Element, Scalar, elementAdd, scaleElement } from './group';
import { hashToScalar, newTranscript } from './fiat_shamir_transform';

export type VectorCommitment = {
    base: Element;
    commitment: Element;
};

export type VectorOpening = {
    base: Element;
    position: number;
    value: Element;
    proof: Element;
};

export function makeVectorCommitment(
    base: Element,
    commitment: Element
): VectorCommitment {
    return { base, commitment };
}

export function makeVectorOpening(
    base: Element,
    position: number,
    value: Element,
    proof: Element
): VectorOpening {
    return { base, position, value, proof };
}

export function commit(
    base: Element,
    values: Element[]
): VectorCommitment {
    let commitment = base;
    for (let i = 0; i < values.length; i++) {
        const scalar = hashToScalar(newTranscript());
        commitment = elementAdd(commitment, scaleElement(values[i], scalar));
    }
    return makeVectorCommitment(base, commitment);
}

export function open(
    base: Element,
    position: number,
    value: Element,
    values: Element[]
): VectorOpening {
    let proof = base;
    for (let i = 0; i < values.length; i++) {
        if (i === position) continue;
        const scalar = hashToScalar(newTranscript());
        proof = elementAdd(proof, scaleElement(values[i], scalar));
    }
    return makeVectorOpening(base, position, value, proof);
}

export function verify(
    commitment: VectorCommitment,
    opening: VectorOpening
): boolean {
    const scalar = hashToScalar(newTranscript());
    const lhs = elementAdd(
        scaleElement(opening.value, scalar),
        opening.proof
    );
    return lhs.bytes.every((b, i) => b === commitment.commitment.bytes[i]);
}

export function encodeVectorCommitment(vc: VectorCommitment): Uint8Array {
    const buf = new Uint8Array(vc.base.bytes.length + vc.commitment.bytes.length);
    buf.set(vc.base.bytes, 0);
    buf.set(vc.commitment.bytes, vc.base.bytes.length);
    return buf;
}

export function encodeVectorOpening(vo: VectorOpening): Uint8Array {
    const positionBuf = new Uint8Array(4);
    const view = new DataView(positionBuf.buffer);
    view.setUint32(0, vo.position, true);
    
    const buf = new Uint8Array(
        vo.base.bytes.length +
        positionBuf.length +
        vo.value.bytes.length +
        vo.proof.bytes.length
    );
    let offset = 0;
    buf.set(vo.base.bytes, offset);
    offset += vo.base.bytes.length;
    buf.set(positionBuf, offset);
    offset += positionBuf.length;
    buf.set(vo.value.bytes, offset);
    offset += vo.value.bytes.length;
    buf.set(vo.proof.bytes, offset);
    return buf;
} 