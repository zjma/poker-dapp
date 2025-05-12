import { Element, Scalar, dummyElement, dummyScalar } from './group';
import { newTranscript } from './fiat_shamir_transform';

export type Proof = {
    t: Element;
    s: Scalar;
};

export function encodeProof(proof: Proof): Uint8Array {
    throw new Error('Not implemented');
}

export function sigmaDLogProve(
    base: Element,
    exponent: Scalar,
    result: Element
): Proof {
    const transcript = newTranscript();
    // TODO: Implement Sigma DLog proof
    return { t: dummyElement(), s: dummyScalar() };
}
