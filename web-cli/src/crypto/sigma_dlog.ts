import { Element, Scalar } from './group';
import { Transcript } from './fiat_shamir_transform';

export type Proof = {
    t: Element;
    s: Scalar;
};

export function encodeProof(proof: Proof): Uint8Array {
    throw new Error('Not implemented');
}
