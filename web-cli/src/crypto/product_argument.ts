import { Element, Scalar } from './group';
import { newTranscript } from './fiat_shamir_transform';

export function productProve(
    bases: Element[],
    scalars: Scalar[],
    product: Scalar
): Uint8Array {
    const transcript = newTranscript();
    // TODO: Implement product proof
    return new Uint8Array(0);
} 