import { Element, Scalar } from './group';
import { newTranscript } from './fiat_shamir_transform';

export function sigmaDLogProve(
    base: Element,
    exponent: Scalar,
    result: Element
): Uint8Array {
    const transcript = newTranscript();
    // TODO: Implement Sigma DLog proof
    return new Uint8Array(0);
} 