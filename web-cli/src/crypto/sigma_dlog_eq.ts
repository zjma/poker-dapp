import { Element, Scalar } from './group';
import { newTranscript } from './fiat_shamir_transform';

export function sigmaDLogEqProve(
    base1: Element,
    base2: Element,
    exponent: Scalar,
    result1: Element,
    result2: Element
): Uint8Array {
    const transcript = newTranscript();
    // TODO: Implement Sigma DLog Equality proof
    return new Uint8Array(0);
} 