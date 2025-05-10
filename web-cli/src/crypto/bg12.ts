import { Element, Scalar } from './group';
import { newTranscript } from './fiat_shamir_transform';

export function bg12Prove(
    bases: Element[],
    scalars: Scalar[],
    commitment: Element
): Uint8Array {
    const transcript = newTranscript();
    // TODO: Implement BG12 proof generation
    return new Uint8Array(0);
} 