import type { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToNumberBE, bytesToNumberLE, numberToBytesBE, numberToBytesLE } from '@noble/curves/abstract/utils';

// Constants
const Q = BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');

// Types
export type Element = {
    bytes: Uint8Array;
};

export type Scalar = {
    bytes: Uint8Array;
};

// Helper functions
function u8ToLittleEndianBits(x: number): boolean[] {
    return Array.from({ length: 8 }, (_, i) => ((x >> i) & 1) === 1);
}

function safeAddMod(a: bigint, b: bigint, m: bigint): bigint {
    const negB = m - b;
    if (a < negB) {
        return a + b;
    }
    return a - negB;
}

function u256ToLittleEndianBytes(x: bigint): Uint8Array {
    return new Uint8Array(Array.from({ length: 32 }, (_, i) => {
        const shift = BigInt(8 * i);
        return Number((x >> shift) & BigInt(0xff));
    }));
}

export function scalarFromBigEndianBytesModQ(bytes: Uint8Array): Scalar {
    const value = bytesToNumberBE(bytes) % Q;
    return { bytes: numberToBytesLE(value, 32) };
}

export function dummyElement(): Element {
    return { bytes: new Uint8Array(48) }; // BLS12-381 G1 point size
}

export function dummyScalar(): Scalar {
    return { bytes: new Uint8Array(32) }; // BLS12-381 scalar size
}

// Main functions
export function encodeElement(element: Element): Uint8Array {
    return element.bytes;
}

export function decodeElement(buf: Uint8Array): { errors: number[]; element: Element; remaining: Uint8Array } {
    if (buf.length < 48) {
        return { errors: [115605], element: dummyElement(), remaining: buf };
    }
    const bytes = new Uint8Array(48);
    // Convert Buffer to Uint8Array if needed
    const inputBytes = buf instanceof Buffer ? new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength) : buf;
    bytes.set(inputBytes.slice(0, 48));
    console.log('Input bytes:', inputBytes);
    console.log('Decoded element bytes:', bytes);
    const element = { bytes };
    const remaining = buf.slice(48);
    return { errors: [], element, remaining };
}

export function encodeScalar(scalar: Scalar): Uint8Array {
    return scalar.bytes;
}

export function decodeScalar(buf: Uint8Array): { errors: number[]; scalar: Scalar; remainder: Uint8Array } {
    if (buf.length < 32) {
        return { errors: [115605], scalar: dummyScalar(), remainder: buf };
    }
    const scalar = { bytes: buf.slice(0, 32) };
    const remainder = buf.slice(32);
    return { errors: [], scalar, remainder };
}

export function randScalar(): Scalar {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    const scalar = bytesToNumberLE(randomBytes) % Q;
    return { bytes: numberToBytesLE(scalar, 32) };
}

export function randElement(): Element {
    const randomBytes = crypto.getRandomValues(new Uint8Array(32));
    const h2cPoint = bls12_381.G1.hashToCurve(randomBytes);
    const affine = h2cPoint.toAffine();
    const proj = bls12_381.G1.ProjectivePoint.fromAffine(affine);
    return elementFromInner(proj);
}

export function groupIdentity(): Element {
    return elementFromInner(bls12_381.G1.ProjectivePoint.ZERO);
}

export function elementAdd(a: Element, b: Element): Element {
    const pointA = elementIntoInner(a);
    const pointB = elementIntoInner(b);
    const result = pointA.add(pointB);
    return elementFromInner(result);
}

export function elementSub(a: Element, b: Element): Element {
    const pointA = elementIntoInner(a);
    const pointB = elementIntoInner(b);
    const result = pointA.subtract(pointB);
    return elementFromInner(result);
}

export function scaleElement(element: Element, scalar: Scalar): Element {
    const point = elementIntoInner(element);
    console.log('Input point:', point);
    const s = bytesToNumberLE(scalar.bytes) % Q;
    console.log('Scalar bytes:', scalar.bytes);
    console.log('Scalar value:', s);
    console.log('Scalar hex:', s.toString(16));
    const result = point.multiply(s);
    console.log('Result point:', result);
    const elementResult = elementFromInner(result);
    console.log('Result bytes:', elementResult.bytes);
    return elementResult;
}

export function scalarFromU64(x: bigint): Scalar {
    return { bytes: numberToBytesBE(x, 32) };
}

export function scalarAdd(a: Scalar, b: Scalar): Scalar {
    const aNum = bytesToNumberBE(a.bytes);
    const bNum = bytesToNumberBE(b.bytes);
    const result = (aNum + bNum) % Q;
    return { bytes: numberToBytesBE(result, 32) };
}

export function scalarMul(a: Scalar, b: Scalar): Scalar {
    const aNum = bytesToNumberBE(a.bytes);
    const bNum = bytesToNumberBE(b.bytes);
    const result = (aNum * bNum) % Q;
    return { bytes: numberToBytesBE(result, 32) };
}

export function scalarNeg(s: Scalar): Scalar {
    const sNum = bytesToNumberBE(s.bytes);
    const result = (Q - sNum) % Q;
    return { bytes: numberToBytesBE(result, 32) };
}

export function msm(bases: Element[], scalars: Scalar[]): Element {
    let result = groupIdentity();
    for (let i = 0; i < bases.length; i++) {
        const scaled = scaleElement(bases[i], scalars[i]);
        result = elementAdd(result, scaled);
    }
    return result;
}

function elementIntoInner(element: Element): ProjPointType<bigint> {
    console.log('Element bytes:', element.bytes);
    // Points are in Big Endian format, use directly
    const point = bls12_381.G1.ProjectivePoint.fromHex(element.bytes);
    console.log('Decoded point:', point);
    return point;
}

function elementFromInner(inner: ProjPointType<bigint>): Element {
    const bytes = inner.toRawBytes(true); // true for compressed format
    console.log('Point to encode:', inner);
    console.log('Encoded bytes:', bytes);
    return { bytes };
}
