import type { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToNumberBE, bytesToNumberLE, numberToBytesBE, numberToBytesLE } from '@noble/curves/abstract/utils';
import { Deserializer, Serializer } from '@aptos-labs/ts-sdk';

// Constants
const Q = BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');

// Types
export class Element {
    bytes: Uint8Array;

    constructor(bytes: Uint8Array) {
        this.bytes = bytes;
    }
    static dummy(): Element {
        return new Element(new Uint8Array(48));
    }

    static fromInner(inner: ProjPointType<bigint>): Element {
        const compressed = true;
        const bytes = inner.toRawBytes(compressed);
        return new Element(bytes);
    }

    static groupIdentity(): Element {
        return Element.fromInner(bls12_381.G1.ProjectivePoint.ZERO);
    }

    static rand(): Element {
        const randomBytes = crypto.getRandomValues(new Uint8Array(32));
        const h2cPoint = bls12_381.G1.hashToCurve(randomBytes);
        const affine = h2cPoint.toAffine();
        const proj = bls12_381.G1.ProjectivePoint.fromAffine(affine);
        return Element.fromInner(proj);
    }

    static decode(deserializer: Deserializer): Element {
        const bytes = deserializer.deserializeBytes();
        return new Element(bytes);
    }

    encode(serializer: Serializer) {
        serializer.serializeBytes(this.bytes);
    }

    asInner(): ProjPointType<bigint> {
        return bls12_381.G1.ProjectivePoint.fromHex(this.bytes);
    }

    add(other: Element): Element {
        const pointA = this.asInner();
        const pointB = other.asInner();
        const result = pointA.add(pointB);
        return Element.fromInner(result);
    }
    

    sub(other: Element): Element {
        const pointA = this.asInner();
        const pointB = other.asInner();
        const result = pointA.subtract(pointB);
        return Element.fromInner(result);
    }

    scale(scalar: Scalar): Element {
        const point = this.asInner();
        const s = bytesToNumberLE(scalar.bytes) % Q;
        const result = point.multiply(s);
        return Element.fromInner(result);
    }
}

export class Scalar {
    bytes: Uint8Array;

    constructor(bytes: Uint8Array) {
        this.bytes = bytes;
    }
    
    static dummy(): Scalar {
        return new Scalar(new Uint8Array(32));
    }

    fromU64(x: bigint): Scalar {
        return new Scalar(numberToBytesBE(x, 32));
    }
    
    static fromBigEndianBytesModQ(bytes: Uint8Array): Scalar {
        const value = bytesToNumberBE(bytes) % Q;
        return new Scalar(numberToBytesLE(value, 32));
    }

    static rand(): Scalar {
        const randomBytes = crypto.getRandomValues(new Uint8Array(64));
        const value = bytesToNumberLE(randomBytes) % Q;
        return new Scalar(numberToBytesLE(value, 32));
    }

    static decode(deserializer: Deserializer): Scalar {
        const bytes = deserializer.deserializeBytes();
        return new Scalar(bytes);
    }

    encode(serializer: Serializer) {
        serializer.serializeBytes(this.bytes);
    }

    add(other: Scalar): Scalar {
        const result = (bytesToNumberBE(this.bytes) + bytesToNumberBE(other.bytes)) % Q;
        return new Scalar(numberToBytesBE(result, 32));
    }

    mul(other: Scalar): Scalar {
        const result = (bytesToNumberBE(this.bytes) * bytesToNumberBE(other.bytes)) % Q;
        return new Scalar(numberToBytesBE(result, 32));
    }

    neg(): Scalar {
        const result = Q - bytesToNumberBE(this.bytes);
        return new Scalar(numberToBytesBE(result, 32));
    }
}

export function msm(bases: Element[], scalars: Scalar[]): Element {
    let acc = Element.groupIdentity();
    for (let i = 0; i < bases.length; i++) {
        const scaled = bases[i].scale(scalars[i]);
        acc = acc.add(scaled);
    }
    return acc;
}
