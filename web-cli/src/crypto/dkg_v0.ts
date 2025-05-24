import { AccountAddress, Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Element, Scalar } from './group';
import * as SigmaDLog from './sigma_dlog';

import * as Group from './group';
import { EncKey } from "./elgamal";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

export const STATE_IN_PROGRESS = 0;
export const STATE_SUCCEEDED = 1;
export const STATE_TIMED_OUT = 2;

export class SessionBrief {
    addr: AccountAddress;
    basePoint: Element;
    expectedContributors: AccountAddress[];
    deadline: number;
    state: number;
    contributionFlags: boolean[];
    aggPublicPoint: Element;

    constructor(addr: AccountAddress, basePoint: Element, expectedContributors: AccountAddress[], deadline: number, state: number, contributionFlags: boolean[], aggPublicPoint: Element) {
        this.addr = addr;
        this.basePoint = basePoint;
        this.expectedContributors = expectedContributors;
        this.deadline = deadline;
        this.state = state;
        this.contributionFlags = contributionFlags;
        this.aggPublicPoint = aggPublicPoint;
    }

    static decode(deserializer: Deserializer): SessionBrief {
        const addr = deserializer.deserialize(AccountAddress);
        const basePoint = Group.Element.decode(deserializer);
        const expectedContributors = deserializer.deserializeVector(AccountAddress);
        const deadline = Number(deserializer.deserializeU64());
        const state = Number(deserializer.deserializeU64());
        const numContributions = deserializer.deserializeUleb128AsU32();
        const contributionFlags = new Array<boolean>(numContributions);
        for (let i = 0; i < numContributions; i++) {
            contributionFlags[i] = deserializer.deserializeBool();
        }
        const aggPublicPoint = Group.Element.decode(deserializer);
        return new SessionBrief(addr, basePoint, expectedContributors, deadline, state, contributionFlags, aggPublicPoint);
    }

    succeeded(): boolean {
        return this.state === STATE_SUCCEEDED;
    }

    failed(): boolean {
        return this.state === STATE_TIMED_OUT;
    }

    generateContribution(): {secretShare: SecretShare, contribution: VerifiableContribution} {
        const privateScalar = Scalar.rand();
        const secretShare = new SecretShare(privateScalar);
        const publicPoint = this.basePoint.scale(privateScalar);
        
        const contribution = new VerifiableContribution(publicPoint, null); //TODO: Implement proof
        return { secretShare, contribution };
    }
};

export class VerifiableContribution {
    publicPoint: Element;
    proof: SigmaDLog.Proof | null;

    constructor(publicPoint: Element, proof: SigmaDLog.Proof | null) {
        this.publicPoint = publicPoint;
        this.proof = proof;
    }

    static decode(deserializer: Deserializer): VerifiableContribution {
        const publicPoint = Group.Element.decode(deserializer);
        const hasProof = deserializer.deserializeU8() === 1;
        const proof = hasProof ? SigmaDLog.Proof.decode(deserializer) : null;
        return new VerifiableContribution(publicPoint, proof);
    }

    encode(serializer: Serializer): void {
        this.publicPoint.encode(serializer);
        if (this.proof === null) {
            serializer.serializeU8(0);
        } else {
            serializer.serializeU8(1);
            this.proof.encode(serializer);
        }
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.encode(serializer);
        return serializer.toUint8Array();
    }
};

export class SecretShare {
    privateScalar: Scalar;

    constructor(privateScalar: Scalar) {
        this.privateScalar = privateScalar;
    }

    static fromBytes(bytes: Uint8Array): SecretShare {
        const deserializer = new Deserializer(bytes);
        return SecretShare.decode(deserializer);
    }

    static fromHex(hex: string): SecretShare {
        return SecretShare.fromBytes(hexToBytes(hex));
    }

    static decode(deserializer: Deserializer): SecretShare {
        const privateScalar = Scalar.decode(deserializer);
        return new SecretShare(privateScalar);
    }

    encode(serializer: Serializer): void {
        this.privateScalar.encode(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.encode(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
};

export class SharedSecretPublicInfo {
    sessionAddr: AccountAddress;
    agg_ek: EncKey;
    ek_shares: EncKey[];

    constructor(sessionAddr: AccountAddress, agg_ek: EncKey, ek_shares: EncKey[]) {
        this.sessionAddr = sessionAddr;
        this.agg_ek = agg_ek;
        this.ek_shares = ek_shares;
    }

    static decode(deserializer: Deserializer): SharedSecretPublicInfo {
        const sessionAddr = deserializer.deserialize(AccountAddress);
        const agg_ek = EncKey.decode(deserializer);
        const ek_shares = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => EncKey.decode(deserializer));
        return new SharedSecretPublicInfo(sessionAddr, agg_ek, ek_shares);
    }

    encode(serializer: Serializer): void {
        serializer.serialize(this.sessionAddr);
        this.agg_ek.encode(serializer);
        serializer.serializeU32AsUleb128(this.ek_shares.length);
        for (const ek of this.ek_shares) {
            ek.encode(serializer);
        }
    }
};
