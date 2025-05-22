import { AccountAddress, Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Element, Scalar } from './group';
import * as SigmaDLog from './sigma_dlog';

import * as Group from './group';
import { EncKey } from "./elgamal";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

export const STATE_IN_PROGRESS = 0;
export const STATE_SUCCEEDED = 1;
export const STATE_TIMED_OUT = 2;

export class DKGSession {
    basePoint: Element;
    expectedContributors: AccountAddress[];
    deadline: number;
    state: number;
    contributions: (VerifiableContribution | null)[];
    contributionStillNeeded: number;
    aggPublicPoint: Element;
    culprits: AccountAddress[];

    constructor(basePoint: Element, expectedContributors: AccountAddress[], deadline: number, state: number, contributions: (VerifiableContribution | null)[], contributionStillNeeded: number, aggPublicPoint: Element, culprits: AccountAddress[]) {
        this.basePoint = basePoint;
        this.expectedContributors = expectedContributors;
        this.deadline = deadline;
        this.state = state;
        this.contributions = contributions;
        this.contributionStillNeeded = contributionStillNeeded;
        this.aggPublicPoint = aggPublicPoint;
        this.culprits = culprits;
    }

    static dummy(): DKGSession {
        return new DKGSession(
            Group.Element.groupIdentity(),
            [],
            0,
            0,
            [],
            0,
            Group.Element.groupIdentity(),
            [],
        );
    }
    
    static decode(deserializer: Deserializer): DKGSession {
        const basePoint = Group.Element.decode(deserializer);
        const expectedContributors = deserializer.deserializeVector(AccountAddress);
        const deadline = Number(deserializer.deserializeU64());
        const state = Number(deserializer.deserializeU64());
        const numContributions = deserializer.deserializeUleb128AsU32();
        const contributions = new Array<VerifiableContribution | null>(numContributions);
        for (let i = 0; i < numContributions; i++) {
            const isNull = deserializer.deserializeU8() === 0;
            contributions[i] = isNull ? null : VerifiableContribution.decode(deserializer);
        }
        const contributionStillNeeded = Number(deserializer.deserializeU64());
        const aggPublicPoint = Group.Element.decode(deserializer);
        const culprits = deserializer.deserializeVector(AccountAddress);
        return new DKGSession(basePoint, expectedContributors, deadline, state, contributions, contributionStillNeeded, aggPublicPoint, culprits);
    }

    encode(serializer: Serializer): void {
        this.basePoint.encode(serializer);
        serializer.serializeVector(this.expectedContributors);
        serializer.serializeU64(this.deadline);
        serializer.serializeU64(this.state);
        serializer.serializeU32AsUleb128(this.contributions.length);
        for (const contribution of this.contributions) {
            if (contribution === null) {
                serializer.serializeU8(0);
            } else {
                serializer.serializeU8(1);
                contribution.encode(serializer);
            }
        }
        serializer.serializeU64(this.contributionStillNeeded);
        this.aggPublicPoint.encode(serializer);
        serializer.serializeVector(this.culprits);
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
    agg_ek: EncKey;
    ek_shares: EncKey[];

    constructor(agg_ek: EncKey, ek_shares: EncKey[]) {
        this.agg_ek = agg_ek;
        this.ek_shares = ek_shares;
    }

    static decode(deserializer: Deserializer): SharedSecretPublicInfo {
        const agg_ek = EncKey.decode(deserializer);
        const ek_shares = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => EncKey.decode(deserializer));
        return new SharedSecretPublicInfo(agg_ek, ek_shares);
    }

    encode(serializer: Serializer): void {
        this.agg_ek.encode(serializer);
        serializer.serializeU32AsUleb128(this.ek_shares.length);
        for (const ek of this.ek_shares) {
            ek.encode(serializer);
        }
    }
};
