import { AccountAddress, Deserializer, Serializer } from '@aptos-labs/ts-sdk';
import * as Group from './group';
import * as DKG from './dkg_v0';
import * as SigmaDlogEq from './sigma_dlog_eq';
import { Transcript } from './fiat_shamir_transform';

export const STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE: number = 1;
export const STATE__SUCCEEDED: number = 3;
export const STATE__FAILED: number = 4;

export class VerifiableContribution {
    payload: Group.Element;
    proof: SigmaDlogEq.Proof | null;

    constructor(payload: Group.Element, proof: SigmaDlogEq.Proof | null) {
        this.payload = payload;
        this.proof = proof;
    }

    static decode(deserializer: Deserializer): VerifiableContribution {
        const payload = Group.Element.decode(deserializer);
        const hasProof = deserializer.deserializeU8();
        const proof = hasProof ? SigmaDlogEq.Proof.decode(deserializer) : null;
        return new VerifiableContribution(payload, proof);
    }

    encode(serializer: Serializer): void {
        this.payload.encode(serializer);
        serializer.serializeU8(this.proof ? 1 : 0);
        if (this.proof) {
            this.proof.encode(serializer);
        }
    }
    
    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.encode(serializer);
        return serializer.toUint8Array();
    }
    
    
}

export class Session {
    toBeScaled: Group.Element;
    secretInfo: DKG.SharedSecretPublicInfo;
    allowedContributors: AccountAddress[];
    state: number;
    deadline: number;
    culprits: AccountAddress[];
    contributions: (VerifiableContribution | null)[];
    result: Group.Element | null;

    constructor(toBeScaled: Group.Element, secretInfo: DKG.SharedSecretPublicInfo, allowedContributors: AccountAddress[], state: number, deadline: number, culprits: AccountAddress[], contributions: (VerifiableContribution | null)[], result: Group.Element | null) {
        this.toBeScaled = toBeScaled;
        this.secretInfo = secretInfo;
        this.allowedContributors = allowedContributors;
        this.state = state;
        this.deadline = deadline;
        this.culprits = culprits;
        this.contributions = contributions;
        this.result = result;
    }

    static decode(deserializer: Deserializer): Session {
        const toBeScaled = Group.Element.decode(deserializer);
        const secretInfo = DKG.SharedSecretPublicInfo.decode(deserializer);

        const allowedContributorsSize = Number(deserializer.deserializeUleb128AsU32());
        const allowedContributors = new Array<AccountAddress>(allowedContributorsSize);
        for (let i = 0; i < allowedContributorsSize; i++) {
            allowedContributors[i] = deserializer.deserialize(AccountAddress);
        }

        const state = Number(deserializer.deserializeU64());
        const deadline = Number(deserializer.deserializeU64());

        const numCulprits = Number(deserializer.deserializeUleb128AsU32());
        const culprits = new Array<AccountAddress>(numCulprits);
        for (let i = 0; i < numCulprits; i++) {
            culprits[i] = deserializer.deserialize(AccountAddress);
        }

        const numContributions = Number(deserializer.deserializeUleb128AsU32());
        const contributions = new Array<VerifiableContribution | null>(numContributions);
        for (let i = 0; i < numContributions; i++) {
            const hasContribution = deserializer.deserializeU8() > 0;
            contributions[i] = hasContribution ? VerifiableContribution.decode(deserializer) : null;
        }

        const hasResult = deserializer.deserializeU8();
        const result = hasResult ? Group.Element.decode(deserializer) : null;

        return new Session(toBeScaled, secretInfo, allowedContributors, state, deadline, culprits, contributions, result);
    }

    generateContribution(me: AccountAddress, secretShare: DKG.SecretShare): VerifiableContribution {
        if (this.state != STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE) {
            throw new Error('Cannot generate contribution in this state');
        }

        const contributor_idx = this.allowedContributors.findIndex(c => c.toString() == me.toString());
        if (contributor_idx == -1) {
            throw new Error('I am not in the allowed contributors list');
        }

        const payload = this.toBeScaled.scale(secretShare.privateScalar);
        const trx = new Transcript();
        const proof = SigmaDlogEq.prove(
            trx,
            this.secretInfo.agg_ek.encBase,
            this.secretInfo.ek_shares[contributor_idx].publicPoint,
            this.toBeScaled,
            payload,
            secretShare.privateScalar
        );
        return new VerifiableContribution(payload, proof);

    }
}
