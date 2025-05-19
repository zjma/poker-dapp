import { AccountAddress, Deserializer } from '@aptos-labs/ts-sdk';
import * as Group from './group';
import * as DKG from './dkg_v0';
import * as SigmaDlogEq from './sigma_dlog';

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
}

export class Session {
    toBeScaled: Group.Element;
    secretInfo: DKG.SharedSecretPublicInfo;
    allowedContributors: AccountAddress[];
    /// Can be one of the following values.
    /// - `STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE`
    /// - `STATE__SUCCEEDED`
    /// - `STATE__FAILED`
    state: number;
    /// If `state == STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE`, this field describes the deadline (in unix seconds).
    deadline: number;
    /// When `state == STATE__FAILED`, this keeps track of who misbehaved.
    culprits: AccountAddress[];
    contributions: VerifiableContribution[];
    /// Filled once `state` is changed to `STATE__SUCCEEDED`.
    result: Group.Element | null;

    constructor(toBeScaled: Group.Element, secretInfo: DKG.SharedSecretPublicInfo, allowedContributors: AccountAddress[], state: number, deadline: number, culprits: AccountAddress[], contributions: VerifiableContribution[], result: Group.Element | null) {
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
        const contributions = new Array<VerifiableContribution>(numContributions);
        for (let i = 0; i < numContributions; i++) {
            contributions[i] = VerifiableContribution.decode(deserializer);
        }

        const hasResult = deserializer.deserializeU8();
        const result = hasResult ? Group.Element.decode(deserializer) : null;

        return new Session(toBeScaled, secretInfo, allowedContributors, state, deadline, culprits, contributions, result);
    }
}
