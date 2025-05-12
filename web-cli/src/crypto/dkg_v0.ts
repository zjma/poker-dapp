import { AccountAddress } from "@aptos-labs/ts-sdk";
import { Element, Scalar, randScalar, groupIdentity, scaleElement, elementAdd, scalarFromU64, scalarAdd } from './group';
import * as SigmaDLog from './sigma_dlog';
import * as Utils from '../utils';

import * as Group from './group';
export type DKGSession = {
    base_point: Element;
    expected_contributors: AccountAddress[];
    deadline: number;
    state: number;
    contributions: (VerifiableContribution | null)[];
    contribution_still_needed: number;
    agg_public_point: Element;
    culprits: AccountAddress[];
};

export type VerifiableContribution = {
    publicPoint: Element;
    proof: SigmaDLog.Proof | null;
};

export type SecretShare = {
    privateScalar: Scalar;
};

export type SharedSecretPublicInfo = {
    agg_ek: EncKey;
    ek_shares: EncKey[];
};

export type EncKey = {
    enc_base: Element;
    public_point: Element;
};

const STATE_IN_PROGRESS = 0;
const STATE_SUCCEEDED = 1;
const STATE_TIMED_OUT = 2;

export function encodeContribution(contribution: VerifiableContribution): Uint8Array {
    var buf = Group.encodeElement(contribution.publicPoint);
    if (contribution.proof) {
        buf = Utils.concat(buf, new Uint8Array([1]));
    }
    return buf;
}

export function generate_contribution(session: DKGSession): { secretShare: SecretShare; contribution: VerifiableContribution } {
    const privateScalar = randScalar();
    const secretShare = { privateScalar };
    const publicPoint = scaleElement(session.base_point, privateScalar);
    
    const contribution = { publicPoint, proof: null };
    return { secretShare, contribution };
}

export function succeeded(session: DKGSession): boolean {
    return session.state === STATE_SUCCEEDED;
}

export function failed(session: DKGSession): boolean {
    return session.state === STATE_TIMED_OUT;
}

export function getCulprits(session: DKGSession): AccountAddress[] {
    return session.culprits;
}

export function getContributors(session: DKGSession): AccountAddress[] {
    if (session.state !== STATE_SUCCEEDED) {
        throw new Error('DKG session has not succeeded');
    }
    return session.expected_contributors;
}

export function getSharedSecretPublicInfo(session: DKGSession): SharedSecretPublicInfo {
    if (session.state !== STATE_SUCCEEDED) {
        throw new Error('DKG session has not succeeded');
    }
    
    const agg_ek = {
        enc_base: session.base_point,
        public_point: session.agg_public_point
    };
    
    const ek_shares = session.contributions.map(contribution => {
        if (!contribution) {
            throw new Error('Invalid contribution');
        }
        return {
            enc_base: session.base_point,
            public_point: contribution.publicPoint
        };
    });
    
    return { agg_ek, ek_shares };
}

export function getThreshold(secret_info: SharedSecretPublicInfo): number {
    return secret_info.ek_shares.length;
}

export function aggregateScalarMul(
    secret_info: SharedSecretPublicInfo,
    shares: (Element | null)[]
): Element {
    let ret = groupIdentity();
    for (const share of shares) {
        if (!share) {
            throw new Error('Invalid share');
        }
        ret = elementAdd(ret, share);
    }
    return ret;
}

export function reconstructSecret(
    public_info: SharedSecretPublicInfo,
    shares: (SecretShare | null)[]
): Scalar {
    if (public_info.ek_shares.length !== shares.length) {
        throw new Error('Number of shares does not match');
    }
    
    let agg = scalarFromU64(0n);
    for (const share of shares) {
        if (!share) {
            throw new Error('Invalid share');
        }
        agg = scalarAdd(agg, share.privateScalar);
    }
    return agg;
} 