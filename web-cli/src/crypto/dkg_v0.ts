import { AccountAddress } from "@aptos-labs/ts-sdk";
import { Element, Scalar, randScalar, groupIdentity, scaleElement, elementAdd, scalarFromU64, scalarAdd } from './group';
import { sigmaDLogProve } from './sigma_dlog';
import { newTranscript } from './fiat_shamir_transform';

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
    public_point: Element;
    proof: Uint8Array;
};

export type SecretShare = {
    private_scalar: Scalar;
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

export function newSession(expected_contributors: AccountAddress[]): DKGSession {
    return {
        base_point: groupIdentity(),
        expected_contributors,
        deadline: Math.floor(Date.now() / 1000) + 10,
        state: STATE_IN_PROGRESS,
        contributions: Array(expected_contributors.length).fill(null),
        contribution_still_needed: expected_contributors.length,
        agg_public_point: groupIdentity(),
        culprits: []
    };
}

export function generate(session: DKGSession): { secret_share: SecretShare; contribution: VerifiableContribution } {
    const private_scalar = randScalar();
    const secret_share = { private_scalar };
    const public_point = scaleElement(session.base_point, private_scalar);
    
    const transcript = newTranscript();
    const proof = sigmaDLogProve(
        session.base_point,
        private_scalar,
        public_point
    );
    
    const contribution = { public_point, proof };
    return { secret_share, contribution };
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
            public_point: contribution.public_point
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
        agg = scalarAdd(agg, share.private_scalar);
    }
    return agg;
} 