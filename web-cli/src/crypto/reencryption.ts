import * as Elgamal from './elgamal';
import { AccountAddress, Deserializer, Serializer } from '@aptos-labs/ts-sdk';
import * as DKG from './dkg_v0';
import * as ThresholdScalarMul from './threshold_scalar_mul';
import * as Group from './group';
import * as SigmaDlogEq from './sigma_dlog_eq';
import * as SigmaDlog from './sigma_dlog';
import { Transcript } from './fiat_shamir_transform';
import { bytesToHex, toBytes } from '@noble/hashes/utils';

export const STATE__ACCEPTING_REENC = 1;
export const STATE__THRESHOLD_SCALAR_MUL_IN_PROGRESS = 2;
export const STATE__SUCCEEDED = 3;
export const STATE__FAILED = 4;

export class RecipientPrivateState {
    u: Group.Scalar;

    constructor(u: Group.Scalar) {
        this.u = u;
    }

    encode(serializer: Serializer): void {
        this.u.encode(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.encode(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
}

export class VerifiableReencryption {
    th: Group.Element;
    tsh: Group.Element;
    urth: Group.Element;
    proof_t: SigmaDlogEq.Proof | null;
    proof_u: SigmaDlog.Proof | null;

    constructor(th: Group.Element, tsh: Group.Element, urth: Group.Element, proof_t: SigmaDlogEq.Proof | null, proof_u: SigmaDlog.Proof | null) {
        this.th = th;
        this.tsh = tsh;
        this.urth = urth;
        this.proof_t = proof_t;
        this.proof_u = proof_u;
    }

    encode(serializer: Serializer): void {
        this.th.encode(serializer);
        this.tsh.encode(serializer);
        this.urth.encode(serializer);
        serializer.serializeU8(this.proof_t ? 1 : 0);
        if (this.proof_t) {
            this.proof_t.encode(serializer);
        }
        serializer.serializeU8(this.proof_u ? 1 : 0);
        if (this.proof_u) {
            this.proof_u.encode(serializer);
        }
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.encode(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
}

export class Session {
    card: Elgamal.Ciphertext;
    dealTarget: AccountAddress;
    scalarMulParty: AccountAddress[];
    secretInfo: DKG.SharedSecretPublicInfo;
    scalarMulDeadline: number;
    state: number;
    deadline: number;
    reenc: Elgamal.Ciphertext | null;
    threshScalarMulSession: ThresholdScalarMul.Session | null;
    culprits: AccountAddress[];
    
    constructor(card: Elgamal.Ciphertext, deal_target: AccountAddress, scalar_mul_party: AccountAddress[], secret_info: DKG.SharedSecretPublicInfo, scalar_mul_deadline: number, state: number, deadline: number, reenc: Elgamal.Ciphertext | null, thresh_scalar_mul_session: ThresholdScalarMul.Session | null, culprits: AccountAddress[]) {
        this.card = card;
        this.dealTarget = deal_target;
        this.scalarMulParty = scalar_mul_party;
        this.secretInfo = secret_info;
        this.scalarMulDeadline = scalar_mul_deadline;
        this.state = state;
        this.deadline = deadline;
        this.reenc = reenc;
        this.threshScalarMulSession = thresh_scalar_mul_session;
        this.culprits = culprits;
    }

    static decode(deserializer: Deserializer): Session {
        const card = Elgamal.Ciphertext.decode(deserializer);
        const deal_target = deserializer.deserialize(AccountAddress);
        const scalar_mul_party = deserializer.deserializeVector(AccountAddress);
        const secret_info = DKG.SharedSecretPublicInfo.decode(deserializer);
        const scalar_mul_deadline = Number(deserializer.deserializeU64());
        const state = Number(deserializer.deserializeU64());
        const deadline = Number(deserializer.deserializeU64());

        const hasReenc = deserializer.deserializeU8() === 1;
        const reenc = hasReenc ? Elgamal.Ciphertext.decode(deserializer) : null;

        const hasThreshScalarMulSession = deserializer.deserializeU8() === 1;
        const thresh_scalar_mul_session = hasThreshScalarMulSession ? ThresholdScalarMul.Session.decode(deserializer) : null;

        const culprits = deserializer.deserializeVector(AccountAddress);

        return new Session(card, deal_target, scalar_mul_party, secret_info, scalar_mul_deadline, state, deadline, reenc, thresh_scalar_mul_session, culprits);
    }

    encode(serializer: Serializer): void {
        this.card.encode(serializer);
        serializer.serialize(this.dealTarget);
        serializer.serializeVector(this.scalarMulParty);
        this.secretInfo.encode(serializer);
        serializer.serializeU64(this.scalarMulDeadline);
        serializer.serializeU64(this.state);
        serializer.serializeU64(this.deadline);
        serializer.serializeU8(this.reenc ? 1 : 0);
        if (this.reenc) {
            this.reenc.encode(serializer);
        }
        serializer.serializeU8(this.threshScalarMulSession ? 1 : 0);
        if (this.threshScalarMulSession) {
            this.threshScalarMulSession.encode(serializer);
        }
        serializer.serializeVector(this.culprits);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.encode(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
    
    reencrypt(): {recipientPrivateState: RecipientPrivateState, verifiableReencryption: VerifiableReencryption} {
        const t = Group.Scalar.rand();
        const u = Group.Scalar.rand();
        const th = this.card.encBase.scale(t);
        const tsh = this.secretInfo.agg_ek.publicPoint.scale(t);
        const rth = this.card.c0.add(th);
        const urth = rth.scale(u);
        const trx = new Transcript();
        const proof_t = SigmaDlogEq.prove(trx, this.card.encBase, th, this.secretInfo.agg_ek.publicPoint, tsh, t);
        const proof_u = SigmaDlog.prove(trx, rth, urth, u);
        const recipientPrivateState = new RecipientPrivateState(u);
        const verifiableReencryption = new VerifiableReencryption(th, tsh, urth, proof_t, proof_u);
        return {recipientPrivateState, verifiableReencryption};
    }
}
