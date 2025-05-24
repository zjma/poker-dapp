import * as Elgamal from './elgamal';
import * as PedersenCommitment from './pedersenCommitment';
import { AccountAddress, Deserializer, Serializer } from '@aptos-labs/ts-sdk';
import * as Group from './group';
import { bytesToHex } from '@noble/hashes/utils';
import * as BG12 from './bg12';

export const STATE__ACCEPTING_CONTRIBUTION: number = 1;
export const STATE__SUCCEEDED: number = 2;
export const STATE__FAILED: number = 3;

export class VerifiableContribution {
    newCiphertexts: Elgamal.Ciphertext[];
    proof: BG12.Proof | null;

    constructor(newCiphertexts: Elgamal.Ciphertext[], proof: BG12.Proof | null) {
        this.newCiphertexts = newCiphertexts;
        this.proof = proof;
    }

    static decode(deserializer: Deserializer): VerifiableContribution {
        const numCiphertexts = deserializer.deserializeUleb128AsU32();
        const newCiphertexts = new Array<Elgamal.Ciphertext>(numCiphertexts);
        for (let i = 0; i < numCiphertexts; i++) {
            newCiphertexts[i] = Elgamal.Ciphertext.decode(deserializer);
        }
        const hasProof = deserializer.deserializeU8();
        const proof = hasProof ? BG12.Proof.decode(deserializer) : null;
        return new VerifiableContribution(newCiphertexts, proof);
    }

    encode(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.newCiphertexts.length);
        for (let i = 0; i < this.newCiphertexts.length; i++) {
            this.newCiphertexts[i].encode(serializer);
        }
        serializer.serializeU8(this.proof == null ? 0 : 1);
        if (this.proof != null) {
            this.proof.encode(serializer);
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


export class SessionBrief {
    addr: AccountAddress;
    encKey: Elgamal.EncKey;
    pedersenCtxt: PedersenCommitment.Context;
    allowedContributors: AccountAddress[];
    deadlines: number[];
    status: number;
    expectedContributorIdx: number;
    lastCiphertexts: Elgamal.Ciphertext[];

    constructor(addr: AccountAddress, encKey: Elgamal.EncKey, pedersenCtxt: PedersenCommitment.Context, allowedContributors: AccountAddress[], deadlines: number[], status: number, expectedContributorIdx: number, lastCiphertexts: Elgamal.Ciphertext[]) {
        this.addr = addr;
        this.encKey = encKey;
        this.pedersenCtxt = pedersenCtxt;
        this.allowedContributors = allowedContributors;
        this.deadlines = deadlines;
        this.status = status;
        this.expectedContributorIdx = expectedContributorIdx;
        this.lastCiphertexts = lastCiphertexts;
    }

    static decode(deserializer: Deserializer): SessionBrief {
        const addr = deserializer.deserialize(AccountAddress);
        const encKey = Elgamal.EncKey.decode(deserializer);
        const pedersenCtxt = PedersenCommitment.Context.decode(deserializer);
        const allowedContributors = deserializer.deserializeVector(AccountAddress);

        const numDeadlines = deserializer.deserializeUleb128AsU32();
        const deadlines = new Array<number>(numDeadlines);
        for (let i = 0; i < numDeadlines; i++) {
            deadlines[i] = Number(deserializer.deserializeU64());
        }

        const status = Number(deserializer.deserializeU64());
        const expectedContributorIdx = Number(deserializer.deserializeU64());

        const numLastCiphertexts = deserializer.deserializeUleb128AsU32();
        const lastCiphertexts = new Array<Elgamal.Ciphertext>(numLastCiphertexts);
        for (let i = 0; i < numLastCiphertexts; i++) {
            lastCiphertexts[i] = Elgamal.Ciphertext.decode(deserializer);
        }

        return new SessionBrief(addr, encKey, pedersenCtxt, allowedContributors, deadlines, status, expectedContributorIdx, lastCiphertexts);
    }

    nextToContribute(): AccountAddress {
        return this.allowedContributors[this.expectedContributorIdx];
    }

    generateContribution(): VerifiableContribution {
        const n = this.lastCiphertexts.length;

        // Random permutation.
        const permutation = Array.from({ length: n }, (_, i) => i);
        for (let i = n-1; i >= 0 ; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            const tmp = permutation[i];
            permutation[i] = permutation[j];
            permutation[j] = tmp;
        }

        // Re-randomizers.
        const rerandomizers = Array.from({ length: n }, (_) => Group.Scalar.rand());

        const newCiphs = Array.from({ length: n }, (_, i) => {
            let blinder = Elgamal.enc(this.encKey, rerandomizers[i], Group.Element.groupIdentity());
            return this.lastCiphertexts[permutation[i]].add(blinder);
        });

        // const trx = new Transcript();
        // const proof = BG12.prove(this.encKey, this.pedersenCtxt, trx, curCiphs, newCiphs, permutation, rerandomizers); // 1.5s
        return new VerifiableContribution(newCiphs, null);
    }
}
