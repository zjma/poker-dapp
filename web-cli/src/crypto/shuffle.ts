import * as Elgamal from './elgamal';
import * as PedersenCommitment from './pedersenCommitment';
import * as SigmaDLog from './sigma_dlog';
import { AccountAddress, Deserializer, Serializer } from '@aptos-labs/ts-sdk';
import * as Group from './group';

function range(start: number, end: number): number[] {
    return Array.from({ length: end - start }, (_, i) => i + start);
}

export class VerifiableContribution {
    newCiphertexts: Elgamal.Ciphertext[];
    proof: SigmaDLog.Proof | null;

    constructor(newCiphertexts: Elgamal.Ciphertext[], proof: SigmaDLog.Proof | null) {
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
        const proof = hasProof ? SigmaDLog.Proof.decode(deserializer) : null;
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
}


export class Session {
    encKey: Elgamal.EncKey;
    pedersenCtxt: PedersenCommitment.Context;
    initialCiphertexts: Elgamal.Ciphertext[];
    allowedContributors: AccountAddress[];
    numContributionsExpected: number;
    deadlines: number[];
    status: number;
    expectedContributorIdx: number;
    contributions: VerifiableContribution[];
    culprit: AccountAddress | null;

    constructor(encKey: Elgamal.EncKey, pedersenCtxt: PedersenCommitment.Context, initialCiphertexts: Elgamal.Ciphertext[], allowedContributors: AccountAddress[], numContributionsExpected: number, deadlines: number[], status: number, expectedContributorIdx: number, contributions: VerifiableContribution[], culprit: AccountAddress | null) {
        this.encKey = encKey;
        this.pedersenCtxt = pedersenCtxt;
        this.initialCiphertexts = initialCiphertexts;
        this.allowedContributors = allowedContributors;
        this.numContributionsExpected = numContributionsExpected;
        this.deadlines = deadlines;
        this.status = status;
        this.expectedContributorIdx = expectedContributorIdx;
        this.contributions = contributions;
        this.culprit = culprit;
    }

    static decode(deserializer: Deserializer): Session {
        const encKey = Elgamal.EncKey.decode(deserializer);
        const pedersenCtxt = PedersenCommitment.Context.decode(deserializer);
        const numInitialCiphertexts = deserializer.deserializeUleb128AsU32();
        const initialCiphertexts = new Array<Elgamal.Ciphertext>(numInitialCiphertexts);
        for (let i = 0; i < numInitialCiphertexts; i++) {
            initialCiphertexts[i] = Elgamal.Ciphertext.decode(deserializer);
        }
        const allowedContributors = deserializer.deserializeVector(AccountAddress);

        const numContributionsExpected = deserializer.deserializeUleb128AsU32();

        const numDeadlines = deserializer.deserializeUleb128AsU32();
        const deadlines = new Array<number>(numDeadlines);
        for (let i = 0; i < numDeadlines; i++) {
            deadlines[i] = Number(deserializer.deserializeU64());
        }

        const status = Number(deserializer.deserializeU64());
        const expectedContributorIdx = deserializer.deserializeUleb128AsU32();

        const numContributions = deserializer.deserializeUleb128AsU32();
        const contributions = new Array<VerifiableContribution>(numContributions);
        for (let i = 0; i < numContributions; i++) {
            contributions[i] = VerifiableContribution.decode(deserializer);
        }

        const culprit = deserializer.deserializeOption(AccountAddress) ?? null;

        return new Session(encKey, pedersenCtxt, initialCiphertexts, allowedContributors, numContributionsExpected, deadlines, status, expectedContributorIdx, contributions, culprit);
    }

    nextToContribute(): AccountAddress {
        const numContributionsReceived = this.contributions.length;
        return this.allowedContributors[numContributionsReceived];
    }

    generateContribution(): VerifiableContribution {
        const newCiphertexts = this.expectedContributorIdx == 0 ? this.initialCiphertexts : this.contributions[this.contributions.length - 1].newCiphertexts;

        // Permute
        const n = newCiphertexts.length;
        for (let i = n-1; i >= 0 ; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            const tmp = newCiphertexts[i];
            newCiphertexts[i] = newCiphertexts[j];
            newCiphertexts[j] = tmp;
        }

        // Re-randomize
        const rerandomizers = Array.from({ length: n }, (_) => Group.Scalar.rand());
        for (let i = 0; i < newCiphertexts.length; i++) {
            const blinder = Elgamal.enc(this.encKey, rerandomizers[i], Group.Element.groupIdentity());
            newCiphertexts[i] = newCiphertexts[i].add(blinder);
        }

        return new VerifiableContribution(newCiphertexts, null);
    }
}
