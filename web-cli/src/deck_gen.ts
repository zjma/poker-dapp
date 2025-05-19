import { AccountAddress, Deserializer } from '@aptos-labs/ts-sdk';
import * as Shuffle from './crypto/shuffle';
import * as Group from './crypto/group';

import * as ElGamal from './crypto/elgamal';
export class Session {
    aggEk: ElGamal.EncKey;
    allowedContributors: AccountAddress[] | null;
    cardReprs: Group.Element[];
    initialCiphertexts: ElGamal.Ciphertext[];
    shuffle: Shuffle.Session | null;

    constructor(aggEk: ElGamal.EncKey, allowedContributions: AccountAddress[] | null, cardReprs: Group.Element[], initialCiphertexts: ElGamal.Ciphertext[], shuffle: Shuffle.Session | null) {
        this.aggEk = aggEk;
        this.allowedContributors = allowedContributions;
        this.cardReprs = cardReprs;
        this.initialCiphertexts = initialCiphertexts;
        this.shuffle = shuffle;
    }

    static decode(deserializer: Deserializer): Session {
        const aggEk = ElGamal.EncKey.decode(deserializer);

        const allowedContributors = deserializer.deserializeVector(AccountAddress);
        
        const numCardReprs = deserializer.deserializeUleb128AsU32();
        const cardReprs = new Array<Group.Element>(numCardReprs);
        for (let i = 0; i < numCardReprs; i++) {
            cardReprs[i] = Group.Element.decode(deserializer);
        }

        const numInitialCiphertexts = deserializer.deserializeUleb128AsU32();
        const initialCiphertexts = new Array<ElGamal.Ciphertext>(numInitialCiphertexts);
        for (let i = 0; i < numInitialCiphertexts; i++) {
            initialCiphertexts[i] = ElGamal.Ciphertext.decode(deserializer);
        }

        const hasShuffle = deserializer.deserializeU8() === 1;
        const shuffle = hasShuffle ? Shuffle.Session.decode(deserializer) : null;
        
        return new Session(aggEk, allowedContributors, cardReprs, initialCiphertexts, shuffle);
    }
}