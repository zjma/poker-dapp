import { Deserializer } from '@aptos-labs/ts-sdk';
import * as Shuffle from './crypto/shuffle';

export class Session {
    shuffle: Shuffle.Session;

    constructor(shuffle: Shuffle.Session) {
        this.shuffle = shuffle;
    }

    static decode(deserializer: Deserializer): Session {
        console.log(`remaining for deckgen: ${deserializer.remaining()}`);
        const shuffle = Shuffle.Session.decode(deserializer);
        return new Session(shuffle);
    }
}
