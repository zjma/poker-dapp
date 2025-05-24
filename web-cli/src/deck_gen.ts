import { AccountAddress, Deserializer } from '@aptos-labs/ts-sdk';
import * as Shuffle from './crypto/shuffle';

export class SessionBrief {
    addr: AccountAddress;
    shuffle: Shuffle.SessionBrief;

    constructor(addr: AccountAddress, shuffle: Shuffle.SessionBrief) {
        this.addr = addr;
        this.shuffle = shuffle;
    }

    static decode(deserializer: Deserializer): SessionBrief {
        const addr = deserializer.deserialize(AccountAddress);
        const shuffle = Shuffle.SessionBrief.decode(deserializer);
        return new SessionBrief(addr, shuffle);
    }
}
