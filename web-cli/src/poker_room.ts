import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk"
import { DKGSession } from "./crypto/dkg_v0";
import * as Hand from "./hand";
import * as Deckgen from "./deck_gen";

export class PokerRoomStateBrief {
    expectedPlayerAddresses: AccountAddress[];
    playerLivenesses: boolean[];
    playerChips: number[];
    lastButtonPosition: number;
    state: number;
    curHand: Hand.Session | null;
    numHandsDone: number;
    numDKGsDone: number;
    numDeckgensDone: number;
    curDKGSession: DKGSession | null;
    curDeckgenSession: Deckgen.Session | null;
    
    constructor(expectedPlayerAddresses: AccountAddress[], playerLivenesses: boolean[], playerChips: number[], lastButtonPosition: number, state: number, curHand: Hand.Session | null, numHandsDone: number, numDKGsDone: number, numDeckgensDone: number, curDKGSession: DKGSession | null, curDeckgenSession: Deckgen.Session | null) {
        this.expectedPlayerAddresses = expectedPlayerAddresses;
        this.playerLivenesses = playerLivenesses;
        this.playerChips = playerChips;
        this.lastButtonPosition = lastButtonPosition;
        this.state = state;
        this.curHand = curHand;
        this.numHandsDone = numHandsDone;
        this.numDKGsDone = numDKGsDone;
        this.numDeckgensDone = numDeckgensDone;
        this.curDKGSession = curDKGSession;
        this.curDeckgenSession = curDeckgenSession;
    }

    static decode(deserializer: Deserializer): PokerRoomStateBrief {
        const expectedPlayerAddresses = deserializer.deserializeVector(AccountAddress);

        const numPlayerLivenesses = deserializer.deserializeUleb128AsU32();
        const playerLivenesses = new Array<boolean>(numPlayerLivenesses);
        for (let i = 0; i < numPlayerLivenesses; i++) {
            playerLivenesses[i] = deserializer.deserializeBool();
        }

        const numPlayerChips = deserializer.deserializeUleb128AsU32();
        const playerChips = new Array<number>(numPlayerChips);  
        for (let i = 0; i < numPlayerChips; i++) {
            playerChips[i] = Number(deserializer.deserializeU64());
        }

        const lastButtonPosition = Number(deserializer.deserializeU64());
        const state = Number(deserializer.deserializeU64());

        const hasCurHand = deserializer.deserializeU8();
        const curHand = hasCurHand > 0 ? Hand.Session.decode(deserializer) : null;

        const numHandsDone = Number(deserializer.deserializeU64());
        const numDKGsDone = Number(deserializer.deserializeU64());
        const numDeckgensDone = Number(deserializer.deserializeU64());

        const hasCurDKGSession = deserializer.deserializeU8();
        const curDKGSession = hasCurDKGSession > 0 ? DKGSession.decode(deserializer) : null;

        const hasCurDeckgenSession = deserializer.deserializeU8();
        const curDeckgenSession = hasCurDeckgenSession > 0 ? Deckgen.Session.decode(deserializer) : null;

        return new PokerRoomStateBrief(expectedPlayerAddresses, playerLivenesses, playerChips, lastButtonPosition, state, curHand, numHandsDone, numDKGsDone, numDeckgensDone, curDKGSession, curDeckgenSession);
    }
    
}