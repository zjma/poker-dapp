import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk"
import * as Hand from "./hand";
import * as Deckgen from "./deck_gen";
import * as DKG from "./crypto/dkg_v0";

export const STATE__WAITING_FOR_PLAYERS: number = 1;
export const STATE__DKG_IN_PROGRESS: number = 2;
export const STATE__DECKGEN_IN_PROGRESS: number = 3;
export const STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS: number = 4;
export const STATE__CLOSED: number = 5;

export class SessionBrief {
    canJoin(accountAddress: AccountAddress): boolean {
        const myIdxInRoom = this.expectedPlayerAddresses.findIndex(addr => addr.toString() == accountAddress.toString());
        if (myIdxInRoom == -1) return false;
        if (this.playerLivenesses[myIdxInRoom]) return false;
        if (this.state != STATE__WAITING_FOR_PLAYERS && this.playerChips[myIdxInRoom] == 0) return false;
        return true;
    }

    hasCompetitor(accountAddress: AccountAddress): boolean {
        return this.expectedPlayerAddresses.some(addr => addr.equals(accountAddress));
    }

    addr: AccountAddress;
    expectedPlayerAddresses: AccountAddress[];
    playerLivenesses: boolean[];
    playerChips: number[];
    lastButtonPosition: number;
    state: number;
    curHand: Hand.SessionBrief | null;
    numHandsDone: number;
    numDKGsDone: number;
    numDeckgensDone: number;
    curDKGSession: DKG.SessionBrief | null;
    curDeckgenSession: Deckgen.SessionBrief | null;
    
    constructor(addr: AccountAddress, expectedPlayerAddresses: AccountAddress[], playerLivenesses: boolean[], playerChips: number[], lastButtonPosition: number, state: number, curHand: Hand.SessionBrief | null, numHandsDone: number, numDKGsDone: number, numDeckgensDone: number, curDKGSession: DKG.SessionBrief | null, curDeckgenSession: Deckgen.SessionBrief | null) {
        this.addr = addr;
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

    static decode(deserializer: Deserializer): SessionBrief {
        const addr = deserializer.deserialize(AccountAddress);
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
        const curHand = hasCurHand > 0 ? Hand.SessionBrief.decode(deserializer) : null;

        const numHandsDone = Number(deserializer.deserializeU64());
        const numDKGsDone = Number(deserializer.deserializeU64());
        const numDeckgensDone = Number(deserializer.deserializeU64());

        const hasCurDKGSession = deserializer.deserializeU8();
        const curDKGSession = hasCurDKGSession > 0 ? DKG.SessionBrief.decode(deserializer) : null;

        const hasCurDeckgenSession = deserializer.deserializeU8();
        const curDeckgenSession = hasCurDeckgenSession > 0 ? Deckgen.SessionBrief.decode(deserializer) : null;

        return new SessionBrief(addr, expectedPlayerAddresses, playerLivenesses, playerChips, lastButtonPosition, state, curHand, numHandsDone, numDKGsDone, numDeckgensDone, curDKGSession, curDeckgenSession);
    }   
}
