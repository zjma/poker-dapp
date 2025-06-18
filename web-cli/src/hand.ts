import { AccountAddress, Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import * as DKG from "./crypto/dkg_v0";
import * as ThresholdScalarMul from "./crypto/threshold_scalar_mul";
import * as Reencryption from "./crypto/reencryption";
import * as Group from "./crypto/group";
import * as ElGamal from "./crypto/elgamal";
import { bytesToHex } from "@noble/hashes/utils";

export const STATE__DEALING_PRIVATE_CARDS: number = 140658;
export const STATE__PLAYER_BETTING: number = 140855;
export const STATE__OPENING_COMMUNITY_CARDS: number = 141022;
export const STATE__SHOWDOWN: number = 141414;
export const STATE__SUCCEEDED: number = 141628;
export const STATE__FAILED: number = 141629;
export const CARD__UNREVEALED: number = 0xffffffff;

export const PLAYER_STATE__ACTIVE: number = 614544;
export const PLAYER_STATE__FOLDED: number = 614545;
export const PLAYER_STATE__CHECKED: number = 614546;
export const PLAYER_STATE__CALLED: number = 614547;
export const PLAYER_STATE__BET: number = 614548;
export const PLAYER_STATE__RAISED: number = 614549;
export const PLAYER_STATE__ALL_IN: number = 614550;

export class SessionBrief {
    idxByAddr(addr: AccountAddress): number | null {
        const idx = this.players.findIndex(player => player.toString() == addr.toString());
        return idx == -1 ? null : idx;
    }

    minRaiseStep(): number {
        return this.nextRaiseThreshold - this.lastRaise;
    }
    addr_owner: AccountAddress;
    addr_self: AccountAddress;
    players: AccountAddress[]; // [btn, sb, bb, ...]
    secretInfo: DKG.SharedSecretPublicInfo;
    expectedSmallBlind: number;
    expectedBigBlind: number;
    cardReprs: Group.Element[];
    shuffledDeck: ElGamal.Ciphertext[];
    chipsInHand: number[];
    bets: number[];
    playerStates: number[];
    callTarget: number;
    lastRaise: number;
    nextRaiseThreshold: number;
    revealedPrivateCards: number[];
    state: number;
    expectingActionFrom: number | null;
    privateDealingSessions: Reencryption.SessionBrief[];
    publicOpeningSessions: ThresholdScalarMul.SessionBrief[];
    publiclyOpenedCards: number[];

    constructor(addr_owner: AccountAddress, addr_self: AccountAddress, players: AccountAddress[], secretInfo: DKG.SharedSecretPublicInfo, expectedSmallBlind: number, expectedBigBlind: number, cardReprs: Group.Element[], shuffledDeck: ElGamal.Ciphertext[], chipsInHand: number[], bets: number[], playerStates: number[], callTarget: number, lastRaise: number, nextRaiseThreshold: number, expectingActionFrom: number | null, revealedPrivateCards: number[], state: number, privateDealingSessions: Reencryption.SessionBrief[], publicOpeningSessions: ThresholdScalarMul.SessionBrief[], publiclyOpenedCards: number[]) {
        this.addr_owner = addr_owner;
        this.addr_self = addr_self;
        this.players = players;
        this.secretInfo = secretInfo;
        this.expectedSmallBlind = expectedSmallBlind;
        this.expectedBigBlind = expectedBigBlind;
        this.cardReprs = cardReprs;
        this.shuffledDeck = shuffledDeck;
        this.chipsInHand = chipsInHand;
        this.bets = bets;
        this.playerStates = playerStates;
        this.callTarget = callTarget;
        this.lastRaise = lastRaise;
        this.nextRaiseThreshold = nextRaiseThreshold;
        this.revealedPrivateCards = revealedPrivateCards;
        this.state = state;
        this.expectingActionFrom = expectingActionFrom;
        this.privateDealingSessions = privateDealingSessions;
        this.publicOpeningSessions = publicOpeningSessions;
        this.publiclyOpenedCards = publiclyOpenedCards;
    }

    static decode(deserializer: Deserializer): SessionBrief {
        const addr_owner = deserializer.deserialize(AccountAddress);
        const addr_self = deserializer.deserialize(AccountAddress);
        const players = deserializer.deserializeVector(AccountAddress);
        const secretInfo = DKG.SharedSecretPublicInfo.decode(deserializer);
        const expectedSmallBlind = Number(deserializer.deserializeU64());
        const expectedBigBlind = Number(deserializer.deserializeU64());
        const cardReprs = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Group.Element.decode(deserializer));
        const shuffledDeck = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => ElGamal.Ciphertext.decode(deserializer));
        const chipsInHand = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        const bets = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        const playerStates = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        const callTarget = Number(deserializer.deserializeU64());
        const lastRaise = Number(deserializer.deserializeU64());
        const nextRaiseThreshold = Number(deserializer.deserializeU64());
        const revealedPrivateCards = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        const state = Number(deserializer.deserializeU64());
        const expectingActionFrom = deserializer.deserializeU8() == 0 ? null : Number(deserializer.deserializeU64());
        const privateDealingSessions = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Reencryption.SessionBrief.decode(deserializer));
        const publicOpeningSessions = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => ThresholdScalarMul.SessionBrief.decode(deserializer));
        const publiclyOpenedCards = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        return new SessionBrief(addr_owner, addr_self, players, secretInfo, expectedSmallBlind, expectedBigBlind, cardReprs, shuffledDeck, chipsInHand, bets, playerStates, callTarget, lastRaise, nextRaiseThreshold, expectingActionFrom, revealedPrivateCards, state, privateDealingSessions, publicOpeningSessions, publiclyOpenedCards);
    }

    
    encode(serializer: Serializer) {
        serializer.serialize(this.addr_owner);
        serializer.serialize(this.addr_self);
        serializer.serializeVector(this.players);
        this.secretInfo.encode(serializer);
        serializer.serializeU64(this.expectedSmallBlind);
        serializer.serializeU64(this.expectedBigBlind);
        serializer.serializeU32AsUleb128(this.cardReprs.length);
        for (const cardRepr of this.cardReprs) {
            cardRepr.encode(serializer);
        }
        serializer.serializeU32AsUleb128(this.shuffledDeck.length);
        for (const ciphertext of this.shuffledDeck) {
            ciphertext.encode(serializer);
        }
        serializer.serializeU32AsUleb128(this.chipsInHand.length);
        for (const chip of this.chipsInHand) {
            serializer.serializeU64(chip);
        }
        serializer.serializeU32AsUleb128(this.bets.length);
        for (const bet of this.bets) {
            serializer.serializeU64(bet);
        }
        serializer.serializeU32AsUleb128(this.playerStates.length);
        for (const playerState of this.playerStates) {
            serializer.serializeU64(playerState);
        }
        serializer.serializeU64(this.callTarget);
        serializer.serializeU64(this.lastRaise);
        serializer.serializeU64(this.nextRaiseThreshold);

        serializer.serializeU32AsUleb128(this.revealedPrivateCards.length);
        for (const card of this.revealedPrivateCards) {
            serializer.serializeU64(card);
        }

        serializer.serializeU64(this.state);

        serializer.serializeU8(this.expectingActionFrom == null ? 0 : 1);
        if (this.expectingActionFrom != null) {
            serializer.serializeU64(this.expectingActionFrom);
        }

        serializer.serializeU32AsUleb128(this.privateDealingSessions.length);
        for (const session of this.privateDealingSessions) {
            session.encode(serializer);
        }
        serializer.serializeU32AsUleb128(this.publicOpeningSessions.length);
        for (const session of this.publicOpeningSessions) {
            session.encode(serializer);
        }
        serializer.serializeU32AsUleb128(this.publiclyOpenedCards.length);
        for (const card of this.publiclyOpenedCards) {
            serializer.serializeU64(card);
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

    getLastActionText(idxInHand: number): string {
        if (this.playerStates[idxInHand] == PLAYER_STATE__FOLDED) {
            return 'FOLD';
        } else if (this.playerStates[idxInHand] == PLAYER_STATE__CHECKED) {
            return 'CHECK';
        } else if (this.playerStates[idxInHand] == PLAYER_STATE__CALLED) {
            return 'CALL';
        } else if (this.playerStates[idxInHand] == PLAYER_STATE__BET) {
            return 'BET';
        } else if (this.playerStates[idxInHand] == PLAYER_STATE__RAISED) {
            return 'RAISE';
        } else if (this.playerStates[idxInHand] == PLAYER_STATE__ALL_IN) {
            return 'ALL IN';
        } else {
            return '🤔';
        }
    }

    hasActed(idxInHand: number): boolean {
        return this.playerStates[idxInHand] != PLAYER_STATE__ACTIVE;
    }
}
