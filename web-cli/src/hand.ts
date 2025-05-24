import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk";
import * as DKG from "./crypto/dkg_v0";
import * as ThresholdScalarMul from "./crypto/threshold_scalar_mul";
import * as Reencryption from "./crypto/reencryption";
import * as Group from "./crypto/group";
import * as ElGamal from "./crypto/elgamal";

export const STATE__DEALING_PRIVATE_CARDS: number = 140658;
export const STATE__PLAYER_BETTING: number = 140855;
export const STATE__OPENING_COMMUNITY_CARDS: number = 141022;
export const STATE__SHOWDOWN: number = 141414;
export const STATE__SUCCEEDED: number = 141628;
export const STATE__FAILED: number = 141629;
export const CARD__UNREVEALED: number = 0xffffffff;

export class SessionBrief {
    addr: AccountAddress;
    players: AccountAddress[]; // [btn, sb, bb, ...]
    secretInfo: DKG.SharedSecretPublicInfo;
    expectedSmallBlind: number;
    expectedBigBlind: number;
    cardReprs: Group.Element[];
    shuffledDeck: ElGamal.Ciphertext[];
    chipsInHand: number[];
    bets: number[];
    foldStatuses: boolean[];
    minRaiseStep: number;
    revealedPrivateCards: number[];
    state: number;
    currentActionPlayerIdx: number;
    currentActionDeadline: number;
    currentActionCompleted: boolean;
    completedActionIsRaise: boolean;
    privateDealingSessions: Reencryption.SessionBrief[];
    publicOpeningSessions: ThresholdScalarMul.SessionBrief[];
    publiclyOpenedCards: number[];

    constructor(addr: AccountAddress, players: AccountAddress[], secretInfo: DKG.SharedSecretPublicInfo, expectedSmallBlind: number, expectedBigBlind: number, cardReprs: Group.Element[], shuffledDeck: ElGamal.Ciphertext[], chipsInHand: number[], bets: number[], foldStatuses: boolean[], minRaiseStep: number, revealedPrivateCards: number[], state: number, currentActionPlayerIdx: number, currentActionDeadline: number, currentActionCompleted: boolean, completedActionIsRaise: boolean, privateDealingSessions: Reencryption.SessionBrief[], publicOpeningSessions: ThresholdScalarMul.SessionBrief[], publiclyOpenedCards: number[]) {
        this.addr = addr;
        this.players = players;
        this.secretInfo = secretInfo;
        this.expectedSmallBlind = expectedSmallBlind;
        this.expectedBigBlind = expectedBigBlind;
        this.cardReprs = cardReprs;
        this.shuffledDeck = shuffledDeck;
        this.chipsInHand = chipsInHand;
        this.bets = bets;
        this.foldStatuses = foldStatuses;
        this.minRaiseStep = minRaiseStep;
        this.revealedPrivateCards = revealedPrivateCards;
        this.state = state;
        this.currentActionPlayerIdx = currentActionPlayerIdx;
        this.currentActionDeadline = currentActionDeadline;
        this.currentActionCompleted = currentActionCompleted;
        this.completedActionIsRaise = completedActionIsRaise;
        this.privateDealingSessions = privateDealingSessions;
        this.publicOpeningSessions = publicOpeningSessions;
        this.publiclyOpenedCards = publiclyOpenedCards;
    }

    static decode(deserializer: Deserializer): SessionBrief {
        const addr = deserializer.deserialize(AccountAddress);
        const players = deserializer.deserializeVector(AccountAddress);
        const secretInfo = DKG.SharedSecretPublicInfo.decode(deserializer);
        const expectedSmallBlind = Number(deserializer.deserializeU64());
        const expectedBigBlind = Number(deserializer.deserializeU64());
        const cardReprs = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Group.Element.decode(deserializer));
        const shuffledDeck = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => ElGamal.Ciphertext.decode(deserializer));
        const chipsInHand = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        const bets = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        const foldStatuses = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => deserializer.deserializeBool());
        const minRaiseStep = Number(deserializer.deserializeU64());
        const revealedPrivateCards = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        const state = Number(deserializer.deserializeU64());
        const currentActionPlayerIdx = Number(deserializer.deserializeU64());
        const currentActionDeadline = Number(deserializer.deserializeU64());
        const currentActionCompleted = deserializer.deserializeBool();
        const completedActionIsRaise = deserializer.deserializeBool();
        const privateDealingSessions = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Reencryption.SessionBrief.decode(deserializer));
        const publicOpeningSessions = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => ThresholdScalarMul.SessionBrief.decode(deserializer));
        const publiclyOpenedCards = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        return new SessionBrief(addr, players, secretInfo, expectedSmallBlind, expectedBigBlind, cardReprs, shuffledDeck, chipsInHand, bets, foldStatuses, minRaiseStep, revealedPrivateCards, state, currentActionPlayerIdx, currentActionDeadline, currentActionCompleted, completedActionIsRaise, privateDealingSessions, publicOpeningSessions, publiclyOpenedCards);
    }
}