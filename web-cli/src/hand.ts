import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk";
import * as DKG from "./crypto/dkg_v0";
import * as Elgamal from "./crypto/elgamal";
import * as Group from "./crypto/group";
import * as Shuffle from "./crypto/shuffle";
import * as ThresholdScalarMul from "./crypto/threshold_scalar_mul";
import * as Reencryption from "./crypto/reencryption";

export const STATE__DEALING_PRIVATE_CARDS = 140658;
export const STATE__PLAYER_BETTING = 140855;
export const STATE__OPENING_COMMUNITY_CARDS = 141022;
export const STATE__SHOWDOWN = 141414;
export const STATE__SUCCEEDED = 141628;
export const STATE__FAILED = 141629;

export class Session {
    numPlayers: number;
    players: AccountAddress[]; // [btn, sb, bb, ...]
    secretInfo: DKG.SharedSecretPublicInfo;
    expectedSmallBlind: number;
    expectedBigBlind: number;

    /// The randomly chosen group elements that represent:
    /// Spade-A, Spade-2, ..., Spade-K, Heart-A, ..., Heart-K, Diamond-A, ... Diamond-K, Club-A, ..., Club-K,
    /// respectively.
    cardReps: Group.Element[];
    /// Cards at position [2*i, 1+2*i] will be cards dealt to player i (referred to as "having destintation i").
    /// Cards at posit
    /// ions [2*n, 2*n+4] will be community cards (referred to as "having destintation community").
    /// The remaining cards is referred to as having a void destination.
    shuffledDeck: Elgamal.Ciphertext[];

    /// Chips still available in player `i`'s hand.
    /// For any `i`, `chips_in_hand[i] + bets[i]` is a constant before the winner decision.
    chipsInHand: number[];

    /// Chips that player `i` has put in all pots.
    /// For any `i`, `chips_in_hand[i] + bets[i]` is a constant before the winner decision.
    bets: number[];

    /// Whether player `i` has folded.
    foldStatuses: boolean[];

    /// In a betting phase, `no_more_action_needed[i]` indicates whether we need to ask player `i` for bet actions.
    /// At the beginning of a betting phase, `no_more_action_needed[i]` is initialized to `false` for all `i`.
    /// When player `i` correctly checks/calls/bets/raises, `no_more_action_needed[i]` is set to `true`.
    /// Additonally, when player `i` bets/raises, for every `j!=i`, `no_more_action_needed[j]` is reset to `false`.
    /// When `no_more_action_needed[i]` is true for everyone that is still in, the betting round is completed.
    noMoreActionNeeded: boolean[];

    /// In a betting phase, this indicates the minimum raise.
    minRaiseStep: number;

    /// Private cards revealed at showdown phase are saved here.
    revealedPrivateCards: number[];

    state: number;

    /// When `state == STATE__PHASE_*_BET_BY_PLAYER_X_BEFORE_Y`, indicate `X`.
    currentActionPlayerIdx: number;
    /// When `state == STATE__PHASE_*_BET_BY_PLAYER_X_BEFORE_Y`, indicate `Y`.
    currentActionDeadline: number;
    /// When `state == STATE__PHASE_*_BET_BY_PLAYER_X_BEFORE_Y`, indicate whether player `X` has taken the expected action.
    currentActionCompleted: boolean;
    completedActionIsRaise: boolean;
    /// When `state == STATE__FAILED`, indicates who misbehaved.
    blames: boolean[];
    privateDealingSessions: Reencryption.Session[];
    publicOpeningSessions: ThresholdScalarMul.Session[];
    publiclyOpenedCards: number[];

    constructor(numPlayers: number, players: AccountAddress[], secretInfo: DKG.SharedSecretPublicInfo, expectedSmallBlind: number, expectedBigBlind: number, cardReps: Group.Element[], shuffledDeck: Elgamal.Ciphertext[], chipsInHand: number[], bets: number[], foldStatuses: boolean[], noMoreActionNeeded: boolean[], minRaiseStep: number, revealedPrivateCards: number[], state: number, currentActionPlayerIdx: number, currentActionDeadline: number, currentActionCompleted: boolean, completedActionIsRaise: boolean, blames: boolean[], privateDealingSessions: Reencryption.Session[], publicOpeningSessions: ThresholdScalarMul.Session[], publiclyOpenedCards: number[]) {
        this.numPlayers = numPlayers;
        this.players = players;
        this.secretInfo = secretInfo;
        this.expectedSmallBlind = expectedSmallBlind;
        this.expectedBigBlind = expectedBigBlind;
        this.cardReps = cardReps;
        this.shuffledDeck = shuffledDeck;
        this.chipsInHand = chipsInHand;
        this.bets = bets;
        this.foldStatuses = foldStatuses;
        this.noMoreActionNeeded = noMoreActionNeeded;
        this.minRaiseStep = minRaiseStep;
        this.revealedPrivateCards = revealedPrivateCards;
        this.state = state;
        this.currentActionPlayerIdx = currentActionPlayerIdx;
        this.currentActionDeadline = currentActionDeadline;
        this.currentActionCompleted = currentActionCompleted;
        this.completedActionIsRaise = completedActionIsRaise;
        this.blames = blames;
        this.privateDealingSessions = privateDealingSessions;
        this.publicOpeningSessions = publicOpeningSessions;
        this.publiclyOpenedCards = publiclyOpenedCards;
    }

    static decode(deserializer: Deserializer): Session {
        const numPlayers = Number(deserializer.deserializeU64());
        const players = deserializer.deserializeVector(AccountAddress);
        const secretInfo = DKG.SharedSecretPublicInfo.decode(deserializer);
        const expectedSmallBlind = Number(deserializer.deserializeU64());
        const expectedBigBlind = Number(deserializer.deserializeU64());
        const cardReps = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Group.Element.decode(deserializer));
        const shuffledDeck = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Elgamal.Ciphertext.decode(deserializer));
        const chipsInHand = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        const bets = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        const foldStatuses = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => deserializer.deserializeBool());
        const noMoreActionNeeded = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => deserializer.deserializeBool());
        const minRaiseStep = Number(deserializer.deserializeU64());
        const revealedPrivateCards = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        const state = Number(deserializer.deserializeU64());
        const currentActionPlayerIdx = Number(deserializer.deserializeU64());
        const currentActionDeadline = Number(deserializer.deserializeU64());
        const currentActionCompleted = deserializer.deserializeBool();
        const completedActionIsRaise = deserializer.deserializeBool();
        const blames = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => deserializer.deserializeBool());
        const privateDealingSessions = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Reencryption.Session.decode(deserializer));
        const publicOpeningSessions = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => ThresholdScalarMul.Session.decode(deserializer));
        const publiclyOpenedCards = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Number(deserializer.deserializeU64()));
        return new Session(numPlayers, players, secretInfo, expectedSmallBlind, expectedBigBlind, cardReps, shuffledDeck, chipsInHand, bets, foldStatuses, noMoreActionNeeded, minRaiseStep, revealedPrivateCards, state, currentActionPlayerIdx, currentActionDeadline, currentActionCompleted, completedActionIsRaise, blames, privateDealingSessions, publicOpeningSessions, publiclyOpenedCards);
    }
}