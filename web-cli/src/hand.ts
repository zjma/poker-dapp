import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk";
import * as DKG from "./crypto/dkg_v0";
import * as Elgamal from "./crypto/elgamal";
import * as Group from "./crypto/group";
import * as Shuffle from "./crypto/shuffle";
import * as ThresholdScalarMul from "./crypto/threshold_scalar_mul";

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
    privateDealingSessions: Shuffle.Session[];
    publicOpeningSessions: ThresholdScalarMul.Session[];
    publiclyOpenedCards: number[];

    constructor(numPlayers: number, players: AccountAddress[], secretInfo: DKG.SharedSecretPublicInfo, expectedSmallBlind: number, expectedBigBlind: number, cardReps: Group.Element[], shuffledDeck: Elgamal.Ciphertext[], chipsInHand: number[], bets: number[], foldStatuses: boolean[], noMoreActionNeeded: boolean[], minRaiseStep: number, revealedPrivateCards: number[], state: number, currentActionPlayerIdx: number, currentActionDeadline: number, currentActionCompleted: boolean, completedActionIsRaise: boolean, blames: boolean[], privateDealingSessions: Shuffle.Session[], publicOpeningSessions: ThresholdScalarMul.Session[], publiclyOpenedCards: number[]) {
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

        const cardReps = new Array<Group.Element>(52);
        for (let i = 0; i < 52; i++) {
            cardReps[i] = Group.Element.decode(deserializer);
        }

        const shuffledDeckSize = Number(deserializer.deserializeUleb128AsU32());
        const shuffledDeck = new Array<Elgamal.Ciphertext>(shuffledDeckSize);
        for (let i = 0; i < shuffledDeckSize; i++) {
            shuffledDeck[i] = Elgamal.Ciphertext.decode(deserializer);
        }

        const chipsInHandSize = Number(deserializer.deserializeUleb128AsU32());
        const chipsInHand = new Array<number>(chipsInHandSize);
        for (let i = 0; i < chipsInHandSize; i++) {
            chipsInHand[i] = Number(deserializer.deserializeU64());
        }

        const betsSize = Number(deserializer.deserializeUleb128AsU32());
        const bets = new Array<number>(betsSize);
        for (let i = 0; i < betsSize; i++) {
            bets[i] = Number(deserializer.deserializeU64());
        }

        const foldStatusesSize = Number(deserializer.deserializeUleb128AsU32());
        const foldStatuses = new Array<boolean>(foldStatusesSize);
        for (let i = 0; i < foldStatusesSize; i++) {
            foldStatuses[i] = deserializer.deserializeBool();
        }

        const noMoreActionNeededSize = Number(deserializer.deserializeUleb128AsU32());
        const noMoreActionNeeded = new Array<boolean>(noMoreActionNeededSize);
        for (let i = 0; i < noMoreActionNeededSize; i++) {
            noMoreActionNeeded[i] = deserializer.deserializeBool();
        }
        const minRaiseStep = Number(deserializer.deserializeU64());

        const revealedPrivateCardsSize = Number(deserializer.deserializeUleb128AsU32());
        const revealedPrivateCards = new Array<number>(revealedPrivateCardsSize);
        for (let i = 0; i < revealedPrivateCardsSize; i++) {
            revealedPrivateCards[i] = Number(deserializer.deserializeU64());
        }

        const state = Number(deserializer.deserializeU64());
        const currentActionPlayerIdx = Number(deserializer.deserializeU64());
        const currentActionDeadline = Number(deserializer.deserializeU64());
        const currentActionCompleted = deserializer.deserializeBool();
        const completedActionIsRaise = deserializer.deserializeBool();

        const numBlames = Number(deserializer.deserializeUleb128AsU32());
        const blames = new Array<boolean>(numBlames);
        for (let i = 0; i < numBlames; i++) {
            blames[i] = deserializer.deserializeBool();
        }

        const numPrivateDealingSessions = Number(deserializer.deserializeUleb128AsU32());   
        const privateDealingSessions = new Array<Shuffle.Session>(numPrivateDealingSessions);
        for (let i = 0; i < numPrivateDealingSessions; i++) {
            privateDealingSessions[i] = Shuffle.Session.decode(deserializer);
        }

        const numPublicOpeningSessions = Number(deserializer.deserializeUleb128AsU32());
        const publicOpeningSessions = new Array<ThresholdScalarMul.Session>(numPublicOpeningSessions);
        for (let i = 0; i < numPublicOpeningSessions; i++) {
            publicOpeningSessions[i] = ThresholdScalarMul.Session.decode(deserializer);
        }

        const numPubliclyOpenedCards = Number(deserializer.deserializeUleb128AsU32());
        const publiclyOpenedCards = new Array<number>(numPubliclyOpenedCards);
        for (let i = 0; i < numPubliclyOpenedCards; i++) {
            publiclyOpenedCards[i] = Number(deserializer.deserializeU64());
        }

        return new Session(numPlayers, players, secretInfo, expectedSmallBlind, expectedBigBlind, cardReps, shuffledDeck, chipsInHand, bets, foldStatuses, noMoreActionNeeded, minRaiseStep, revealedPrivateCards, state, currentActionPlayerIdx, currentActionDeadline, currentActionCompleted, completedActionIsRaise, blames, privateDealingSessions, publicOpeningSessions, publiclyOpenedCards);
    }
}
