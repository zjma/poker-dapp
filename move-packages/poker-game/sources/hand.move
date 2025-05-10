/// Implementation of a single Poker hand.
///
/// A hand starts with:
/// - an ordered list of players `P` (BUTTON, then SMALL BLIND, then BIG BLIEND, ...),
/// - a secret scalar `S` shared between `P`,
/// - a verifiably shuffled deck where every card is encrypted against `S`.
///
/// At any time, a hand can be in the following status.
/// - STATE__DEALING_PRIVATE_CARDS: players collaborate to deal private cards.
///   The receiving player calls `process_private_dealing_reencryption()`.
///   Then everyone else calls `process_private_dealing_contribution()`.
///   If not enough player collaborates, the hand fails.
/// - STATE__PLAYER_BETTING: players take turns to check/raise/fold, etc.
///   Whether it is a pre-flop/post-flop/post-turn/post-river betting can be determined by `public_opening_sessions`.
///   The bet action is submitted via calling `process_bet_action()`.
///   Time-out is considered a FOLD.
/// - STATE__OPENING_COMMUNITY_CARDS: players collaborate to deal public cards.
///   Each player calls `process_public_opening_contribution()`.
///   If not enough player collaborates, the hand fails.
///   Whether it is a flop/turn/river dealing can be determined by `public_opening_sessions`.
/// - STATE__SHOWDOWN: active players reveal their private cards so the winner can be determined.
///   Failing to reveal is considered a FOLD.
/// - STATE__SUCCEEDED: the hand has finished normally with everyone's gains/losses decided.
/// - STATE__FAILED: the hand has failed.
///   Culprits are available for querying.
module poker_game::hand {
    use std::signer::address_of;
    use std::vector;
    use aptos_std::math64::{min, max};
    use aptos_framework::timestamp;
    use crypto_core::reencryption::RecipientPrivateState;
    use crypto_core::group;
    use crypto_core::threshold_scalar_mul;
    use crypto_core::dkg_v0;
    use crypto_core::reencryption;
    use crypto_core::dkg_v0::SharedSecretPublicInfo;
    use crypto_core::elgamal;
    friend poker_game::poker_room;

    const STATE__DEALING_PRIVATE_CARDS: u64 = 140658;
    const STATE__PLAYER_BETTING: u64 = 140855;
    const STATE__OPENING_COMMUNITY_CARDS: u64 = 141022;
    const STATE__SHOWDOWN: u64 = 141414;
    const STATE__SUCCEEDED: u64 = 141628;
    const STATE__FAILED: u64 = 141629;

    /// The full state of a hand.
    struct Session has copy, drop, store {
        num_players: u64,
        players: vector<address>, // [btn, sb, bb, ...]
        secret_info: dkg_v0::SharedSecretPublicInfo,
        expected_small_blind: u64,
        expected_big_blind: u64,

        /// The randomly chosen group elements that represent:
        /// Spade-A, Spade-2, ..., Spade-K, Heart-A, ..., Heart-K, Diamond-A, ... Diamond-K, Club-A, ..., Club-K,
        /// respectively.
        card_reprs: vector<group::Element>,
        /// Cards at position [2*i, 1+2*i] will be cards dealt to player i (referred to as "having destintation i").
        /// Cards at positions [2*n, 2*n+4] will be community cards (referred to as "having destintation community").
        /// The remaining cards is referred to as having a void destination.
        shuffled_deck: vector<elgamal::Ciphertext>,

        /// Chips still available in player `i`'s hand.
        /// For any `i`, `chips_in_hand[i] + bets[i]` is a constant before the winner decision.
        chips_in_hand: vector<u64>,

        /// Chips that player `i` has put in all pots.
        /// For any `i`, `chips_in_hand[i] + bets[i]` is a constant before the winner decision.
        bets: vector<u64>,

        /// Whether player `i` has folded.
        fold_statuses: vector<bool>,

        /// In a betting phase, `no_more_action_needed[i]` indicates whether we need to ask player `i` for bet actions.
        /// At the beginning of a betting phase, `no_more_action_needed[i]` is initialized to `false` for all `i`.
        /// When player `i` correctly checks/calls/bets/raises, `no_more_action_needed[i]` is set to `true`.
        /// Additonally, when player `i` bets/raises, for every `j!=i`, `no_more_action_needed[j]` is reset to `false`.
        /// When `no_more_action_needed[i]` is true for everyone that is still in, the betting round is completed.
        no_more_action_needed: vector<bool>,

        /// In a betting phase, this indicates the minimum raise.
        min_raise_step: u64,

        /// Private cards revealed at showdown phase are saved here.
        revealed_private_cards: vector<u64>,
        state: u64,

        /// When `state == STATE__PHASE_*_BET_BY_PLAYER_X_BEFORE_Y`, indicate `X`.
        current_action_player_idx: u64,
        /// When `state == STATE__PHASE_*_BET_BY_PLAYER_X_BEFORE_Y`, indicate `Y`.
        current_action_deadline: u64,
        /// When `state == STATE__PHASE_*_BET_BY_PLAYER_X_BEFORE_Y`, indicate whether player `X` has taken the expected action.
        current_action_completed: bool,
        completed_action_is_raise: bool,
        /// When `state == STATE__FAILED`, indicates who misbehaved.
        blames: vector<bool>,
        private_dealing_sessions: vector<reencryption::Session>,
        public_opening_sessions: vector<threshold_scalar_mul::Session>,
        publicly_opened_cards: vector<u64>
    }

    const CARD_DEST__COMMUNITY_0: u64 = 0xcccc00;
    const CARD_DEST__COMMUNITY_1: u64 = 0xcccc01;
    const CARD_DEST__COMMUNITY_2: u64 = 0xcccc02;
    const CARD_DEST__COMMUNITY_3: u64 = 0xcccc03;
    const CARD_DEST__COMMUNITY_4: u64 = 0xcccc04;
    const CARD_DEST__VOID: u64 = 0xffffff;

    const CARD__UNREVEALED: u64 = 0xffffffff;
    const PLAYER__NULL: u64 = 0xffffffff;

    /// Given a position in the shuffled deck, return:
    /// - `i`, if the card will end up in player `i`'s hand;
    /// - or `CARD_DEST__COMMUNITY_0 + x`, if the card will be the x-th community card,
    /// - or `CARD_DEST__VOID` if the card will be unused.
    fun card_goes_to(hand: &Session, card_idx: u64): u64 {
        let comm_start = hand.num_players * 2;
        if (card_idx < comm_start) {
            return card_idx / 2;
        };
        if (card_idx < comm_start + 5) {
            return CARD_DEST__COMMUNITY_0 + card_idx - comm_start;
        };
        CARD_DEST__VOID
    }

    public fun dummy_session(): Session {
        Session {
            num_players: 0,
            players: vector[],
            secret_info: dkg_v0::dummy_secret_info(),
            expected_small_blind: 0,
            expected_big_blind: 0,
            chips_in_hand: vector[],
            bets: vector[],
            fold_statuses: vector[],
            revealed_private_cards: vector[],
            no_more_action_needed: vector[],
            min_raise_step: 0,
            card_reprs: vector[],
            shuffled_deck: vector[],
            state: 0,
            current_action_player_idx: 0,
            current_action_deadline: 0,
            current_action_completed: false,
            completed_action_is_raise: false,
            blames: vector[],
            private_dealing_sessions: vector[],
            public_opening_sessions: vector[],
            publicly_opened_cards: vector[]
        }
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(
        players: vector<address>,
        chips: vector<u64>,
        secret_info: SharedSecretPublicInfo,
        card_reprs: vector<group::Element>,
        shuffled_deck: vector<elgamal::Ciphertext>
    ): Session {
        let num_players = players.length();

        let session = Session {
            num_players,
            players,
            secret_info,
            expected_small_blind: 125,
            expected_big_blind: 250,
            chips_in_hand: chips,
            bets: vector::range(0, num_players).map(|_| 0),
            fold_statuses: vector::range(0, num_players).map(|_| false),
            no_more_action_needed: vector::range(0, num_players).map(|_| false),
            min_raise_step: 0,
            card_reprs,
            shuffled_deck,
            revealed_private_cards: vector::range(0, num_players * 2).map(|_| CARD__UNREVEALED),
            state: STATE__DEALING_PRIVATE_CARDS,
            current_action_player_idx: 0,
            current_action_deadline: 0,
            current_action_completed: false,
            completed_action_is_raise: false,
            blames: vector[],
            private_dealing_sessions: vector[],
            public_opening_sessions: vector[],
            publicly_opened_cards: vector[]
        };

        let now_secs = timestamp::now_seconds();
        session.private_dealing_sessions = vector::range(0, session.num_players * 2).map(|card_idx| {
            let dest_player_idx = card_goes_to(&session, card_idx);
            reencryption::new_session(
                session.shuffled_deck[card_idx],
                session.players[dest_player_idx],
                session.players,
                session.secret_info,
                now_secs + 5,
                now_secs + 10
            )
        });

        session
    }

    fun num_folded(hand: &Session): u64 {
        hand.fold_statuses.filter(|folded| *folded).length()
    }

    fun highest_bet(hand: &Session): u64 {
        let ret = 0;
        hand.bets.for_each(|bet| {
            ret = max(ret, bet);
        });
        ret
    }

    public fun is_dealing_private_cards(hand: &Session): bool {
        hand.state == STATE__DEALING_PRIVATE_CARDS
    }

    public fun succeeded(hand: &Session): bool {
        hand.state == STATE__SUCCEEDED
    }

    public fun failed(hand: &Session): bool {
        hand.state == STATE__FAILED
    }

    fun calc_powers_and_distribute_chips(hand: &mut Session) {
        let players_sorted_by_powers_desc = vector::range(0, hand.num_players); //TODO: calc real power.
        players_sorted_by_powers_desc.for_each(|winner_idx| {
            let winner_bet = hand.bets[winner_idx];
            vector::range(0, hand.num_players).for_each(|loser_idx| {
                let diff = min(winner_bet, hand.bets[loser_idx]);
                hand.bets[loser_idx] -= diff;
                hand.chips_in_hand[winner_idx] += diff;
            });
        });
    }

    public fun get_ending_chips(hand: &Session): (vector<address>, vector<u64>) {
        assert!(hand.state == STATE__SUCCEEDED, 184544);
        (hand.players, hand.chips_in_hand)
    }

    public fun get_culprits(hand: &Session): vector<address> {
        assert!(hand.state == STATE__FAILED, 184545);
        let culprit_idxs = vector::range(0, hand.num_players).filter(|player_idx| hand.blames[*player_idx]);
        culprit_idxs.map(|idx| hand.players[idx])
    }

    fun get_small_blind_player_idx(hand: &Session): u64 {
        assert!(hand.num_players >= 2, 131817);
        if (hand.num_players == 2) { 0 }
        else { 1 }
    }

    /// Anyone can call this to trigger state transitions for the given hand.
    public fun state_update(hand: &mut Session) {
        let now_secs = timestamp::now_seconds();
        if (hand.state == STATE__DEALING_PRIVATE_CARDS) {
            let num_dealings = hand.num_players * 2;
            let num_successes = 0;
            let num_failures = 0;
            let blames = vector::range(0, hand.num_players).map(|_| false);
            vector::range(0, num_dealings).for_each(|dealing_idx| {
                let deal_session = &mut hand.private_dealing_sessions[dealing_idx];
                reencryption::state_update(deal_session);
                if (reencryption::succeeded(deal_session)) {
                    num_successes += 1;
                } else if (reencryption::failed(deal_session)) {
                    num_failures += 1;
                    reencryption::get_culprits(deal_session).for_each_reverse(|culprit| {
                        let (player_found, player_idx) = hand.players.index_of(&culprit);
                        assert!(player_found, 261052);
                        blames[player_idx] = true;
                    });
                };
            });
            if (num_successes == num_dealings) {
                // Private card dealing is done.
                let sb_player_idx = get_small_blind_player_idx(hand);
                let actual_sb_amount =
                    min(hand.expected_small_blind, hand.chips_in_hand[sb_player_idx]);
                move_chips_to_pot(hand, sb_player_idx, actual_sb_amount);
                let bb_player_idx = (sb_player_idx + 1) % hand.num_players;
                let actual_bb_amount =
                    min(hand.expected_big_blind, hand.chips_in_hand[bb_player_idx]);
                move_chips_to_pot(hand, bb_player_idx, actual_bb_amount);
                hand.no_more_action_needed = vector::range(0, hand.num_players).map(|_| false);
                hand.no_more_action_needed[bb_player_idx] = true;
                hand.no_more_action_needed[sb_player_idx] = player_is_all_in(
                    hand, sb_player_idx
                );
                hand.min_raise_step = hand.expected_big_blind;
                let next_player_idx = (bb_player_idx + 1) % hand.num_players;
                let (next_player_found, next_player_idx) =
                    find_next_action_needed(hand, next_player_idx);
                if (next_player_found) {
                    hand.state = STATE__PLAYER_BETTING;
                    hand.current_action_player_idx = next_player_idx;
                    hand.current_action_deadline = now_secs + 5;
                    hand.current_action_completed = false;
                    hand.completed_action_is_raise = false;
                } else {
                    // Can skip pre-flop betting.
                    initiate_public_card_opening(hand, now_secs + 5);
                    initiate_public_card_opening(hand, now_secs + 5);
                    initiate_public_card_opening(hand, now_secs + 5);
                    hand.state = STATE__OPENING_COMMUNITY_CARDS;
                }
            } else if (num_failures == num_dealings) {
                hand.state = STATE__FAILED;
                hand.blames = blames;
            }
        } else if (hand.state == STATE__PLAYER_BETTING) {
            if (!hand.current_action_completed
                && now_secs < hand.current_action_deadline)
                return;

            let idx = hand.current_action_player_idx;
            if (now_secs >= hand.current_action_deadline) {
                // Player timed out. Take it as FOLD.
                mark_as_fold(hand, idx);
            };
            if (hand.completed_action_is_raise) {
                hand.no_more_action_needed = vector::range(0, hand.num_players).map(|_| false);
            };
            hand.no_more_action_needed[hand.current_action_player_idx] = true;

            let next_player_idx = (hand.current_action_player_idx + 1) % hand.num_players;
            let (next_player_found, next_player_idx) =
                find_next_action_needed(hand, next_player_idx);
            if (next_player_found) {
                hand.current_action_player_idx = next_player_idx;
                hand.current_action_deadline = now_secs + 30;
                hand.current_action_completed = false;
                hand.completed_action_is_raise = false;
            } else if (num_folded(hand) == hand.num_players - 1) {
                // Only 1 player in the hand. Can conclude.
                calc_powers_and_distribute_chips(hand);
                hand.state = STATE__SUCCEEDED;
            } else {
                let num_public_cards_opened = hand.public_opening_sessions.length();
                if (5 == num_public_cards_opened) {
                    // This is the final betting round. Showdown should follow.
                    hand.state = STATE__SHOWDOWN;
                    hand.current_action_deadline = now_secs + 5;
                } else {
                    initiate_public_card_opening(hand, now_secs + 5);
                    if (0 == num_public_cards_opened) {
                        initiate_public_card_opening(hand, now_secs + 5);
                        initiate_public_card_opening(hand, now_secs + 5);
                    };
                    hand.state = STATE__OPENING_COMMUNITY_CARDS;
                }
            }
        } else if (hand.state == STATE__OPENING_COMMUNITY_CARDS) {
            let num_opening_sessions_created = hand.public_opening_sessions.length();
            let (opening_idx_begin, opening_idx_end) =
                if (num_opening_sessions_created == 3) { (0, 3) }
                else {
                    (num_opening_sessions_created - 1, num_opening_sessions_created)
                };

            let num_successes = 0;
            let num_failures = 0;
            let blames = vector::range(0, hand.num_players).map(|_| false);
            vector::range(opening_idx_begin, opening_idx_end).for_each(|opening_idx| {
                let cur_opening_session =
                    &mut hand.public_opening_sessions[opening_idx];
                threshold_scalar_mul::state_update(cur_opening_session);
                if (threshold_scalar_mul::succeeded(cur_opening_session)) {
                    num_successes += 1;
                } else if (threshold_scalar_mul::failed(cur_opening_session)) {
                    num_failures += 1;
                    threshold_scalar_mul::get_culprits(cur_opening_session).for_each(|culprit| {
                        let (found, player_idx) = hand.players.index_of(&culprit);
                        assert!(found, 272424);
                        blames[player_idx] = true;
                    });
                }
            });

            if (num_successes == opening_idx_end - opening_idx_begin) {
                // All succeeded.

                // Compute the publicly revealed cards and store them.
                vector::range(opening_idx_begin, opening_idx_end).for_each(|opening_idx| {
                    let scalar_mul_result =
                        threshold_scalar_mul::get_result(
                            &hand.public_opening_sessions[opening_idx]
                        );
                    let (_, _, c_1) =
                        elgamal::unpack_ciphertext(
                            hand.shuffled_deck[hand.num_players * 2 + opening_idx]
                        );
                    let revealed_card_repr =
                        group::element_sub(&c_1, &scalar_mul_result);
                    let (found, card) = hand.card_reprs.index_of(&revealed_card_repr);
                    assert!(found, 143939);
                    hand.publicly_opened_cards.push_back(card);
                });

                // Figore out what to do next.
                hand.no_more_action_needed = vector::range(0, hand.num_players).map(|_| false);
                let ideally_first_to_take_action = get_small_blind_player_idx(hand);
                let (actor_found, actor_idx) =
                    find_next_action_needed(hand, ideally_first_to_take_action);
                if (actor_found) {
                    // A betting round should follow.
                    hand.state = STATE__PLAYER_BETTING;
                    hand.current_action_player_idx = actor_idx;
                    hand.current_action_deadline = now_secs + 10;
                    hand.current_action_completed = false;
                } else if (num_opening_sessions_created == 5) {
                    // Showdown should follow.
                    hand.state = STATE__SHOWDOWN;
                } else {
                    // Another community card opening should follow.
                    initiate_public_card_opening(hand, now_secs + 5);
                };
            } else if (num_successes + num_failures
                == opening_idx_end - opening_idx_begin) {
                // All finished, some failed.
                hand.state = STATE__FAILED;
                hand.blames = blames;
            } else {
                // While some succeeded, the others are in progress...
            }
        } else if (hand.state == STATE__SHOWDOWN) {
            let every_active_player_revealed = vector::range(0, hand.num_players * 2).all(|card_idx| {
                let owner = card_goes_to(hand, *card_idx);
                hand.fold_statuses[owner]
                    || hand.revealed_private_cards[*card_idx] != CARD__UNREVEALED
            });
            if (every_active_player_revealed
                || now_secs >= hand.current_action_deadline) {
                calc_powers_and_distribute_chips(hand);
                hand.state = STATE__SUCCEEDED;
            }
        }
    }

    fun initiate_public_card_opening(hand: &mut Session, deadline: u64) {
        let card_idx = hand.num_players * 2
            + hand.public_opening_sessions.length();
        let card_to_open = hand.shuffled_deck[card_idx];
        let (_, c_0, _) = elgamal::unpack_ciphertext(card_to_open);
        let opening_session =
            threshold_scalar_mul::new_session(
                c_0, hand.secret_info, hand.players, deadline
            );
        hand.public_opening_sessions.push_back(opening_session);
        hand.state = STATE__OPENING_COMMUNITY_CARDS;
    }

    public fun process_private_dealing_reencryption(
        player: &signer,
        hand: &mut Session,
        card_idx: u64,
        reencryption: reencryption::VerifiableReencrpytion
    ) {
        assert!(hand.state == STATE__DEALING_PRIVATE_CARDS, 262030);
        assert!(card_idx < hand.num_players * 2, 262031);
        reencryption::process_reencryption(
            player, &mut hand.private_dealing_sessions[card_idx], reencryption
        );
    }

    public fun process_private_dealing_contribution(
        player: &signer,
        hand: &mut Session,
        dealing_idx: u64,
        contribution: threshold_scalar_mul::VerifiableContribution
    ) {
        assert!(hand.state == STATE__DEALING_PRIVATE_CARDS, 262030);
        assert!(dealing_idx < hand.num_players * 2, 262031);
        reencryption::process_scalar_mul_share(
            player, &mut hand.private_dealing_sessions[dealing_idx], contribution
        );
    }

    public fun process_public_opening_contribution(
        player: &signer,
        hand: &mut Session,
        opening_idx: u64,
        contribution: threshold_scalar_mul::VerifiableContribution
    ) {
        threshold_scalar_mul::process_contribution(
            player, &mut hand.public_opening_sessions[opening_idx], contribution
        );
    }

    public fun process_bet_action(
        player: &signer, hand: &mut Session, new_invest: u64
    ) {
        let player_idx = get_player_idx_or_abort(hand, player);
        process_bet_action_internal(player_idx, hand, new_invest);
    }

    public fun process_showdown_reveal(
        player: &signer,
        hand: &mut Session,
        dealing_idx: u64,
        reenc_private_state: RecipientPrivateState
    ) {
        let _player_idx = get_player_idx_or_abort(hand, player);
        let session = hand.private_dealing_sessions[dealing_idx];
        let card_repr = reencryption::reveal(&session, reenc_private_state);
        let (found, card) = hand.card_reprs.index_of(&card_repr);
        assert!(found, 104629);
        hand.revealed_private_cards[dealing_idx] = card;
    }

    fun process_bet_action_internal(
        player_idx: u64, hand: &mut Session, new_bet: u64
    ) {
        let now = timestamp::now_seconds();
        assert!(
            hand.state == STATE__PLAYER_BETTING
                && hand.current_action_player_idx == player_idx
                && now < hand.current_action_deadline,
            121115
        );

        // Should never abort here.
        assert!(!player_is_all_in(hand, player_idx), 121116);
        assert!(!player_has_folded(hand, player_idx), 121117);

        let cur_invest = hand.bets[player_idx];
        let cur_in_hand = hand.chips_in_hand[player_idx];

        // Can tell whether it's a FOLD/CALL/CHECK/RAISE from `new_invest`.

        if (new_bet < cur_invest) {
            mark_as_fold(hand, player_idx);
            hand.current_action_completed = true;
        };

        let invest_delta = new_bet - cur_invest;

        if (invest_delta > cur_in_hand) {
            mark_as_fold(hand, player_idx);
            hand.current_action_completed = true;
        };

        if (invest_delta == cur_in_hand) {
            // This is an ALL-IN.
            move_chips_to_pot(hand, player_idx, invest_delta);
            hand.current_action_completed = true;
            return;
        };

        let bet_to_match = max(hand.expected_big_blind, highest_bet(hand));
        if (new_bet < bet_to_match) {
            mark_as_fold(hand, player_idx);
            hand.current_action_completed = true;
            return;
        };

        if (new_bet == bet_to_match) {
            // This is a CALL/CHECK.
            move_chips_to_pot(hand, player_idx, invest_delta);
            hand.current_action_completed = true;
            return;
        };

        // Now it must be a RAISE.

        if (new_bet - bet_to_match < hand.min_raise_step) {
            // Raise amount is invalid. Take it as a FOLD.
            mark_as_fold(hand, player_idx);
            hand.current_action_completed = true;
            return;
        };

        hand.min_raise_step = new_bet - bet_to_match;
        move_chips_to_pot(hand, player_idx, invest_delta);
        hand.current_action_completed = true;
        hand.completed_action_is_raise = true;
    }

    fun move_chips_to_pot(
        hand: &mut Session, player_idx: u64, amount: u64
    ) {
        let in_hand = &mut hand.chips_in_hand[player_idx];
        *in_hand -= amount;
        let invested = &mut hand.bets[player_idx];
        *invested += amount;
    }

    fun find_next_action_needed(
        hand: &Session, first_player_to_check: u64
    ): (bool, u64) {
        let player = first_player_to_check;
        while (hand.no_more_action_needed[player]
            || hand.fold_statuses[player]
            || player_is_all_in(hand, player)) {
            player = (player + 1) % hand.num_players;
            if (player == first_player_to_check) return (false, PLAYER__NULL);
        };
        (true, player)
    }

    fun player_is_all_in(hand: &Session, player_idx: u64): bool {
        0 == hand.chips_in_hand[player_idx]
    }

    fun player_has_folded(hand: &Session, player_idx: u64): bool {
        hand.fold_statuses[player_idx]
    }

    fun mark_as_fold(hand: &mut Session, player_idx: u64) {
        let fold_status = &mut hand.fold_statuses[player_idx];
        assert!(!*fold_status, 152010);
        *fold_status = true;
        hand.no_more_action_needed[player_idx] = false;
    }

    #[test_only]
    public fun get_public_card(hand: &Session, public_card_idx: u64): u64 {
        hand.publicly_opened_cards[public_card_idx]
    }

    #[test_only]
    public fun get_bets(hand: &Session): vector<u64> {
        hand.bets
    }

    #[test_only]
    public fun get_fold_statuses(hand: &Session): vector<bool> {
        hand.fold_statuses
    }

    #[test_only]
    public fun is_dealing_community_cards(hand: &Session): bool {
        hand.state == STATE__OPENING_COMMUNITY_CARDS
            && 3 == hand.public_opening_sessions.length()
    }

    #[test_only]
    public fun is_opening_4th_community_card(hand: &Session): bool {
        hand.state == STATE__OPENING_COMMUNITY_CARDS
            && 4 == hand.public_opening_sessions.length()
    }

    #[test_only]
    public fun is_opening_5th_community_card(hand: &Session): bool {
        hand.state == STATE__OPENING_COMMUNITY_CARDS
            && 5 == hand.public_opening_sessions.length()
    }

    #[test_only]
    public fun is_at_showdown(hand: &Session): bool {
        hand.state == STATE__SHOWDOWN
    }

    #[test_only]
    public fun is_phase_1_betting(hand: &Session, whose_turn: address): bool {
        hand.state == STATE__PLAYER_BETTING
            && 0 == hand.public_opening_sessions.length()
            && whose_turn == hand.players[hand.current_action_player_idx]
    }

    #[test_only]
    public fun is_phase_2_betting(hand: &Session, whose_turn: address): bool {
        hand.state == STATE__PLAYER_BETTING
            && 3 == hand.public_opening_sessions.length()
            && whose_turn == hand.players[hand.current_action_player_idx]
    }

    #[test_only]
    public fun is_phase_3_betting(hand: &Session, whose_turn: address): bool {
        hand.state == STATE__PLAYER_BETTING
            && 4 == hand.public_opening_sessions.length()
            && whose_turn == hand.players[hand.current_action_player_idx]
    }

    #[test_only]
    public fun is_phase_4_betting(hand: &Session, whose_turn: address): bool {
        hand.state == STATE__PLAYER_BETTING
            && 5 == hand.public_opening_sessions.length()
            && whose_turn == hand.players[hand.current_action_player_idx]
    }

    #[test_only]
    public fun borrow_private_dealing_session(hand: &Session, idx: u64):
        &reencryption::Session {
        &hand.private_dealing_sessions[idx]
    }

    #[test_only]
    public fun borrow_public_opening_session(
        hand: &Session, idx: u64
    ): &threshold_scalar_mul::Session {
        &hand.public_opening_sessions[idx]
    }

    fun get_player_idx_or_abort(hand: &Session, player: &signer): u64 {
        let addr = address_of(player);
        let (player_found, idx) = hand.players.index_of(&addr);
        assert!(player_found, 102640);
        idx
    }

    #[test_only]
    public fun reveal_dealed_card_locally(
        player: &signer,
        session: &Session,
        deal_idx: u64,
        player_private_state: reencryption::RecipientPrivateState
    ): u64 {
        let plaintext =
            reencryption::reveal(
                &session.private_dealing_sessions[deal_idx], player_private_state
            );
        let (found, card_val) = session.card_reprs.index_of(&plaintext);
        assert!(found, 310350);
        card_val
    }
}
