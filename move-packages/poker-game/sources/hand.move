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
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::vector;
    use aptos_std::bcs_stream;
    use aptos_std::debug::print;
    use aptos_std::math64::min;
    use aptos_framework::object;
    use aptos_framework::timestamp;
    use poker_game::deck_gen;
    use crypto_core::group;
    use crypto_core::threshold_scalar_mul;
    use crypto_core::dkg_v0;
    use crypto_core::reencryption;
    use crypto_core::elgamal;
    friend poker_game::poker_room;

    const STATE__DEALING_PRIVATE_CARDS: u64 = 140658;
    const STATE__PLAYER_BETTING: u64 = 140855;
    const STATE__OPENING_COMMUNITY_CARDS: u64 = 141022;
    const STATE__SHOWDOWN: u64 = 141414;
    const STATE__SUCCEEDED: u64 = 141628;
    const STATE__FAILED: u64 = 141629;

    const PLAYER_STATE__ACTIVE: u64 = 614544;
    const PLAYER_STATE__FOLDED: u64 = 614545;
    const PLAYER_STATE__CHECKED: u64 = 614546;
    const PLAYER_STATE__CALLED: u64 = 614547;
    const PLAYER_STATE__BET: u64 = 614548;
    const PLAYER_STATE__RAISED: u64 = 614549;
    const PLAYER_STATE__ALL_IN: u64 = 614550;

    /// The full state of a hand.
    struct Session has copy, drop, key, store {
        addr_owner: address,
        addr_self: address,

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
        /// Cards at posit
        /// ions [2*n, 2*n+4] will be community cards (referred to as "having destintation community").
        /// The remaining cards is referred to as having a void destination.
        shuffled_deck: vector<elgamal::Ciphertext>,

        /// The starting chip amounts of all players of this hand.
        chips_in_hand: vector<u64>,

        /// Chips that player `i` has put in all pots.
        /// For any `i`, `chips_in_hand[i] + invested_chips[i]` is a constant before the winner decision.
        invested_chips: vector<u64>,

        player_states: vector<u64>,
        last_raise: u64,
        next_raise_threshold: u64,
        call_target: u64,

        /// Private cards revealed at showdown phase are saved here.
        revealed_private_cards: vector<u64>,
        state: u64,

        /// When `state == STATE__PHASE_*_BET_BY_PLAYER_X_BEFORE_Y`, indicate `X`.
        expecting_action_from: Option<u64>,

        /// When `state == STATE__FAILED`, indicates who misbehaved.
        blames: vector<bool>,
        private_dealing_sessions: vector<address>,
        public_opening_sessions: vector<address>,
        publicly_opened_cards: vector<u64>
    }

    const CARD_DEST__COMMUNITY_0: u64 = 0xcccc00;
    const CARD_DEST__COMMUNITY_1: u64 = 0xcccc01;
    const CARD_DEST__COMMUNITY_2: u64 = 0xcccc02;
    const CARD_DEST__COMMUNITY_3: u64 = 0xcccc03;
    const CARD_DEST__COMMUNITY_4: u64 = 0xcccc04;
    const CARD_DEST__VOID: u64 = 0xffffff;

    const CARD__UNREVEALED: u64 = 0xffffffff;

    const INF: u64 = 999999999;

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

    public fun new_session(
        owner: address,
        players: vector<address>,
        chips: vector<u64>,
        secret_info: dkg_v0::SharedSecretPublicInfo,
        deckgen_addr: address,
    ): address {
        let session_holder = object::generate_signer(&object::create_sticky_object(owner));
        let session_addr = address_of(&session_holder);

        let num_players = players.length();
        let (card_reprs, shuffled_deck) = deck_gen::result(deckgen_addr);
        let session = Session {
            addr_owner: owner,
            addr_self: session_addr,
            num_players,
            players,
            secret_info,
            expected_small_blind: 125,
            expected_big_blind: 250,
            chips_in_hand: chips,
            invested_chips: vector::range(0, num_players).map(|_| 0),
            player_states: vector::range(0, num_players).map(|_| PLAYER_STATE__ACTIVE),
            last_raise: 0,
            next_raise_threshold: 0,
            call_target: 0,
            card_reprs,
            shuffled_deck,
            revealed_private_cards: vector::range(0, num_players * 2).map(|_| CARD__UNREVEALED),
            state: STATE__DEALING_PRIVATE_CARDS,
            expecting_action_from: option::none(),
            blames: vector[],
            private_dealing_sessions: vector[],
            public_opening_sessions: vector[],
            publicly_opened_cards: vector[]
        };

        let now_secs = timestamp::now_seconds();
        session.private_dealing_sessions = vector::range(0, session.num_players * 2).map(|card_idx| {
            let dest_player_idx = card_goes_to(&session, card_idx);
            reencryption::new_session(
                session_addr,
                session.shuffled_deck[card_idx],
                session.players[dest_player_idx],
                session.players,
                session.secret_info,
                now_secs + INF,
                now_secs + INF + INF,
            )
        });

        move_to(&session_holder, session);
        session_addr
    }

    fun num_folded(hand: &Session): u64 {
        hand.player_states.filter(|s| PLAYER_STATE__FOLDED == *s).length()
    }

    public fun is_dealing_private_cards(session_addr: address): bool acquires Session {
        let hand = borrow_global<Session>(session_addr);
        hand.state == STATE__DEALING_PRIVATE_CARDS
    }

    public fun succeeded(session_addr: address): bool acquires Session {
        let hand = borrow_global<Session>(session_addr);
        hand.state == STATE__SUCCEEDED
    }

    public fun failed(session_addr: address): bool acquires Session {
        let hand = borrow_global<Session>(session_addr);
        hand.state == STATE__FAILED
    }

    fun calc_powers_and_distribute_chips(hand: &mut Session) {
        let players_sorted_by_powers_desc = vector::range(0, hand.num_players); //TODO: calc real power.
        players_sorted_by_powers_desc.for_each(|winner_idx| {
            let winner_bet = hand.invested_chips[winner_idx];
            vector::range(0, hand.num_players).for_each(|loser_idx| {
                let diff = min(winner_bet, hand.invested_chips[loser_idx]);
                hand.invested_chips[loser_idx] -= diff;
                hand.chips_in_hand[winner_idx] += diff;
            });
        });
    }

    public fun get_ending_chips(hand_addr: address): (vector<address>, vector<u64>) acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        assert!(hand.state == STATE__SUCCEEDED, 184544);
        (hand.players, hand.chips_in_hand)
    }

    public fun get_culprits(hand_addr: address): vector<address> acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        assert!(hand.state == STATE__FAILED, 184545);
        let culprit_idxs = vector::range(0, hand.num_players).filter(|player_idx| hand.blames[*player_idx]);
        culprit_idxs.map(|idx| hand.players[idx])
    }

    fun get_small_blind_player_idx(hand: &Session): u64 {
        assert!(hand.num_players >= 2, 131817);
        if (hand.num_players == 2) { 0 }
        else { 1 }
    }

    fun find_next_active_player(hand: &mut Session, first_to_check: u64): Option<u64> {
        let rem = hand.num_players;
        let idx = first_to_check;
        while (rem > 0) {
            if (hand.player_states[idx] == PLAYER_STATE__ACTIVE) {
                if (hand.num_players - 1 == num_folded(hand)) {
                    hand.player_states[idx] = PLAYER_STATE__CHECKED;
                    return option::none();
                } else {
                    return option::some(idx);
                }
            };
            idx = (idx + 1) % hand.num_players;
            rem -= 1;
        };
        option::none()
    }

    /// Anyone can call this to trigger state transitions for the given hand.
    public entry fun state_update(session_addr: address) acquires Session {
        let hand = borrow_global_mut<Session>(session_addr);
        if (hand.state == STATE__DEALING_PRIVATE_CARDS) {
            state_update__private_cards(hand);
        } else if (hand.state == STATE__PLAYER_BETTING) {
            state_update__betting(hand);
        } else if (hand.state == STATE__OPENING_COMMUNITY_CARDS) {
            state_update__community_cards(hand);
        } else if (hand.state == STATE__SHOWDOWN) {
            state_update__showdown(hand);
        }
    }

    fun state_update__private_cards(hand: &mut Session) {
        let num_dealings = hand.num_players * 2;
        let num_successes = 0;
        let num_failures = 0;
        let blames = vector::range(0, hand.num_players).map(|_| false);
        vector::range(0, num_dealings).for_each(|dealing_idx| {
            let deal_session_addr = hand.private_dealing_sessions[dealing_idx];
            reencryption::state_update(deal_session_addr);
            if (reencryption::succeeded(deal_session_addr)) {
                num_successes += 1;
            } else if (reencryption::failed(deal_session_addr)) {
                num_failures += 1;
                reencryption::culprits(deal_session_addr).for_each_reverse(|culprit| {
                    let (player_found, player_idx) = hand.players.index_of(&culprit);
                    assert!(player_found, 261052);
                    blames[player_idx] = true;
                });
            };
        });
        if (num_successes == num_dealings) {
            // Private card dealing is done.

            // Put small blind.
            let sb_player_idx = get_small_blind_player_idx(hand);
            let actual_sb_amount = min(hand.expected_small_blind, hand.chips_in_hand[sb_player_idx]);
            move_chips_to_pot(hand, sb_player_idx, actual_sb_amount);
            if (hand.chips_in_hand[sb_player_idx] == 0) hand.player_states[sb_player_idx] = PLAYER_STATE__ALL_IN;

            // Put big blind.
            let bb_player_idx = (sb_player_idx + 1) % hand.num_players;
            let actual_bb_amount = min(hand.expected_big_blind, hand.chips_in_hand[bb_player_idx]);
            move_chips_to_pot(hand, bb_player_idx, actual_bb_amount);
            if (hand.chips_in_hand[bb_player_idx] == 0) hand.player_states[bb_player_idx] = PLAYER_STATE__ALL_IN;

            // Remaining setup for the pre-flop betting.
            hand.call_target = hand.expected_big_blind;
            hand.last_raise = 0;
            hand.next_raise_threshold = hand.expected_big_blind * 2;
            let potential_utg_idx = (bb_player_idx + 1) % hand.num_players;
            hand.expecting_action_from = find_next_active_player(hand, potential_utg_idx);
            hand.state = STATE__PLAYER_BETTING;
        } else if (num_failures == num_dealings) {
            hand.state = STATE__FAILED;
            hand.blames = blames;
        }
    }

    fun state_update__betting(hand: &mut Session) {
        if (hand.expecting_action_from.is_some()) {
            // TODO: implement player action timeout
            return;
        };

        if (num_folded(hand) >= hand.num_players - 1) {
            // Can even conclude the hand.
            calc_powers_and_distribute_chips(hand);
            hand.state = STATE__SUCCEEDED;
            return;
        };

        let num_public_cards_opened = hand.public_opening_sessions.length();
        let now_secs = timestamp::now_seconds();
        if (5 == num_public_cards_opened) {
            // The final betting round just finished. Showdown should follow.
            hand.state = STATE__SHOWDOWN;
            return;
        };

        initiate_public_card_opening(hand, now_secs + INF);
        if (0 == num_public_cards_opened) {
            initiate_public_card_opening(hand, now_secs + INF);
            initiate_public_card_opening(hand,now_secs + INF);
        };
        hand.state = STATE__OPENING_COMMUNITY_CARDS;
    }

    fun state_update__community_cards(hand: &mut Session) {
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
            let cur_opening_session = hand.public_opening_sessions[opening_idx];
            threshold_scalar_mul::state_update(cur_opening_session);
            if (threshold_scalar_mul::succeeded(cur_opening_session)) {
                num_successes += 1;
            } else if (threshold_scalar_mul::failed(cur_opening_session)) {
                num_failures += 1;
                threshold_scalar_mul::culprits(cur_opening_session).for_each(|culprit| {
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
                    threshold_scalar_mul::result(hand.public_opening_sessions[opening_idx]);
                let (_, c_1) = elgamal::unpack_ciphertext(hand.shuffled_deck[hand.num_players * 2 + opening_idx]);
                let revealed_card_repr = group::element_sub(&c_1, &scalar_mul_result);
                let (found, card) = hand.card_reprs.index_of(&revealed_card_repr);
                assert!(found, 143939);
                hand.publicly_opened_cards.push_back(card);
            });

            // Setup for the following betting round.
            print(&hand.player_states);
            hand.player_states.for_each_mut(|player_state|{
                if (!(*player_state == PLAYER_STATE__FOLDED || *player_state == PLAYER_STATE__ALL_IN)) {
                    *player_state = PLAYER_STATE__ACTIVE;
                }
            });
            print(&hand.player_states);

            hand.last_raise = hand.call_target;
            hand.next_raise_threshold = hand.last_raise + hand.expected_big_blind;
            let sb_player_idx = get_small_blind_player_idx(hand);
            hand.expecting_action_from = find_next_active_player(hand, sb_player_idx);
            hand.state = STATE__PLAYER_BETTING;
        } else if (num_successes + num_failures == opening_idx_end - opening_idx_begin) {
            // All finished, some failed.
            hand.state = STATE__FAILED;
            hand.blames = blames;
        } else {
            // While some succeeded, the others are in progress...
        }
    }

    fun state_update__showdown(hand: &mut Session) {
        let every_active_player_revealed = vector::range(0, hand.num_players * 2)
            .all(|card_idx| {
                let owner = card_goes_to(hand, *card_idx);
                hand.player_states[owner] == PLAYER_STATE__FOLDED || hand.revealed_private_cards[*card_idx] != CARD__UNREVEALED
            });
        if (every_active_player_revealed) {
            calc_powers_and_distribute_chips(hand);
            hand.state = STATE__SUCCEEDED;
        }
    }

    fun initiate_public_card_opening(hand: &mut Session, deadline: u64) {
        let card_idx = hand.num_players * 2 + hand.public_opening_sessions.length();
        let card_to_open = hand.shuffled_deck[card_idx];
        let (c_0, _) = elgamal::unpack_ciphertext(card_to_open);
        let opening_session = threshold_scalar_mul::new_session(hand.addr_self, c_0, hand.secret_info, hand.players, deadline);
        hand.public_opening_sessions.push_back(opening_session);
        hand.state = STATE__OPENING_COMMUNITY_CARDS;
    }

    public entry fun process_bet_action(player: &signer, hand_addr: address, action: u64) acquires Session {
        let hand = borrow_global_mut<Session>(hand_addr);
        let player_idx = get_player_idx_or_abort(hand, player);
        assert!(hand.state == STATE__PLAYER_BETTING && hand.expecting_action_from.borrow() == &player_idx, 121115);

        assert!(hand.chips_in_hand[player_idx] >= 1, 121116);
        assert!(PLAYER_STATE__ACTIVE == hand.player_states[player_idx], 121117);
        assert!(hand.next_raise_threshold > hand.call_target, 121118);

        let cur_in_hand = hand.chips_in_hand[player_idx];
        let cur_bet = hand.invested_chips[player_idx];
        assert!(hand.call_target >= cur_bet);

        if (action == cur_bet + cur_in_hand) {
            move_chips_to_pot(hand, player_idx, action - cur_bet);
            hand.player_states[player_idx] = PLAYER_STATE__ALL_IN;
            if (action > hand.call_target) {
                hand.call_target = action;
            };
            if (action >= hand.next_raise_threshold) process_raise_extra(hand, player_idx, action);
        } else if (action >= hand.next_raise_threshold) {
            move_chips_to_pot(hand, player_idx, action - cur_bet);
            hand.player_states[player_idx] = if (hand.call_target == cur_bet) { PLAYER_STATE__BET } else { PLAYER_STATE__RAISED };
            hand.call_target = action;
            process_raise_extra(hand, player_idx, action);
        } else if (action == hand.call_target) {
            move_chips_to_pot(hand, player_idx, action - cur_bet);
            hand.player_states[player_idx] = if (hand.call_target == cur_bet) { PLAYER_STATE__CHECKED } else { PLAYER_STATE__CALLED };
        } else {
            hand.player_states[player_idx] = PLAYER_STATE__FOLDED;
        };
        let next_idx = (player_idx + 1) % hand.num_players;
        hand.expecting_action_from = find_next_active_player(hand, next_idx);
    }

    /// Mark everyone else as "action required"; update raise threshold.
    fun process_raise_extra(hand: &mut Session, player_idx: u64, action: u64) {
        vector::range(0, hand.num_players)
            .filter(|idx| *idx != player_idx && hand.player_states[*idx] != PLAYER_STATE__FOLDED && hand.player_states[*idx] != PLAYER_STATE__ALL_IN)
            .for_each(|idx|{ hand.player_states[idx] = PLAYER_STATE__ACTIVE; });
        hand.next_raise_threshold = action * 2 - hand.last_raise;
        hand.last_raise = action;
    }

    public entry fun process_showdown_reveal(
        player: &signer,
        hand_addr: address,
        dealing_idx: u64,
        reenc_private_state_bytes: vector<u8>,
    ) acquires Session {
        let hand = borrow_global_mut<Session>(hand_addr);
        let _player_idx = get_player_idx_or_abort(hand, player);
        let reenc_addr = hand.private_dealing_sessions[dealing_idx];
        let reenc_private_state = reencryption::decode_private_state(&mut bcs_stream::new(reenc_private_state_bytes));
        let card_repr = reencryption::reveal(reenc_addr, reenc_private_state);
        let (found, card) = hand.card_reprs.index_of(&card_repr);
        assert!(found, 104629);
        hand.revealed_private_cards[dealing_idx] = card;
    }

    fun move_chips_to_pot(hand: &mut Session, player_idx: u64, amount: u64) {
        let in_hand = &mut hand.chips_in_hand[player_idx];
        *in_hand -= amount;
        let invested = &mut hand.invested_chips[player_idx];
        *invested += amount;
    }

    struct SessionBrief has drop, store {
        addr_owner: address,
        addr_self: address,
        players: vector<address>,
        secret_info: dkg_v0::SharedSecretPublicInfo,
        expected_small_blind: u64,
        expected_big_blind: u64,
        card_reprs: vector<group::Element>,
        shuffled_deck: vector<elgamal::Ciphertext>,
        chips_in_hand: vector<u64>,
        bets: vector<u64>,
        player_states: vector<u64>,
        call_target: u64,
        last_raise: u64,
        next_raise_threshold: u64,
        revealed_private_cards: vector<u64>,
        state: u64,
        expecting_action_from: Option<u64>,
        private_dealing_sessions: vector<reencryption::SessionBrief>,
        public_opening_sessions: vector<threshold_scalar_mul::SessionBrief>,
        publicly_opened_cards: vector<u64>
    }

    #[view]
    public fun brief(hand_addr: address): SessionBrief acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        SessionBrief {
            addr_owner: hand.addr_owner,
            addr_self: hand_addr,
            players: hand.players,
            secret_info: hand.secret_info,
            expected_big_blind: hand.expected_big_blind,
            expected_small_blind: hand.expected_small_blind,
            card_reprs: hand.card_reprs,
            shuffled_deck: hand.shuffled_deck,
            chips_in_hand: hand.chips_in_hand,
            bets: hand.invested_chips,
            player_states: hand.player_states,
            call_target: hand.call_target,
            last_raise: hand.last_raise,
            next_raise_threshold: hand.next_raise_threshold,
            revealed_private_cards: hand.revealed_private_cards,
            state: hand.state,
            expecting_action_from: hand.expecting_action_from,
            private_dealing_sessions: hand.private_dealing_sessions.map(|addr|reencryption::brief(addr)),
            public_opening_sessions: hand.public_opening_sessions.map(|addr|threshold_scalar_mul::brief(addr)),
            publicly_opened_cards: hand.publicly_opened_cards,
        }
    }

    #[test_only]
    public fun get_public_card(hand_addr: address, public_card_idx: u64): u64 acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.publicly_opened_cards[public_card_idx]
    }

    #[test_only]
    public fun get_bets(hand_addr: address): vector<u64> acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.invested_chips
    }

    #[test_only]
    public fun get_fold_statuses(hand_addr: address): vector<bool> acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.player_states.map(|s| s == PLAYER_STATE__FOLDED)
    }

    #[test_only]
    public fun is_dealing_community_cards(hand_addr: address): bool acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.state == STATE__OPENING_COMMUNITY_CARDS
            && 3 == hand.public_opening_sessions.length()
    }

    #[test_only]
    public fun is_opening_4th_community_card(hand_addr: address): bool acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.state == STATE__OPENING_COMMUNITY_CARDS
            && 4 == hand.public_opening_sessions.length()
    }

    #[test_only]
    public fun is_opening_5th_community_card(hand_addr: address): bool acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.state == STATE__OPENING_COMMUNITY_CARDS
            && 5 == hand.public_opening_sessions.length()
    }

    #[test_only]
    public fun is_at_showdown(hand_addr: address): bool acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.state == STATE__SHOWDOWN
    }

    #[test_only]
    public fun is_phase_1_betting(hand_addr: address, whose_turn: address): bool acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.state == STATE__PLAYER_BETTING
            && 0 == hand.public_opening_sessions.length()
            && whose_turn == hand.players[*hand.expecting_action_from.borrow()]
    }

    #[test_only]
    public fun is_phase_2_betting(hand_addr: address, whose_turn: address): bool acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.state == STATE__PLAYER_BETTING
            && 3 == hand.public_opening_sessions.length()
            && whose_turn == hand.players[*hand.expecting_action_from.borrow()]
    }

    #[test_only]
    public fun is_phase_3_betting(hand_addr: address, whose_turn: address): bool acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.state == STATE__PLAYER_BETTING
            && 4 == hand.public_opening_sessions.length()
            && whose_turn == hand.players[*hand.expecting_action_from.borrow()]
    }

    #[test_only]
    public fun is_phase_4_betting(hand_addr: address, whose_turn: address): bool acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.state == STATE__PLAYER_BETTING
            && 5 == hand.public_opening_sessions.length()
            && whose_turn == hand.players[*hand.expecting_action_from.borrow()]
    }

    #[test_only]
    public fun private_dealing_session_addr(hand_addr: address, idx: u64): address acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.private_dealing_sessions[idx]
    }

    #[test_only]
    public fun borrow_public_opening_session(hand_addr: address, idx: u64): address acquires Session {
        let hand = borrow_global<Session>(hand_addr);
        hand.public_opening_sessions[idx]
    }

    fun get_player_idx_or_abort(hand: &Session, player: &signer): u64 {
        let addr = address_of(player);
        let (player_found, idx) = hand.players.index_of(&addr);
        assert!(player_found, 102640);
        idx
    }

    #[test_only]
    public fun reveal_dealed_card_locally(
        _player: &signer,
        session_addr: address,
        deal_idx: u64,
        player_private_state: reencryption::RecipientPrivateState
    ): u64 acquires Session {
        let session = borrow_global<Session>(session_addr);
        let plaintext = reencryption::reveal(session.private_dealing_sessions[deal_idx], player_private_state);
        let (found, card_val) = session.card_reprs.index_of(&plaintext);
        assert!(found, 310350);
        card_val
    }
}
