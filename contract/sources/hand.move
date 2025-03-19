module contract_owner::hand {
    use std::option;
    use std::signer::address_of;
    use std::string::utf8;
    use std::vector;
    use aptos_std::debug::print;
    use aptos_std::math64::{min, max};
    use aptos_framework::timestamp;
    use contract_owner::private_card_dealing::RecipientPrivateState;
    use contract_owner::group;
    use contract_owner::public_card_opening;
    use contract_owner::threshold_scalar_mul;
    use contract_owner::dkg_v0;
    use contract_owner::private_card_dealing;
    use contract_owner::dkg_v0::SharedSecretPublicInfo;
    use contract_owner::encryption;
    friend contract_owner::poker_room;

    const STATE__DEALING_PRIVATE_CARDS: u64 = 140658;
    const STATE__PLAYER_BETTING: u64 = 140855;
    const STATE__OPENING_COMMUNITY_CARDS: u64 = 141022;
    const STATE__SHOWDOWN: u64 = 141414;
    const STATE__SUCCEEDED: u64 = 141628;
    const STATE__FAILED: u64 = 141629;


    struct HandSession has copy, drop, store {
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
        shuffled_deck: vector<encryption::Ciphertext>,

        /// Chips still available in hand of player `i`.
        /// For any `i`, `chips_in_hand[i] + bets[i]` is a constant before winner decision.
        chips_in_hand: vector<u64>,

        /// Chips that player `i` has put in the pot.
        /// For any `i`, `chips_in_hand[i] + bets[i]` is a constant before winner decision.
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

        private_dealing_sessions: vector<private_card_dealing::Session>,
        public_opening_sessions: vector<public_card_opening::Session>,
    }

    const CARD_DEST__COMMUNITY_0: u64 = 0xcccc00;
    const CARD_DEST__COMMUNITY_1: u64 = 0xcccc01;
    const CARD_DEST__COMMUNITY_2: u64 = 0xcccc02;
    const CARD_DEST__COMMUNITY_3: u64 = 0xcccc03;
    const CARD_DEST__COMMUNITY_4: u64 = 0xcccc04;
    const CARD_DEST__VOID: u64 = 0xffffff;

    const CARD__UNREVEALED: u64 = 0xffffffff;
    const PLAYER__NULL: u64 = 0xffffffff;

    fun card_goes_to(hand: &HandSession, card_idx: u64): u64 {
        let comm_start = hand.num_players * 2;
        if (card_idx < comm_start) {
            return card_idx / 2;
        };
        if (card_idx < comm_start + 5) {
            return CARD_DEST__COMMUNITY_0 + card_idx - comm_start;
        };
        CARD_DEST__VOID
    }

    public fun dummy_session(): HandSession {
        HandSession {
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
        }
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(players: vector<address>, chips: vector<u64>, secret_info: SharedSecretPublicInfo, card_reprs: vector<group::Element>, shuffled_deck: vector<encryption::Ciphertext>): HandSession {
        let num_players = vector::length(&players);

        let hand = HandSession {
            num_players,
            players,
            secret_info,
            expected_small_blind: 125,
            expected_big_blind: 250,
            chips_in_hand: chips,
            bets: vector::map(vector::range(0, num_players), |_|0),
            fold_statuses: vector::map(vector::range(0, num_players), |_|false),
            no_more_action_needed: vector::map(vector::range(0, num_players), |_|false),
            min_raise_step: 0,
            card_reprs,
            shuffled_deck,
            revealed_private_cards: vector::map(vector::range(0, num_players * 2), |_|CARD__UNREVEALED),
            state: STATE__DEALING_PRIVATE_CARDS,
            current_action_player_idx: 0,
            current_action_deadline: 0,
            current_action_completed: false,
            completed_action_is_raise: false,
            blames: vector[],
            private_dealing_sessions: vector[],
            public_opening_sessions: vector[],
        };

        let now_secs = timestamp::now_seconds();
        hand.private_dealing_sessions = vector::map(vector::range(0, hand.num_players * 2), |card_idx| {
            let dest_player_idx = card_goes_to(&hand, card_idx);
            let dest_addr = *vector::borrow(&hand.players, dest_player_idx);
            let card = *vector::borrow(&hand.shuffled_deck, card_idx);
            private_card_dealing::new_session(card, dest_addr, hand.players, hand.secret_info, now_secs + 5, now_secs + 10)
        });

        hand
    }

    fun num_folded(hand: &HandSession): u64 {
        vector::length(&vector::filter(hand.fold_statuses, |folded|*folded))
    }

    fun highest_bet(hand: &HandSession): u64 {
        let ret = 0;
        vector::for_each(hand.bets, |bet|{
            ret = max(ret, bet);
        });
        ret
    }

    public fun is_dealing_private_cards(hand: &HandSession): bool {
        hand.state == STATE__DEALING_PRIVATE_CARDS
    }

    public fun succeeded(hand: &HandSession): bool {
        hand.state == STATE__SUCCEEDED
    }

    public fun failed(hand: &HandSession): bool {
        hand.state == STATE__FAILED
    }

    public fun calc_powers_and_distribute_chips(hand: &mut HandSession) {
        let players_sorted_by_powers_desc = vector::range(0, hand.num_players); //TODO: calc real power.
        vector::for_each(players_sorted_by_powers_desc, |winner_idx|{
            let winner_bet = hand.bets[winner_idx];
            vector::for_each(vector::range(0, hand.num_players), |loser_idx|{
                let diff = min(winner_bet, hand.bets[loser_idx]);
                hand.bets[loser_idx] = hand.bets[loser_idx] - diff;
                hand.chips_in_hand[winner_idx] = hand.chips_in_hand[winner_idx] + diff;
            });
        });
    }

    public fun get_ending_chips(hand: &HandSession): (vector<address>, vector<u64>) {
        assert!(hand.state == STATE__SUCCEEDED, 184544);
        (hand.players, hand.chips_in_hand)
    }

    public fun get_culprits(hand: &HandSession): vector<address> {
        assert!(hand.state == STATE__FAILED, 184545);
        let culprit_idxs = vector::filter(vector::range(0, hand.num_players), |player_idx| *vector::borrow(&hand.blames, *player_idx));
        vector::map(culprit_idxs, |idx|*vector::borrow(&hand.players, idx))
    }

    fun get_small_blind_player_idx(hand: &HandSession): u64 {
        assert!(hand.num_players >= 2, 131817);
        if (hand.num_players == 2) {
            0
        } else {
            1
        }
    }

    /// Anyone can call this to trigger state transitions for the given hand.
    public fun state_update(hand: &mut HandSession) {
        let now_secs = timestamp::now_seconds();
        if (hand.state == STATE__DEALING_PRIVATE_CARDS) {
            let num_dealings = hand.num_players * 2;
            let num_successes = 0;
            let num_failures = 0;
            let blames = vector::map(vector::range(0, hand.num_players), |_|false);
            vector::for_each(vector::range(0, num_dealings), |dealing_idx|{
                let deal_session = vector::borrow_mut(&mut hand.private_dealing_sessions, dealing_idx);
                private_card_dealing::state_update(deal_session);
                if (private_card_dealing::succeeded(deal_session)) {
                    num_successes = num_successes + 1;
                } else if (private_card_dealing::failed(deal_session)) {
                    num_failures = num_failures + 1;
                    vector::for_each_reverse(private_card_dealing::get_culprits(deal_session), |culprit| {
                        let (player_found, player_idx) = vector::index_of(&hand.players, &culprit);
                        assert!(player_found, 261052);
                        *vector::borrow_mut(&mut blames, player_idx) = true;
                    });
                };
            });
            if (num_successes == num_dealings) {
                // Private card dealing is done.
                let sb_player_idx = get_small_blind_player_idx(hand);
                let actual_sb_amount = min(hand.expected_small_blind, hand.chips_in_hand[sb_player_idx]);
                move_chips_to_pot(hand, sb_player_idx, actual_sb_amount);
                let bb_player_idx = (sb_player_idx + 1) % hand.num_players;
                let actual_bb_amount = min(hand.expected_big_blind, hand.chips_in_hand[bb_player_idx]);
                move_chips_to_pot(hand, bb_player_idx, actual_bb_amount);
                hand.no_more_action_needed = vector::map(vector::range(0, hand.num_players), |_|false);
                hand.no_more_action_needed[bb_player_idx] = true;
                hand.no_more_action_needed[sb_player_idx] = player_is_all_in(hand, sb_player_idx);
                hand.min_raise_step = hand.expected_big_blind;
                let next_player_idx = (bb_player_idx + 1) % hand.num_players;
                let (next_player_found, next_player_idx) = find_next_action_needed(hand, next_player_idx);
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
            if (!hand.current_action_completed && now_secs < hand.current_action_deadline) return;

            let idx = hand.current_action_player_idx;
            if (now_secs >= hand.current_action_deadline) {
                // Player timed out. Take it as FOLD.
                mark_as_fold(hand, idx);
            };
            if (hand.completed_action_is_raise) {
                hand.no_more_action_needed = vector::map(vector::range(0, hand.num_players), |_|false);
            };
            hand.no_more_action_needed[hand.current_action_player_idx] = true;

            let next_player_idx = (hand.current_action_player_idx + 1) % hand.num_players;
            let (next_player_found, next_player_idx) = find_next_action_needed(hand, next_player_idx);
            if (next_player_found) {
                hand.current_action_player_idx = next_player_idx;
                hand.current_action_deadline = now_secs + 30;
                hand.current_action_completed = false;
                hand.completed_action_is_raise = false;
            } else if (num_folded(hand) == hand.num_players - 1) {
                // Only 1 player in the hand. Can conclude this hand.
                calc_powers_and_distribute_chips(hand);
                hand.state = STATE__SUCCEEDED;
            } else {
                let num_public_cards_opened = vector::length(&hand.public_opening_sessions);
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
            let num_opening_sessions_created = vector::length(&hand.public_opening_sessions);
            let (opening_idx_begin, opening_idx_end) = if (num_opening_sessions_created == 3) {
                (0, 3)
            } else {
                (num_opening_sessions_created - 1, num_opening_sessions_created)
            };

            let num_successes = 0;
            let num_failures = 0;
            let blames = vector::map(vector::range(0, hand.num_players), |_|false);
            vector::for_each(vector::range(opening_idx_begin, opening_idx_end), |opening_idx|{
                let cur_opening_session = vector::borrow_mut(&mut hand.public_opening_sessions, opening_idx);
                public_card_opening::state_update(cur_opening_session);
                if (public_card_opening::succeeded(cur_opening_session)) {
                    num_successes = num_successes + 1;
                } else if (public_card_opening::failed(cur_opening_session)) {
                    num_failures = num_failures + 1;
                    vector::for_each(public_card_opening::get_culprits(cur_opening_session), |culprit|{
                        let (found, player_idx) = vector::index_of(&hand.players, &culprit);
                        assert!(found, 272424);
                        *vector::borrow_mut(&mut blames, player_idx) = true;
                    });
                }
            });

            if (num_successes == opening_idx_end - opening_idx_begin) {
                // All succeeded.
                hand.no_more_action_needed = vector::map(vector::range(0, hand.num_players), |_|false);
                let ideally_first_to_take_action = get_small_blind_player_idx(hand);
                let (actor_found, actor_idx) = find_next_action_needed(hand, ideally_first_to_take_action);
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
                    let card_idx = hand.num_players * 2 + num_opening_sessions_created;
                    let opening_session = public_card_opening::new_session(hand.card_reprs, hand.shuffled_deck[card_idx], hand.players, hand.secret_info, now_secs + 5);
                    vector::push_back(&mut hand.public_opening_sessions, opening_session);
                };
            } else if (num_successes + num_failures == opening_idx_end - opening_idx_begin) {
                // All finished, some failed.
                hand.state = STATE__FAILED;
                hand.blames = blames;
            } else {
                // While some succeeded, the others are in progress...
            }
        } else if (hand.state == STATE__SHOWDOWN) {
            let every_active_player_revealed = vector::all(&vector::range(0, hand.num_players * 2), |card_idx|{
                let owner = card_goes_to(hand, *card_idx);
                hand.fold_statuses[owner] || hand.revealed_private_cards[*card_idx] != CARD__UNREVEALED
            });
            if (every_active_player_revealed || now_secs >= hand.current_action_deadline) {
                calc_powers_and_distribute_chips(hand);
                hand.state = STATE__SUCCEEDED;
            }
        }
    }

    fun initiate_public_card_opening(hand: &mut HandSession, deadline: u64) {
        let card_idx = hand.num_players * 2 + vector::length(&hand.public_opening_sessions);
        let card_to_open = *vector::borrow(&hand.shuffled_deck, card_idx);
        let opening_session = public_card_opening::new_session(hand.card_reprs, card_to_open, hand.players, hand.secret_info, deadline);
        vector::push_back(&mut hand.public_opening_sessions, opening_session);
        hand.state = STATE__OPENING_COMMUNITY_CARDS;
    }

    public fun process_private_dealing_reencryption(player: &signer, hand: &mut HandSession, card_idx: u64, reencryption: private_card_dealing::VerifiableReencrpytion) {
        assert!(hand.state == STATE__DEALING_PRIVATE_CARDS, 262030);
        assert!(card_idx < hand.num_players * 2, 262031);
        let deal_session = vector::borrow_mut(&mut hand.private_dealing_sessions, card_idx);
        private_card_dealing::process_reencryption(player, deal_session, reencryption);
    }

    public fun process_private_dealing_contribution(player: &signer, hand: &mut HandSession, dealing_idx: u64, contribution: threshold_scalar_mul::VerifiableContribution) {
        assert!(hand.state == STATE__DEALING_PRIVATE_CARDS, 262030);
        assert!(dealing_idx < hand.num_players * 2, 262031);
        let dealing_session = vector::borrow_mut(&mut hand.private_dealing_sessions, dealing_idx);
        private_card_dealing::process_scalar_mul_share(player, dealing_session, contribution);
    }

    public fun process_public_opening_contribution(player: &signer, hand: &mut HandSession, opening_idx: u64, contribution: threshold_scalar_mul::VerifiableContribution) {
        let opening_session = vector::borrow_mut(&mut hand.public_opening_sessions, opening_idx);
        public_card_opening::process_contribution(player, opening_session, contribution);
    }

    public fun process_bet_action(player: &signer, hand: &mut HandSession, new_invest: u64) {
        let player_idx = get_player_idx_or_abort(hand, player);
        process_bet_action_internal(player_idx, hand, new_invest);
    }

    public fun process_showdown_reveal(player: &signer, hand: &mut HandSession, dealing_idx: u64, reenc_private_state: RecipientPrivateState) {
        let _player_idx = get_player_idx_or_abort(hand, player);
        let session = hand.private_dealing_sessions[dealing_idx];
        let card_repr = private_card_dealing::reveal(&session, reenc_private_state);
        let (found, card) = vector::index_of(&hand.card_reprs, &card_repr);
        assert!(found, 104629);
        hand.revealed_private_cards[dealing_idx] = card;
    }

    public fun process_bet_action_internal(player_idx: u64, hand: &mut HandSession, new_bet: u64) {
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

        let cur_invest = *vector::borrow(&hand.bets, player_idx);
        let cur_in_hand =  *vector::borrow(&hand.chips_in_hand, player_idx);

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

    fun move_chips_to_pot(hand: &mut HandSession, player_idx: u64, amount: u64) {
        let in_hand = vector::borrow_mut(&mut hand.chips_in_hand, player_idx);
        *in_hand = *in_hand - amount;
        let invested = vector::borrow_mut(&mut hand.bets, player_idx);
        *invested = *invested + amount;
    }

    fun find_next_action_needed(hand: &HandSession, first_player_to_check: u64): (bool, u64) {
        let player = first_player_to_check;
        while (hand.no_more_action_needed[player] || hand.fold_statuses[player] || player_is_all_in(hand, player)) {
            player = (player + 1) % hand.num_players;
            if (player == first_player_to_check) return (false, PLAYER__NULL);
        };
        (true, player)
    }

    fun player_is_all_in(hand: &HandSession, player_idx: u64): bool {
        0 == *vector::borrow(&hand.chips_in_hand, player_idx)
    }

    fun player_has_folded(hand: &HandSession, player_idx: u64): bool {
        *vector::borrow(&hand.fold_statuses, player_idx)
    }

    fun mark_as_fold(hand: &mut HandSession, player_idx: u64) {
        let flag = vector::borrow_mut(&mut hand.fold_statuses, player_idx);
        assert!(*flag == false, 152010);
        *flag = true;
        hand.no_more_action_needed[player_idx] = false;
    }

    public fun get_bets(hand: &HandSession): vector<u64> {
        hand.bets
    }

    public fun get_fold_statuses(hand: &HandSession): vector<bool> {
        hand.fold_statuses
    }

    public fun is_dealing_community_cards(hand: &HandSession): bool {
        hand.state == STATE__OPENING_COMMUNITY_CARDS && 3 == vector::length(&hand.public_opening_sessions)
    }

    public fun is_opening_4th_community_card(hand: &HandSession): bool {
        hand.state == STATE__OPENING_COMMUNITY_CARDS && 4 == vector::length(&hand.public_opening_sessions)
    }

    public fun is_opening_5th_community_card(hand: &HandSession): bool {
        hand.state == STATE__OPENING_COMMUNITY_CARDS && 5 == vector::length(&hand.public_opening_sessions)
    }

    public fun is_at_showdown(hand: &HandSession): bool {
        hand.state == STATE__SHOWDOWN
    }

    public fun is_phase_1_betting(hand: &HandSession, whose_turn: address): bool {
        hand.state == STATE__PLAYER_BETTING
            && 0 == vector::length(&hand.public_opening_sessions)
            && whose_turn == *vector::borrow(&hand.players, hand.current_action_player_idx)
    }

    public fun is_phase_2_betting(hand: &HandSession, whose_turn: address): bool {
        hand.state == STATE__PLAYER_BETTING
            && 3 == vector::length(&hand.public_opening_sessions)
            && whose_turn == *vector::borrow(&hand.players, hand.current_action_player_idx)
    }

    public fun is_phase_3_betting(hand: &HandSession, whose_turn: address): bool {
        hand.state == STATE__PLAYER_BETTING
            && 4 == vector::length(&hand.public_opening_sessions)
            && whose_turn == *vector::borrow(&hand.players, hand.current_action_player_idx)
    }

    public fun is_phase_4_betting(hand: &HandSession, whose_turn: address): bool {
        hand.state == STATE__PLAYER_BETTING
            && 5 == vector::length(&hand.public_opening_sessions)
            && whose_turn == *vector::borrow(&hand.players, hand.current_action_player_idx)
    }

    public fun borrow_private_dealing_session(hand: &HandSession, idx: u64): &private_card_dealing::Session {
        vector::borrow(&hand.private_dealing_sessions, idx)
    }

    public fun borrow_public_opening_session(hand: &HandSession, idx: u64): &public_card_opening::Session {
        vector::borrow(&hand.public_opening_sessions, idx)
    }

    fun get_player_idx_or_abort(hand: &HandSession, player: &signer): u64 {
        let addr = address_of(player);
        let (player_found, idx) = vector::index_of(&hand.players, &addr);
        assert!(player_found, 102640);
        idx
    }

    #[test_only]
    public fun reveal_dealed_card_locally(player: &signer, session: &HandSession, deal_idx: u64, player_private_state: private_card_dealing::RecipientPrivateState): u64 {
        let deal_session = vector::borrow(&session.private_dealing_sessions, deal_idx);
        let plaintext = private_card_dealing::reveal(deal_session, player_private_state);
        let (found, card_val) = vector::index_of(&session.card_reprs, &plaintext);
        assert!(found, 310350);
        card_val
    }
}
