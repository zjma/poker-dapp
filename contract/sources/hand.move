module contract_owner::hand {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::vector;
    use aptos_std::math64::min;
    use aptos_framework::timestamp;
    use contract_owner::group;
    use contract_owner::public_card_opening;
    use contract_owner::threshold_scalar_mul;
    use contract_owner::dkg_v0;
    use contract_owner::private_card_dealing;
    use contract_owner::dkg_v0::SharedSecretPublicInfo;
    use contract_owner::encryption;
    friend contract_owner::poker_room;

    const STATE__DEALING_PRIVATE_CARDS: u64 = 140658;
    const STATE__PHASE_1_BET_BY_PLAYER_X_BEFORE_Y: u64 = 140855;
    const STATE__OPENING_3_COMMUNITY_CARDS: u64 = 141022;
    const STATE__PHASE_2_BET_BY_PLAYER_X_BEFORE_Y: u64 = 141103;
    const STATE__OPENING_4TH_COMMUNITY_CARD: u64 = 141131;
    const STATE__PHASE_3_BET_BY_PLAYER_X_BEFORE_Y: u64 = 141245;
    const STATE__OPENING_5TH_COMMUNITY_CARD: u64 = 141256;
    const STATE__PHASE_4_BET_BY_PLAYER_X_BEFORE_Y: u64 = 141414;
    const STATE__SHOWDOWN_BEFORE_Y: u64 = 141414;
    const STATE__SUCCEEDED: u64 = 141628;
    const STATE__FAILED: u64 = 141629;


    struct HandSession has copy, drop, store {
        num_players: u64,
        players: vector<address>, // [btn, sb, bb, ...]
        secret_info: dkg_v0::SharedSecretPublicInfo,
        expected_small_blind: u64,
        expected_big_blind: u64,
        chips_in_hand: vector<u64>,
        bets: vector<u64>,
        fold_statuses: vector<bool>,
        num_folded: u64,
        highest_invest: u64,
        min_raise_step: u64,
        card_reprs: vector<group::Element>,
        /// Cards at position [2*i, 1+2*i] will be cards dealt to player i (referred to as "having destintation i").
        /// Cards at positions [2*n, 2*n+4] will be community cards (referred to as "having destintation community").
        /// The remaining cards is referred to as having a void destination.
        shuffled_deck: vector<encryption::Ciphertext>,
        state: u64,
        /// When `state == STATE__PHASE_*_BET_BY_PLAYER_X_BEFORE_Y`, indicate `X`.
        current_action_player_idx: u64,
        /// When `state == STATE__PHASE_*_BET_BY_PLAYER_X_BEFORE_Y`, indicate `Y`.
        current_action_deadline: u64,
        /// When `state == STATE__PHASE_*_BET_BY_PLAYER_X_BEFORE_Y`, indicate whether player `X` has taken the expected action.
        current_action_completed: bool,
        /// When `state == STATE__FAILED`, indicates who misbehaved.
        blames: vector<bool>,
        private_dealing_sessions: vector<Option<private_card_dealing::Session>>,
        public_opening_sessions: vector<Option<public_card_opening::Session>>,
    }

    const CARD_DEST__COMMUNITY_0: u64 = 0xcccc00;
    const CARD_DEST__COMMUNITY_1: u64 = 0xcccc01;
    const CARD_DEST__COMMUNITY_2: u64 = 0xcccc02;
    const CARD_DEST__COMMUNITY_3: u64 = 0xcccc03;
    const CARD_DEST__COMMUNITY_4: u64 = 0xcccc04;
    const CARD_DEST__VOID: u64 = 0xffffff;

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
            num_folded: 0,
            highest_invest: 0,
            min_raise_step: 0,
            card_reprs: vector[],
            shuffled_deck: vector[],
            state: 0,
            current_action_player_idx: 0,
            current_action_deadline: 0,
            current_action_completed: false,
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
            num_folded: 0,
            highest_invest: 0,
            min_raise_step: 0,
            card_reprs,
            shuffled_deck,
            state: STATE__DEALING_PRIVATE_CARDS,
            current_action_player_idx: 0,
            current_action_deadline: 0,
            current_action_completed: false,
            blames: vector[],
            private_dealing_sessions: vector::map(vector::range(0, num_players * 2), |_|option::none()),
            public_opening_sessions: vector::map(vector::range(0, 5), |_|option::none()),
        };


        // Put blinds.
        let sb_player_idx = get_small_blind_player_idx(&hand);
        let actual_small_blind = min(hand.expected_small_blind, *vector::borrow(&hand.chips_in_hand, sb_player_idx));
        move_chips_to_pot(&mut hand, sb_player_idx, actual_small_blind);
        let bb_player_idx = (sb_player_idx + 1) % hand.num_players;
        let actual_big_blind = min(hand.expected_big_blind, *vector::borrow(&hand.chips_in_hand, bb_player_idx));
        move_chips_to_pot(&mut hand, bb_player_idx, actual_big_blind);
        hand.highest_invest = hand.expected_big_blind;

        let now_secs = timestamp::now_seconds();
        vector::for_each(vector::range(0, hand.num_players * 2), |card_idx| {
            let dest_player_idx = card_goes_to(&hand, card_idx);
            let dest_addr = *vector::borrow(&hand.players, dest_player_idx);
            let card = *vector::borrow(&hand.shuffled_deck, card_idx);
            let deal_session = private_card_dealing::new_session(card, dest_addr, hand.players, hand.secret_info, now_secs + 5, now_secs + 10);
            let deal_session_holder = vector::borrow_mut(&mut hand.private_dealing_sessions, card_idx);
            option::fill(deal_session_holder, deal_session);
        });

        hand
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

    public fun get_gains_and_losses(hand: &HandSession): (vector<address>, vector<u64>, vector<u64>) {
        assert!(hand.state == STATE__SUCCEEDED, 184544);
        //TODO: real impl
        let zeros = vector::map(hand.players, |_|0);
        (hand.players, zeros, zeros)
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
                let deal_session = option::borrow_mut(vector::borrow_mut(&mut hand.private_dealing_sessions, dealing_idx));
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
                let bb_player_idx = (get_small_blind_player_idx(hand) + 1) % hand.num_players;
                let (actor_found, actor_idx) = try_get_next_actor(hand, bb_player_idx, option::some(hand.expected_big_blind));
                if (actor_found) {
                    hand.state = STATE__PHASE_1_BET_BY_PLAYER_X_BEFORE_Y;
                    hand.current_action_player_idx = actor_idx;
                    hand.current_action_deadline = now_secs + 5;
                    hand.current_action_completed = false;
                } else {
                    // Can skip pre-flop.
                    set_state_to_community_card_opening_0_1_2(hand, now_secs + 5);
                }
            } else if (num_failures == num_dealings) {
                hand.state = STATE__FAILED;
                hand.blames = blames;
            }
        } else if (hand.state == STATE__PHASE_1_BET_BY_PLAYER_X_BEFORE_Y) {
            if (!hand.current_action_completed && now_secs < hand.current_action_deadline) return;

            // Time-out ==> FOLD
            let idx = hand.current_action_player_idx;
            if (now_secs >= hand.current_action_deadline) mark_as_fold(hand, idx);

            let (next_actor_found, next_actor) = try_get_next_actor(hand, hand.current_action_player_idx, option::some(hand.highest_invest));
            if (next_actor_found) {
                hand.current_action_player_idx = next_actor;
                hand.current_action_deadline = now_secs + 10;
            } else {
                if (hand.num_folded == hand.num_players - 1) {
                    hand.state = STATE__SUCCEEDED;
                } else {
                    set_state_to_community_card_opening_0_1_2(hand, now_secs + 5);
                }
            }
        } else if (hand.state == STATE__OPENING_3_COMMUNITY_CARDS) {
            let all_succeeded = true;
            let blames = vector::map(vector::range(0, hand.num_players), |_|false);
            vector::for_each(vector::range(0, 3), |i|{
                let opening_session = option::borrow_mut(vector::borrow_mut(&mut hand.public_opening_sessions, i));
                public_card_opening::state_update(opening_session);
                if (public_card_opening::succeeded(opening_session)) {
                    // Good.
                } else if (public_card_opening::failed(opening_session)) {
                    all_succeeded = false;
                    vector::for_each(public_card_opening::get_culprits(opening_session), |culprit|{
                        let (found, player_idx) = vector::index_of(&hand.players, &culprit);
                        assert!(found, 272424);
                        *vector::borrow_mut(&mut blames, player_idx) = true;
                    });
                } else {
                    all_succeeded = false;
                }
            });
            if (all_succeeded) {
                let (actor_found, actor_idx) = try_get_next_actor(hand, 0, option::none());
                if (actor_found) {
                    hand.state = STATE__PHASE_2_BET_BY_PLAYER_X_BEFORE_Y;
                    hand.current_action_player_idx = actor_idx;
                    hand.current_action_deadline = now_secs + 10;
                    hand.current_action_completed = false;
                } else {
                    let card_to_open = *vector::borrow(&hand.shuffled_deck, hand.num_players * 2 + 3);
                    let opening_session = public_card_opening::new_session(hand.card_reprs, card_to_open, hand.players, hand.secret_info, now_secs + 5);
                    option::fill(vector::borrow_mut(&mut hand.public_opening_sessions, 3), opening_session);
                    hand.state = STATE__OPENING_4TH_COMMUNITY_CARD;
                };
            }
        } else if (hand.state == STATE__PHASE_2_BET_BY_PLAYER_X_BEFORE_Y) {
            //TODO
        } else if (hand.state == STATE__OPENING_4TH_COMMUNITY_CARD) {
            //TODO
        } else if (hand.state == STATE__PHASE_3_BET_BY_PLAYER_X_BEFORE_Y) {
            //TODO
        } else if (hand.state == STATE__OPENING_5TH_COMMUNITY_CARD) {
            //TODO
        } else if (hand.state == STATE__PHASE_4_BET_BY_PLAYER_X_BEFORE_Y) {
            //TODO
        } else if (hand.state == STATE__SHOWDOWN_BEFORE_Y) {
            //TODO
        }
    }

    fun set_state_to_community_card_opening_0_1_2(hand: &mut HandSession, deadline: u64) {
        let public_card_starting_idx = hand.num_players * 2;
        vector::for_each(vector[0,1,2], |opening_idx|{
            let card_to_open = *vector::borrow(&hand.shuffled_deck, public_card_starting_idx + opening_idx);
            let opening_session = public_card_opening::new_session(hand.card_reprs, card_to_open, hand.players, hand.secret_info, deadline);
            option::fill(vector::borrow_mut(&mut hand.public_opening_sessions, opening_idx), opening_session);
        });
        hand.state = STATE__OPENING_3_COMMUNITY_CARDS;
    }

    public fun process_private_dealing_reencryption(player: &signer, hand: &mut HandSession, card_idx: u64, reencryption: private_card_dealing::VerifiableReencrpytion) {
        assert!(hand.state == STATE__DEALING_PRIVATE_CARDS, 262030);
        assert!(card_idx < hand.num_players * 2, 262031);
        let deal_session = option::borrow_mut(vector::borrow_mut(&mut hand.private_dealing_sessions, card_idx));
        private_card_dealing::process_reencryption(player, deal_session, reencryption);
    }

    public fun process_private_dealing_contribution(player: &signer, hand: &mut HandSession, dealing_idx: u64, contribution: threshold_scalar_mul::VerifiableContribution) {
        assert!(hand.state == STATE__DEALING_PRIVATE_CARDS, 262030);
        assert!(dealing_idx < hand.num_players * 2, 262031);
        let dealing_session = option::borrow_mut(vector::borrow_mut(&mut hand.private_dealing_sessions, dealing_idx));
        private_card_dealing::process_scalar_mul_share(player, dealing_session, contribution);
    }

    public fun process_public_opening_contribution(player: &signer, hand: &mut HandSession, opening_idx: u64, contribution: threshold_scalar_mul::VerifiableContribution) {
        if (hand.state == STATE__OPENING_3_COMMUNITY_CARDS) {
            assert!(opening_idx < 3, 264934);
        } else if (hand.state == STATE__OPENING_4TH_COMMUNITY_CARD) {
            assert!(opening_idx == 3, 264935);
        } else if (hand.state == STATE__OPENING_5TH_COMMUNITY_CARD) {
            assert!(opening_idx == 4, 264936);
        } else {
            abort(264937)
        };
        let opening_session = option::borrow_mut(vector::borrow_mut(&mut hand.public_opening_sessions, opening_idx));
        public_card_opening::process_contribution(player, opening_session, contribution);
    }

    public fun process_new_invest(player: &signer, hand: &mut HandSession, new_invest: u64) {
        let now = timestamp::now_seconds();
        let player_addr = address_of(player);
        let (player_found, player_idx) = vector::index_of(&hand.players, &player_addr);
        assert!(player_found, 121114);

        assert!(hand.state == STATE__PHASE_1_BET_BY_PLAYER_X_BEFORE_Y
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

        if (new_invest < cur_invest) {
            mark_as_fold(hand, player_idx);
            hand.current_action_completed = true;
        };

        let invest_delta = new_invest - cur_invest;

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

        if (new_invest < hand.highest_invest) {
            mark_as_fold(hand, player_idx);
            hand.current_action_completed = true;
            return;
        };

        if (new_invest == hand.highest_invest) {
            // This is a CALL.
            move_chips_to_pot(hand, player_idx, invest_delta);
            hand.current_action_completed = true;
            return;
        };

        // Now it must be a RAISE.

        if (new_invest - hand.highest_invest < hand.min_raise_step) {
            // Raise amount is invalid. Take it as a FOLD.
            mark_as_fold(hand, player_idx);
            hand.current_action_completed = true;
            return;
        };

        hand.min_raise_step = new_invest - hand.highest_invest;
        hand.highest_invest = new_invest;
        move_chips_to_pot(hand, player_idx, invest_delta);
        hand.current_action_completed = true;
    }

    fun move_chips_to_pot(hand: &mut HandSession, player_idx: u64, amount: u64) {
        let in_hand = vector::borrow_mut(&mut hand.chips_in_hand, player_idx);
        *in_hand = *in_hand - amount;
        let invested = vector::borrow_mut(&mut hand.bets, player_idx);
        *invested = *invested + amount;
    }

    fun try_get_next_actor(hand: &HandSession, last_actor: u64, bet_to_match: Option<u64>): (bool, u64) {
        let actor = last_actor;
        loop {
            actor = (actor + 1) % hand.num_players;
            if (actor == last_actor) return (false, 0);
            if (bet_to_match == option::some(*vector::borrow(&hand.bets, actor))) {
                // This betting round is done.
                return (false, 0);
            };
            if (!player_is_all_in(hand, actor) && !player_has_folded(hand, actor)) break;
        };
        (true, actor)
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
        hand.num_folded = hand.num_folded + 1;
    }

    public fun get_bets(hand: &HandSession): vector<u64> {
        hand.bets
    }

    public fun get_fold_statuses(hand: &HandSession): vector<bool> {
        hand.fold_statuses
    }

    public fun is_dealing_community_cards(hand: &HandSession): bool {
        hand.state == STATE__OPENING_3_COMMUNITY_CARDS
    }

    public fun is_phase_1_betting(hand: &HandSession, whose_turn: Option<address>): bool {
        if (hand.state != STATE__PHASE_1_BET_BY_PLAYER_X_BEFORE_Y) return false;
        if (option::is_none(&whose_turn)) return true;
        let whose_turn = option::extract(&mut whose_turn);
        whose_turn == *vector::borrow(&hand.players, hand.current_action_player_idx)
    }

    public fun is_phase_2_betting(hand: &HandSession, actor: Option<address>): bool {
        if (hand.state != STATE__PHASE_2_BET_BY_PLAYER_X_BEFORE_Y) return false;
        if (option::is_none(&actor)) return true;
        let actor = option::extract(&mut actor);
        actor == *vector::borrow(&hand.players, hand.current_action_player_idx)
    }

    public fun borrow_private_dealing_session(hand: &HandSession, idx: u64): &private_card_dealing::Session {
        option::borrow(vector::borrow(&hand.private_dealing_sessions, idx))
    }

    public fun borrow_public_opening_session(hand: &HandSession, idx: u64): &public_card_opening::Session {
        option::borrow(vector::borrow(&hand.public_opening_sessions, idx))
    }

    #[test_only]
    public fun reveal_dealed_card_locally(player: &signer, session: &HandSession, deal_idx: u64, player_private_state: private_card_dealing::RecipientPrivateState): u64 {
        let deal_session = option::borrow(vector::borrow(&session.private_dealing_sessions, deal_idx));
        let plaintext = private_card_dealing::unblind_locally(player, deal_session, player_private_state);
        let (found, card_val) = vector::index_of(&session.card_reprs, &plaintext);
        assert!(found, 310350);
        card_val
    }
}
