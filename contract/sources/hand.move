module contract_owner::hand {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::string::utf8;
    use std::vector;
    use aptos_std::crypto_algebra::inv;
    use aptos_std::debug;
    use aptos_std::math64::min;
    use aptos_framework::stake::cur_validator_consensus_infos;
    use aptos_framework::timestamp;
    use contract_owner::dkg_v0::SharedSecretPublicInfo;
    use contract_owner::encryption;
    use contract_owner::deck;
    use contract_owner::deck::Deck;
    friend contract_owner::poker_room;

    const STATE__WAITING_SHUFFLE_CONTRIBUTION_BEFORE_Y: u64 = 140333;
    const STATE__DEALING_HOLE_CARDS_BEFORE_Y: u64 = 140658;
    const STATE__PHASE_1_BET_BY_PLAYER_X_BEFORE_Y: u64 = 140855;
    const STATE__OPENING_3_COMMUNITY_CARDS_BEFORE_Y: u64 = 141022;
    const STATE__PHASE_2_BET_BY_PLAYER_X_BEFORE_Y: u64 = 141103;
    const STATE__OPENING_4TH_COMMUNITY_CARD_BEFORE_Y: u64 = 141131;
    const STATE__PHASE_3_BET_BY_PLAYER_X_BEFORE_Y: u64 = 141245;
    const STATE__OPENING_5TH_COMMUNITY_CARD_BEFORE_Y: u64 = 141256;
    const STATE__PHASE_4_BET_BY_PLAYER_X_BEFORE_Y: u64 = 141414;
    const STATE__SHOWDOWN_BEFORE_Y: u64 = 141414;
    const STATE__SUCCEEDED: u64 = 141628;
    const STATE__FAILED: u64 = 141629;


    struct HandStateCode has copy, drop, store {
        main: u64,
        x: u64,
        y: u64,
        /// Only used with `STATE__PHASE_*_BET_BY_PLAYER_X_BEFORE_Y`.
        acted: bool,
        /// Only used with `STATE__FAILED`.
        culprits: vector<address>,
    }

    struct HandSession has copy, drop, store {
        num_players: u64,
        players: vector<address>, // [btn, sb, bb, ...]
        expected_small_blind: u64,
        expected_big_blind: u64,
        chips_in_hand: vector<u64>,
        bets: vector<u64>,
        fold_statuses: vector<bool>,
        num_folded: u64,
        highest_invest: u64,
        min_raise_step: u64,
        state: HandStateCode,

        /// Cards at position [2*i, 1+2*i] will be cards dealt to player i (referred to as "having destintation i").
        /// Cards at positions [2*n, 2*n+4] will be community cards (referred to as "having destintation community").
        /// The remaining cards is referred to as having a void destination.
        deck: Deck,
        num_shuffle_contributions: u64,
        culprits: vector<address>,
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
            expected_small_blind: 0,
            expected_big_blind: 0,
            chips_in_hand: vector[],
            bets: vector[],
            fold_statuses: vector[],
            num_folded: 0,
            highest_invest: 0,
            min_raise_step: 0,
            state: HandStateCode { main: 0, x: 0, y: 0, acted: false, culprits: vector[] },
            deck: deck::dummy_deck(),
            num_shuffle_contributions: 0,
            culprits: vector[],
        }
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(players: vector<address>, chips: vector<u64>, shared_secret_public_info: SharedSecretPublicInfo): (vector<u64>, HandSession) {
        let (errors, deck) = deck::new(players, shared_secret_public_info);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 160248);
            return (errors, dummy_session());
        };
        let num_players = vector::length(&players);
        let session = HandSession {
            num_players,
            players,
            expected_small_blind: 125,
            expected_big_blind: 250,
            chips_in_hand: chips,
            bets: vector::map(vector::range(0, num_players), |_|0),
            fold_statuses: vector::map(vector::range(0, num_players), |_|false),
            num_folded: 0,
            highest_invest: 0,
            min_raise_step: 0,
            state: HandStateCode {
                main: STATE__WAITING_SHUFFLE_CONTRIBUTION_BEFORE_Y,
                x: 0,
                y: timestamp::now_seconds() + 5,
                acted: false,
                culprits: vector[],
            },
            deck,
            num_shuffle_contributions: 0,
            culprits: vector[],
        };
        (vector[], session)
    }

    public fun borrow_deck(hand: &HandSession): &deck::Deck {
        &hand.deck
    }

    public fun is_waiting_for_shuffle_contribution_from(hand: &HandSession, addr: address): bool {
        if (hand.state.main != STATE__WAITING_SHUFFLE_CONTRIBUTION_BEFORE_Y) return false;
        if (addr != *vector::borrow(&hand.players, hand.state.x)) return false;
        true
    }

    public fun is_dealing_hole_cards(hand: &HandSession): bool {
        hand.state.main == STATE__DEALING_HOLE_CARDS_BEFORE_Y
    }

    public fun is_phase_1_betting(hand: &HandSession, whose_turn: Option<address>): bool {
        debug::print(&hand.state);
        if (hand.state.main != STATE__PHASE_1_BET_BY_PLAYER_X_BEFORE_Y) return false;
        if (option::is_none(&whose_turn)) return true;
        let whose_turn = option::extract(&mut whose_turn);
        whose_turn == *vector::borrow(&hand.players, hand.state.x)
    }

    public fun succeeded(hand: &HandSession): bool {
        hand.state.main == STATE__SUCCEEDED
    }

    public fun failed(hand: &HandSession): bool {
        hand.state.main == STATE__FAILED
    }

    public fun get_gains_and_losses(hand: &HandSession): (vector<address>, vector<u64>, vector<u64>) {
        assert!(hand.state.main == STATE__SUCCEEDED, 184544);
        //TODO: real impl
        let zeros = vector::map(hand.players, |_|0);
        (hand.players, zeros, zeros)
    }

    public fun get_culprits(hand: &HandSession): vector<address> {
        assert!(failed(hand), 184545);
        hand.culprits
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
        if (hand.state.main == STATE__WAITING_SHUFFLE_CONTRIBUTION_BEFORE_Y) {
            let addr = *vector::borrow(&hand.players, hand.state.x);
            if (deck::has_shuffle_contribution_from(&hand.deck, addr)) {
                if (hand.state.x == hand.num_players - 1) {
                    // Put blinds.
                    let sb_player_idx = get_small_blind_player_idx(hand);
                    let actual_small_blind = min(hand.expected_small_blind, *vector::borrow(&hand.chips_in_hand, sb_player_idx));
                    move_chips_to_pot(hand, sb_player_idx, actual_small_blind);
                    let bb_player_idx = (sb_player_idx + 1) % hand.num_players;
                    let actual_big_blind = min(hand.expected_big_blind, *vector::borrow(&hand.chips_in_hand, bb_player_idx));
                    move_chips_to_pot(hand, bb_player_idx, actual_big_blind);
                    hand.highest_invest = hand.expected_big_blind;

                    // State transistion.
                    hand.state = HandStateCode {
                        main: STATE__DEALING_HOLE_CARDS_BEFORE_Y,
                        x: 0,
                        y: now_secs + 5,
                        acted: false,
                        culprits: vector[],
                    };
                } else {
                    hand.state.x = hand.state.x + 1;
                    hand.state.y = now_secs + 5;
                }
            } else if (now_secs >= hand.state.y) {
                hand.state.main = STATE__FAILED;
                hand.culprits = vector[addr];
            }
        } else if (hand.state.main == STATE__DEALING_HOLE_CARDS_BEFORE_Y) {
            if (now_secs < hand.state.y) return;
            let culprits = vector::filter(hand.players, |player|{
                // For a player P, if the contribution of P is missing for any hole card that does not go to P, P is considered to have misbehaved.
                let (player_found, player_idx) = vector::index_of(&hand.players, player);
                assert!(player_found, 143341);
                let hole_card_idxs = vector::range(0, hand.num_players * 2);
                vector::any(&hole_card_idxs, |card_idx|{
                    let dest = card_goes_to(hand, *card_idx);
                    let maybe_contribution = deck::get_decryption_share(&hand.deck, *card_idx, *player);
                    dest != player_idx && option::is_none(&maybe_contribution)
                })
            });
            if (vector::is_empty(&culprits)) {
                // Hole card dealing is done.
                let bb_player_idx = (get_small_blind_player_idx(hand) + 1) % hand.num_players;
                debug::print(&bb_player_idx);
                let (actor_found, actor_idx) = try_get_next_actor(hand, bb_player_idx);
                debug::print(&actor_found);
                debug::print(&actor_idx);
                if (actor_found) {
                    hand.state = HandStateCode {
                        main: STATE__PHASE_1_BET_BY_PLAYER_X_BEFORE_Y,
                        x: actor_idx,
                        y: now_secs + 5,
                        acted: false,
                        culprits: vector[],
                    };
                } else {
                    // Can skip pre-flop.
                    hand.state = HandStateCode {
                        main: STATE__OPENING_3_COMMUNITY_CARDS_BEFORE_Y,
                        x: 0,
                        y: now_secs + 5,
                        acted: false,
                        culprits: vector[],
                    };
                }
            } else {
                hand.state = HandStateCode {
                    main: STATE__FAILED,
                    x: 0,
                    y: 0,
                    acted: false,
                    culprits,
                };
            }
        } else if (hand.state.main == STATE__PHASE_1_BET_BY_PLAYER_X_BEFORE_Y) {
            let expected_actor = hand.state.x;
            if (!hand.state.acted && now_secs < hand.state.y) return;

            // Time-out ==> FOLD
            if (now_secs >= hand.state.y) mark_as_fold(hand, expected_actor);

            let (next_actor_found, next_actor) = try_get_next_actor(hand, hand.state.x);
            if (next_actor_found) {
                hand.state.x = next_actor;
                hand.state.y = now_secs + 10;
            } else {
                if (hand.num_folded == hand.num_players - 1) {
                    hand.state = HandStateCode {
                        main: STATE__SUCCEEDED,
                        x: 0,
                        y: 0,
                        acted: false,
                        culprits: vector[],
                    };
                } else {
                    hand.state = HandStateCode {
                        main: STATE__OPENING_3_COMMUNITY_CARDS_BEFORE_Y,
                        x: 0,
                        y: now_secs + 5,
                        acted: false,
                        culprits: vector[],
                    };
                }
            }
        } else if (hand.state.main == STATE__OPENING_3_COMMUNITY_CARDS_BEFORE_Y) {
            //TODO
        } else if (hand.state.main == STATE__PHASE_2_BET_BY_PLAYER_X_BEFORE_Y) {
            //TODO
        } else if (hand.state.main == STATE__OPENING_4TH_COMMUNITY_CARD_BEFORE_Y) {
            //TODO
        } else if (hand.state.main == STATE__PHASE_3_BET_BY_PLAYER_X_BEFORE_Y) {
            //TODO
        } else if (hand.state.main == STATE__OPENING_5TH_COMMUNITY_CARD_BEFORE_Y) {
            //TODO
        } else if (hand.state.main == STATE__PHASE_4_BET_BY_PLAYER_X_BEFORE_Y) {
            //TODO
        } else if (hand.state.main == STATE__SHOWDOWN_BEFORE_Y) {
            //TODO
        }
    }

    public fun process_shuffle_contribution(player: &signer, hand: &mut HandSession, new_draw_pile: vector<encryption::Ciphertext>, proof: deck::ShuffleProof) {
        let now = timestamp::now_seconds();
        let player_addr = address_of(player);
        let (found, player_idx) = vector::index_of(&hand.players, &player_addr);
        assert!(found, 171019);
        assert!(hand.state.main == STATE__WAITING_SHUFFLE_CONTRIBUTION_BEFORE_Y, 171018);
        assert!(hand.state.x == player_idx, 171020);
        assert!(now < hand.state.y, 171021);

        deck::apply_shuffle(player, &mut hand.deck, new_draw_pile, proof);
    }

    public fun process_card_decryption_share(player: &signer, hand: &mut HandSession, card_idx: u64, share: deck::VerifiableDecryptionShare) {
        let now = timestamp::now_seconds();
        let player_addr = address_of(player);
        let (found, player_idx) = vector::index_of(&hand.players, &player_addr);
        let card_destination = card_goes_to(hand, card_idx);
        assert!(found, 130400);

        // Check target correctness.
        if (hand.state.main == STATE__DEALING_HOLE_CARDS_BEFORE_Y) {
            assert!(
                card_destination != CARD_DEST__VOID
                    && card_destination != CARD_DEST__COMMUNITY_0
                    && card_destination != CARD_DEST__COMMUNITY_1
                    && card_destination != CARD_DEST__COMMUNITY_2
                    && card_destination != CARD_DEST__COMMUNITY_3
                    && card_destination != CARD_DEST__COMMUNITY_4
                    && card_destination != player_idx,
                130401
            );
        } else if (hand.state.main == STATE__OPENING_3_COMMUNITY_CARDS_BEFORE_Y) {
            assert!(
                    card_destination == CARD_DEST__COMMUNITY_0
                    || card_destination == CARD_DEST__COMMUNITY_1
                    || card_destination == CARD_DEST__COMMUNITY_2,
                130402
            );
        } else if (hand.state.main == STATE__OPENING_4TH_COMMUNITY_CARD_BEFORE_Y) {
            assert!(card_destination == CARD_DEST__COMMUNITY_3, 130403);
        } else if (hand.state.main == STATE__OPENING_5TH_COMMUNITY_CARD_BEFORE_Y) {
            assert!(card_destination == CARD_DEST__COMMUNITY_4, 130404);
        } else {
            abort(130405);
        };

        // Check time.
        assert!(now < hand.state.y, 130406);

        // Pass the share into deck.
        deck::process_decryption_share(player, &mut hand.deck, card_idx, share);
    }

    public fun process_new_invest(player: &signer, hand: &mut HandSession, new_invest: u64) {
        let now = timestamp::now_seconds();
        let player_addr = address_of(player);
        let (player_found, player_idx) = vector::index_of(&hand.players, &player_addr);
        assert!(player_found, 121114);

        assert!(hand.state.main == STATE__PHASE_1_BET_BY_PLAYER_X_BEFORE_Y
            && hand.state.x == player_idx
            && now < hand.state.y,
            121115
        );

        // Should never abort here.
        assert!(!player_has_all_in(hand, player_idx), 121116);
        assert!(!player_has_folded(hand, player_idx), 121117);

        let cur_invest = *vector::borrow(&hand.bets, player_idx);
        let cur_in_hand =  *vector::borrow(&hand.chips_in_hand, player_idx);

        // Can tell whether it's a FOLD/CALL/CHECK/RAISE from `new_invest`.

        if (new_invest < cur_invest) {
            mark_as_fold(hand, player_idx);
            hand.state.acted = true;
        };

        let invest_delta = new_invest - cur_invest;

        if (invest_delta > cur_in_hand) {
            mark_as_fold(hand, player_idx);
            hand.state.acted = true;
        };

        if (invest_delta == cur_in_hand) {
            // This is an ALL-IN.
            move_chips_to_pot(hand, player_idx, invest_delta);
            hand.state.acted = true;
            return;
        };

        if (new_invest < hand.highest_invest) {
            mark_as_fold(hand, player_idx);
            hand.state.acted = true;
            return;
        };

        if (new_invest == hand.highest_invest) {
            // This is a CALL.
            move_chips_to_pot(hand, player_idx, invest_delta);
            hand.state.acted = true;
            return;
        };

        // Now it must be a RAISE.

        if (new_invest - hand.highest_invest < hand.min_raise_step) {
            // Raise amount is invalid. Take it as a FOLD.
            mark_as_fold(hand, player_idx);
            hand.state.acted = true;
            return;
        };

        hand.min_raise_step = new_invest - hand.highest_invest;
        hand.highest_invest = new_invest;
        move_chips_to_pot(hand, player_idx, invest_delta);
        hand.state.acted = true;
    }

    fun move_chips_to_pot(hand: &mut HandSession, player_idx: u64, amount: u64) {
        let in_hand = vector::borrow_mut(&mut hand.chips_in_hand, player_idx);
        *in_hand = *in_hand - amount;
        let invested = vector::borrow_mut(&mut hand.bets, player_idx);
        *invested = *invested + amount;
    }

    fun try_get_next_actor(hand: &HandSession, last_actor: u64): (bool, u64) {
        let actor = last_actor;
        loop {
            actor = (actor + 1) % hand.num_players;
            if (hand.highest_invest == *vector::borrow(&hand.bets, actor)) {
                // This betting round is done.
                return (false, 0);
            };
            if (!player_has_all_in(hand, actor) && !player_has_folded(hand, actor)) break;
        };
        (true, actor)
    }

    fun player_has_all_in(hand: &HandSession, player_idx: u64): bool {
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
        hand.state.main == STATE__OPENING_3_COMMUNITY_CARDS_BEFORE_Y
    }
}
