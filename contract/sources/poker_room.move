module contract_owner::poker_room {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::vector;
    use aptos_std::math64::min;
    use aptos_std::table;
    use aptos_std::table::Table;
    use contract_owner::deck;
    use contract_owner::group;
    use contract_owner::hand;
    use contract_owner::hand::HandSession;
    use contract_owner::dkg_v0;
    use contract_owner::encryption;
    #[test_only]
    use std::string::utf8;
    #[test_only]
    use aptos_std::debug;
    #[test_only]
    use aptos_framework::randomness;
    #[test_only]
    use aptos_framework::timestamp;

    const STATE__WAITING_FOR_PLAYERS: u64 = 1;
    const STATE__DKG_IN_PROGRESS: u64 = 2;
    const STATE__HAND_IN_PROGRESS: u64 = 3;
    const STATE__CLOSED: u64 = 4;


    struct StateCode has copy, drop, store {
        main: u64,
        x: u64,
        y: u64,
    }

    struct PokerRoomStateBrief has drop {
        num_players: u64,
        expected_player_addresses: vector<address>,
        card_enc_base: group::Element,
        player_enc_keys: vector<Option<encryption::EncKey>>,
        player_chips: vector<u64>,
        last_button_position: u64,
        state: StateCode,
        cur_hand: hand::HandSession,
        num_hands_done: u64,
        num_dkgs_done: u64,
        cur_dkg_session: dkg_v0::DKGSession,
    }

    struct PokerRoomState has key {
        num_players: u64,
        expected_player_addresses: vector<address>,
        misbehavior_penalty: u64,
        card_enc_base: group::Element,
        player_enc_keys: vector<Option<encryption::EncKey>>,
        player_chips: vector<u64>,
        burned_chips: u64,
        last_button_position: u64,
        state: StateCode,
        hands: Table<u64, HandSession>,
        num_hands_done: u64, // Including successes and failures.
        num_dkgs_done: u64, // Including successes and failures.
        dkg_sessions: Table<u64, dkg_v0::DKGSession>,
    }

    fun next_alive_player(room: &PokerRoomState, pos: u64): u64 {
        let starting_pos = pos;
        loop {
            pos = (pos + 1) % room.num_players;
            if (*vector::borrow(&room.player_chips, pos) > 0) return pos;
            if (pos == starting_pos) abort(161310);
        }
    }

    /// If no DKG was done or the last succeedful DKG does not match the currently alive player set, start a DKG.
    /// Otherwise, start a hand.
    fun start_dkg_or_hand(room: &mut PokerRoomState) {
        let alive_player_idxs = vector::filter(vector::range(0, room.num_players), |idx|room.player_chips[*idx] > 0);
        let alive_players = vector::map(alive_player_idxs, |idx|*vector::borrow(&room.expected_player_addresses, idx));
        let maybe_available_shared_secret = if (room.num_dkgs_done == 0) {
            option::none()
        } else {
            let last_dkg = table::borrow(&room.dkg_sessions, room.num_dkgs_done - 1);
            let contributors = dkg_v0::get_contributors(last_dkg);
            if (contributors != alive_players) {
                option::none()
            } else {
                option::some(dkg_v0::get_shared_secret_public_info(last_dkg))
            }
        };

        if (option::is_none(&maybe_available_shared_secret)) {
            let new_dkg_id = room.num_dkgs_done;
            let dkg_session = dkg_v0::new_session(alive_players);
            table::add(&mut room.dkg_sessions, new_dkg_id, dkg_session);
            room.state = StateCode {
                main: STATE__DKG_IN_PROGRESS,
                x: 0,
                y: 0,
            };
        } else {
            let shared_secret_public_info = option::extract(&mut maybe_available_shared_secret);
            let new_hand_id = room.num_hands_done;
            let alive_player_chips = vector::filter(room.player_chips, |chip_amount|*chip_amount > 0);
            let (errors, new_hand) = hand::new_session(alive_players, alive_player_chips, shared_secret_public_info);
            assert!(vector::is_empty(&errors), 20250306182613);
            table::add(&mut room.hands, new_hand_id, new_hand);
            room.state = StateCode {
                main: STATE__HAND_IN_PROGRESS,
                x: 0,
                y: 0,
            };

        }
    }

    /// Anyone can call this to trigger state transitions in the given poker room.
    #[randomness]
    entry fun state_update(room_addr: address) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room_addr);
        if (room.state.main == STATE__WAITING_FOR_PLAYERS) {
            if (vector::all(&room.player_enc_keys, |maybe_enc_key|option::is_some(maybe_enc_key))) {
                //TODO: shuffle the seats?
                start_dkg_or_hand(room);
            }
        } else if (room.state.main == STATE__DKG_IN_PROGRESS) {
            let cur_dkg = table::borrow_mut(&mut room.dkg_sessions, room.state.x);
            dkg_v0::state_update(cur_dkg);
            if (dkg_v0::succeeded(cur_dkg)) {
                room.num_dkgs_done = room.num_dkgs_done + 1;
                start_dkg_or_hand(room);
            } else if (dkg_v0::failed(cur_dkg)) {
                punish_culprits(room, dkg_v0::get_culprits(cur_dkg));
                room.num_dkgs_done = room.num_dkgs_done + 1;
                start_dkg_or_hand(room);
            } else {
                // DKG is still in progress.
            }
        } else if (room.state.main == STATE__HAND_IN_PROGRESS) {
            let cur_hand = table::borrow_mut(&mut room.hands, room.state.x);
            hand::state_update(cur_hand);
            if (hand::succeeded(cur_hand)) {
                // Apply the hand result.
                let (players, gains, losses) = hand::get_gains_and_losses(cur_hand);
                let n = vector::length(&players);
                vector::for_each(vector::range(0, n), |i|{
                    let player = *vector::borrow(&players, i);
                    let gain = *vector::borrow(&gains, i);
                    let loss = *vector::borrow(&losses, i);
                    let (found, player_idx) = vector::index_of(&room.expected_player_addresses, &player);
                    assert!(found, 192724);
                    let chip_amount = vector::borrow_mut(&mut room.player_chips, player_idx);
                    *chip_amount = *chip_amount + gain - loss;
                });
                room.num_hands_done = room.num_hands_done + 1;

                // Do the next thing.
                start_dkg_or_hand(room);
            } else if (hand::failed(cur_hand)) {
                punish_culprits(room, hand::get_culprits(cur_hand));
                room.num_hands_done = room.num_hands_done + 1;

                // Do the next thing.
                start_dkg_or_hand(room);
            } else {
                // The hand is still in progress.
            }
        }
    }

    fun punish_culprits(room: &mut PokerRoomState, troublemakers: vector<address>) {
        vector::for_each(troublemakers, |player_addr|{
            let (found, player_idx) = vector::index_of(&room.expected_player_addresses, &player_addr);
            assert!(found, 192725);
            let player_chip_amount = vector::borrow_mut(&mut room.player_chips, player_idx);
            let chips_to_burn = min(*player_chip_amount, room.misbehavior_penalty);
            *player_chip_amount = *player_chip_amount - chips_to_burn;
            room.burned_chips = room.burned_chips + chips_to_burn;
        });
    }

    /// A host calls this to create a room. Room state will be stored as a resource under the host's address.
    #[randomness]
    entry fun create(host: &signer, allowed_players: vector<address>) {
        let player_enc_keys = vector::map_ref<address, Option<encryption::EncKey>>(&allowed_players, |_| option::none());
        let player_chips = vector::map_ref<address, u64>(&allowed_players, |_| 100); //TODO: real implementation
        let num_players = vector::length(&allowed_players);
        let room = PokerRoomState {
            num_players,
            last_button_position: num_players - 1,
            expected_player_addresses: allowed_players,
            misbehavior_penalty: 8000,
            card_enc_base: group::rand_element(),
            player_enc_keys,
            player_chips,
            burned_chips: 0,
            state: StateCode {
                main: STATE__WAITING_FOR_PLAYERS,
                x: 0,
                y: 0,
            },
            hands: table::new(),
            dkg_sessions: table::new(),
            num_dkgs_done: 0,
            num_hands_done: 0,
        };
        move_to(host, room)
    }

    /// A player calls this to join a poker room.
    #[randomness]
    entry fun join(player: &signer, room: address, ek_bytes: vector<u8>) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state.main == STATE__WAITING_FOR_PLAYERS, 174045);
        let player_addr = address_of(player);
        let (found, player_idx) = vector::index_of(&room.expected_player_addresses, &player_addr);
        assert!(found, 174046);
        let (error, ek, remainder) = encryption::decode_enc_key(ek_bytes);
        assert!(vector::is_empty(&error), 174047);
        assert!(vector::is_empty(&remainder), 174048);
        *vector::borrow_mut(&mut room.player_enc_keys, player_idx) = option::some(ek);
        *vector::borrow_mut(&mut room.player_chips, player_idx) = 25000; //TODO: what's the initial value to start the table with?
        // state_transition(room);
    }

    #[randomness]
    entry fun process_dkg_contribution(player: &signer, room: address, session_id: u64, contribution_bytes: vector<u8>) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state.main == STATE__DKG_IN_PROGRESS, 174737);
        assert!(room.num_dkgs_done == session_id, 174738);
        let dkg_session = table::borrow_mut(&mut room.dkg_sessions, session_id);
        let (errors, contribution, remainder) = dkg_v0::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 174739);
        assert!(vector::is_empty(&remainder), 174740);
        dkg_v0::process_contribution(player, dkg_session, contribution);
    }

    #[randomness]
    entry fun process_shuffle_contribution(player: &signer, room: address, hand_idx: u64, shuffle_result_bytes: vector<u8>, proof_bytes: vector<u8>) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state.main == STATE__HAND_IN_PROGRESS, 180918);
        assert!(room.num_hands_done == hand_idx, 180919);
        let hand = table::borrow_mut(&mut room.hands, hand_idx);
        let (errors, new_draw_pile, remainder) = deck::decode_shuffle_result(shuffle_result_bytes);
        assert!(vector::is_empty(&errors), 180920);
        assert!(vector::is_empty(&remainder), 180921);
        let (errors, proof, remainder) = deck::decode_shuffle_proof(proof_bytes);
        assert!(vector::is_empty(&errors), 180922);
        assert!(vector::is_empty(&remainder), 180923);
        hand::process_shuffle_contribution(player, hand, new_draw_pile, proof);
    }

    entry fun process_card_decryption_share(player: &signer, room: address, hand_idx: u64, card_idx: u64, share_bytes: vector<u8>) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state.main == STATE__HAND_IN_PROGRESS, 124642);
        assert!(room.num_hands_done == hand_idx, 124643);
        let hand = table::borrow_mut(&mut room.hands, hand_idx);
        let (errors, share, remainder) = deck::decode_decryption_share(share_bytes);
        assert!(vector::is_empty(&errors), 124644);
        assert!(vector::is_empty(&remainder), 124645);
        hand::process_card_decryption_share(player, hand, card_idx, share);
    }

    #[view]
    public fun get_room_brief(room: address): PokerRoomStateBrief acquires PokerRoomState {
        let room = borrow_global<PokerRoomState>(room);
        let cur_hand = if (room.state.main == STATE__HAND_IN_PROGRESS) {
            *table::borrow(&room.hands, room.state.x)
        } else {
            hand::dummy_session()
        };
        let cur_dkg_session = if (room.state.main == STATE__DKG_IN_PROGRESS) {
            *table::borrow(&room.dkg_sessions, room.state.x)
        } else {
            dkg_v0::dummy_session()
        };
        PokerRoomStateBrief {
            num_players: room.num_players,
            expected_player_addresses: room.expected_player_addresses,
            card_enc_base: room.card_enc_base,
            player_enc_keys: room.player_enc_keys,
            player_chips: room.player_chips,
            last_button_position: room.last_button_position,
            state: room.state,
            cur_hand: cur_hand,
            num_hands_done: room.num_hands_done,
            num_dkgs_done: room.num_dkgs_done,
            cur_dkg_session,
        }
    }

    #[view]
    public fun get_dkg_session(room: address, session_id: u64): contract_owner::dkg_v0::DKGSession acquires PokerRoomState {
        let room = borrow_global<PokerRoomState>(room);
        *table::borrow(&room.dkg_sessions, session_id)
    }

    public fun process_new_invest(player: &signer, room: address, hand_idx: u64, bet: u64) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state.main == STATE__HAND_IN_PROGRESS, 120142);
        assert!(room.num_hands_done == hand_idx, 120143);
        let hand = table::borrow_mut(&mut room.hands, hand_idx);
        hand::process_new_invest(player, hand, bet);
    }

    #[test(framework=@0x1, host=@0xcafe, alice=@0xaaaa, bob=@0xbbbb, eric=@0xeeee)]
    fun end_to_end(framework: signer, host: signer, alice: signer, bob: signer, eric: signer) acquires PokerRoomState {
        randomness::initialize_for_testing(&framework);
        timestamp::set_time_has_started_for_testing(&framework);
        // Host creates a room with a player allowlist.
        let alice_addr = address_of(&alice);
        let bob_addr = address_of(&bob);
        let eric_addr = address_of(&eric);
        let host_addr = address_of(&host);
        create(&host, vector[alice_addr, bob_addr, eric_addr]);

        // Anyone can see the initial room states, including the encryption base.
        let room = get_room_brief(host_addr);

        // Alice joins the room.
        let (alice_dk, alice_ek) = encryption::key_gen(room.card_enc_base);
        join(&alice, host_addr, encryption::encode_enc_key(&alice_ek));

        // Bob joins the room.
        let (bob_dk, bob_ek) = encryption::key_gen(room.card_enc_base);
        join(&bob, host_addr, encryption::encode_enc_key(&bob_ek));

        // Eric joins the room.
        let (eric_dk, eric_ek) = encryption::key_gen(room.card_enc_base);
        join(&eric, host_addr, encryption::encode_enc_key(&eric_ek));

        state_update(host_addr);

        // Anyone sees we now need to do DKG 0.
        let room = get_room_brief(host_addr);
        assert!(room.state == StateCode {main: STATE__DKG_IN_PROGRESS, x: 0, y: 0}, 999);

        state_update(host_addr);

        // Eric contributes to DKG 0.
        let (dkg_0_eric_secret_share, dkg_0_eric_contribution) = dkg_v0::generate_contribution(&room.cur_dkg_session);
        process_dkg_contribution(&eric, host_addr, 0, dkg_v0::encode_contribution(&dkg_0_eric_contribution));

        state_update(host_addr);

        // Alice contributes to DKG 0.
        let (dkg_0_alice_secret_share, dkg_0_alice_contribution) = dkg_v0::generate_contribution(&room.cur_dkg_session);
        process_dkg_contribution(&alice, host_addr, 0, dkg_v0::encode_contribution(&dkg_0_alice_contribution));

        state_update(host_addr);

        // Bob contributes to DKG 0.
        let (dkg_0_bob_secret_share, dkg_0_bob_contribution) = dkg_v0::generate_contribution(&room.cur_dkg_session);
        process_dkg_contribution(&bob, host_addr, 0, dkg_v0::encode_contribution(&dkg_0_bob_contribution));

        state_update(host_addr);

        // Anyone sees that DKG 0 finished and hand 0 started.
        let room = get_room_brief(host_addr);
        assert!(room.state == StateCode {main: STATE__HAND_IN_PROGRESS, x: 0, y: 0}, 999);
        // Anyone sees that hand 0 shuffle needs to be done.
        // Alice shuffles first.
        assert!(hand::is_waiting_for_shuffle_contribution_from(&room.cur_hand, alice_addr), 999);
        let deck = hand::borrow_deck(&room.cur_hand);
        let (hand_0_alice_shuffle_contri, hand_0_alice_shuffle_contri_proof) = deck::shuffle(deck);
        process_shuffle_contribution(&alice, host_addr, 0, deck::encode_shuffle_result(&hand_0_alice_shuffle_contri), deck::encode_shuffle_proof(&hand_0_alice_shuffle_contri_proof
        ));

        state_update(host_addr);

        // Bob follows.
        let room = get_room_brief(host_addr);
        assert!(hand::is_waiting_for_shuffle_contribution_from(&room.cur_hand, bob_addr), 999);
        let deck = hand::borrow_deck(&room.cur_hand);
        let (hand_0_bob_shuffle_contri, hand_0_bob_shuffle_contri_proof) = deck::shuffle(deck);
        process_shuffle_contribution(&bob, host_addr, 0, deck::encode_shuffle_result(&hand_0_bob_shuffle_contri), deck::encode_shuffle_proof(&hand_0_bob_shuffle_contri_proof
        ));

        state_update(host_addr);

        // Eric concludes shuffle 0.
        let room = get_room_brief(host_addr);
        assert!(hand::is_waiting_for_shuffle_contribution_from(&room.cur_hand, eric_addr), 999);
        let deck = hand::borrow_deck(&room.cur_hand);
        let (hand_0_eric_shuffle_contri, hand_0_eric_shuffle_contri_proof) = deck::shuffle(deck);
        process_shuffle_contribution(&eric, host_addr, 0, deck::encode_shuffle_result(&hand_0_eric_shuffle_contri), deck::encode_shuffle_proof(&hand_0_eric_shuffle_contri_proof));

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(room.state.main == STATE__HAND_IN_PROGRESS && room.num_hands_done == 0, 999);
        hand::is_dealing_hole_cards(&room.cur_hand);
        let deck = hand::borrow_deck(&room.cur_hand);
        // Alice does her dealing duty.
        vector::for_each(vector[2,3,4,5], |card_idx|{
            let share = deck::compute_card_decryption_share(&alice, deck, card_idx, &dkg_0_alice_secret_share);
            process_card_decryption_share(&alice, host_addr, 0, card_idx, deck::encode_decryption_share(&share));
        });

        // Eric does his dealing duty.
        vector::for_each(vector[1,2,3,0], |card_idx|{
            let share = deck::compute_card_decryption_share(&eric, deck, card_idx, &dkg_0_eric_secret_share);
            process_card_decryption_share(&eric, host_addr, 0, card_idx, deck::encode_decryption_share(&share));
        });

        // Bob does his dealing duty.
        vector::for_each(vector[0,1,5,4], |card_idx|{
            let share = deck::compute_card_decryption_share(&bob, deck, card_idx, &dkg_0_bob_secret_share);
            process_card_decryption_share(&bob, host_addr, 0, card_idx, deck::encode_decryption_share(&share));
        });

        timestamp::fast_forward_seconds(6);
        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(room.state.main == STATE__HAND_IN_PROGRESS && room.num_hands_done == 0, 999);
        assert!(vector[0, 125, 250] == hand::get_bets(&room.cur_hand), 999);
        assert!(vector[false, false, false] == hand::get_fold_statuses(&room.cur_hand), 999);
        assert!(hand::is_phase_1_betting(&room.cur_hand, option::some(alice_addr)), 999);
        let deck = hand::borrow_deck(&room.cur_hand);

        // Alice takes a look at her private cards.
        let hand_0_alice_card_0 = deck::reveal_card_privately(deck, 0, &dkg_0_alice_secret_share);
        let hand_0_alice_card_1 = deck::reveal_card_privately(deck, 1, &dkg_0_alice_secret_share);
        debug::print(&utf8(b"hand_0_alice_card_0:"));
        debug::print(&deck::get_card_text(hand_0_alice_card_0));
        debug::print(&utf8(b"hand_0_alice_card_1:"));
        debug::print(&deck::get_card_text(hand_0_alice_card_1));

        // Alice folds.
        process_new_invest(&alice, host_addr, 0, 0);

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(room.state.main == STATE__HAND_IN_PROGRESS && room.num_hands_done == 0, 999);
        assert!(vector[0, 125, 250] == hand::get_bets(&room.cur_hand), 999);
        assert!(vector[true, false, false] == hand::get_fold_statuses(&room.cur_hand), 999);
        assert!(hand::is_phase_1_betting(&room.cur_hand, option::some(bob_addr)), 999);

        // Bob takes a look at his private cards.
        let hand_0_bob_card_0 = deck::reveal_card_privately(deck, 2, &dkg_0_bob_secret_share);
        let hand_0_bob_card_1 = deck::reveal_card_privately(deck, 3, &dkg_0_bob_secret_share);
        debug::print(&utf8(b"hand_0_bob_card_0:"));
        debug::print(&deck::get_card_text(hand_0_bob_card_0));
        debug::print(&utf8(b"hand_0_bob_card_1:"));
        debug::print(&deck::get_card_text(hand_0_bob_card_1));

        // Bob raises.
        process_new_invest(&bob, host_addr, 0, 500);

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(room.state.main == STATE__HAND_IN_PROGRESS && room.num_hands_done == 0, 999);
        assert!(vector[0, 500, 250] == hand::get_bets(&room.cur_hand), 999);
        assert!(vector[true, false, false] == hand::get_fold_statuses(&room.cur_hand), 999);
        assert!(hand::is_phase_1_betting(&room.cur_hand, option::some(eric_addr)), 999);

        // Eric takes a look at his private cards.
        let hand_0_eric_card_0 = deck::reveal_card_privately(deck, 4, &dkg_0_eric_secret_share);
        let hand_0_eric_card_1 = deck::reveal_card_privately(deck, 5, &dkg_0_eric_secret_share);
        debug::print(&utf8(b"hand_0_eric_card_0:"));
        debug::print(&deck::get_card_text(hand_0_eric_card_0));
        debug::print(&utf8(b"hand_0_eric_card_1:"));
        debug::print(&deck::get_card_text(hand_0_eric_card_1));

        // Eric calls.
        process_new_invest(&eric, host_addr, 0, 500);

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(room.state.main == STATE__HAND_IN_PROGRESS && room.num_hands_done == 0, 999);
        assert!(vector[0, 500, 500] == hand::get_bets(&room.cur_hand), 999);
        assert!(vector[true, false, false] == hand::get_fold_statuses(&room.cur_hand), 999);
        assert!(hand::is_dealing_community_cards(&room.cur_hand), 999);

    }
}
