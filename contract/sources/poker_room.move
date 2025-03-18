module contract_owner::poker_room {
    use std::option;
    use std::signer::address_of;
    use std::string;
    use std::vector;
    use aptos_std::debug;
    use aptos_std::math64::min;
    use aptos_std::table;
    use aptos_std::table::Table;
    use aptos_std::type_info;
    use aptos_framework::timestamp;
    use contract_owner::encryption;
    use contract_owner::shuffle;
    use contract_owner::private_card_dealing;
    use contract_owner::threshold_scalar_mul;
    use contract_owner::group;
    use contract_owner::hand;
    use contract_owner::hand::HandSession;
    use contract_owner::dkg_v0;
    #[test_only]
    use std::string::utf8;
    #[test_only]
    use aptos_framework::randomness;
    #[test_only]
    use contract_owner::public_card_opening;
    #[test_only]
    use contract_owner::utils;

    const STATE__WAITING_FOR_PLAYERS: u64 = 1;
    const STATE__DKG_IN_PROGRESS: u64 = 2;
    const STATE__SHUFFLE_IN_PROGRESS: u64 = 3;
    const STATE__HAND_AND_SHUFFLE_IN_PROGRESS: u64 = 4;
    const STATE__CLOSED: u64 = 5;


    struct PokerRoomStateBrief has drop {
        num_players: u64,
        expected_player_addresses: vector<address>,
        player_livenesses: vector<bool>,
        card_enc_base: group::Element,
        player_chips: vector<u64>,
        last_button_position: u64,
        state: u64,
        cur_hand: hand::HandSession,
        num_hands_done: u64,
        num_dkgs_done: u64,
        num_shuffles_done: u64,
        cur_dkg_session: dkg_v0::DKGSession,
        cur_shuffle_session: shuffle::Session,
    }

    struct PokerRoomState has key {
        num_players: u64,
        expected_player_addresses: vector<address>,
        player_livenesses: vector<bool>,
        misbehavior_penalty: u64,
        card_enc_base: group::Element,
        player_chips: vector<u64>,
        burned_chips: u64,
        last_button_position: u64,
        state: u64,
        hands: Table<u64, HandSession>,
        num_hands_done: u64, // Including successes and failures.
        num_dkgs_done: u64, // Including successes and failures.
        num_shuffles_done: u64, // Including successes and failures.
        dkg_sessions: Table<u64, dkg_v0::DKGSession>,
        shuffle_sessions: Table<u64, shuffle::Session>,
    }

    fun start_dkg(room: &mut PokerRoomState) {
        let alive_player_idxs = vector::filter(vector::range(0, room.num_players), |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0);
        let alive_players = vector::map(alive_player_idxs, |idx|*vector::borrow(&room.expected_player_addresses, idx));
        if (room.num_dkgs_done >= 1) {
            let last_dkg = table::borrow(&room.dkg_sessions, room.num_dkgs_done - 1);
            let last_dkg_contributors = dkg_v0::get_contributors(last_dkg);
            assert!(last_dkg_contributors != alive_players, 310223);
        };
        let new_dkg_id = room.num_dkgs_done;
        let new_dkg = dkg_v0::new_session(alive_players);
        table::add(&mut room.dkg_sessions, new_dkg_id, new_dkg);
        room.state = STATE__DKG_IN_PROGRESS;
    }

    fun start_shuffle(room: &mut PokerRoomState) {
        let last_dkg = table::borrow(&room.dkg_sessions, room.num_dkgs_done - 1);
        let last_dkg_contributors = dkg_v0::get_contributors(last_dkg);
        let alive_player_idxs = vector::filter(vector::range(0, room.num_players), |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0);
        let alive_players = vector::map(alive_player_idxs, |idx|*vector::borrow(&room.expected_player_addresses, idx));
        assert!(last_dkg_contributors == alive_players, 311540);

        let now_secs = timestamp::now_seconds();
        let secret_info = dkg_v0::get_shared_secret_public_info(last_dkg);
        let (agg_ek, ek_shares) = dkg_v0::unpack_shared_secret_public_info(secret_info);
        let card_reprs = vector::map(vector::range(0, 52), |_|group::rand_element());
        let initial_ciphertexts = vector::map_ref(&card_reprs, |plain| encryption::enc(&agg_ek, &group::scalar_from_u64(0), plain));
        let deadlines = vector::map(vector::range(0, room.num_players), |i| now_secs + 5 * i);
        let new_shuffle = shuffle::new_session(agg_ek, initial_ciphertexts, alive_players, deadlines);
        let new_shuffle_id = room.num_shuffles_done;
        table::add(&mut room.shuffle_sessions, new_shuffle_id, new_shuffle);
        room.state = STATE__SHUFFLE_IN_PROGRESS;
    }

    fun start_hand_and_shuffle(room: &mut PokerRoomState) {
        let last_dkg = table::borrow(&room.dkg_sessions, room.num_dkgs_done - 1);
        let last_dkg_contributors = dkg_v0::get_contributors(last_dkg);
        let alive_player_idxs = vector::filter(vector::range(0, room.num_players), |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0);
        let alive_players = vector::map(alive_player_idxs, |idx|*vector::borrow(&room.expected_player_addresses, idx));
        assert!(last_dkg_contributors == alive_players, 311540);

        let secret_info = dkg_v0::get_shared_secret_public_info(last_dkg);
        let last_shuffle = table::borrow(&room.shuffle_sessions, room.num_shuffles_done - 1);
        let card_reprs = vector::map(shuffle::input_cloned(last_shuffle), |ciph|{
            let (_, _, c_1) = encryption::unpack_ciphertext(ciph);
            c_1 // The ciphertexts were initially generated with 0-randomizers, so c_1 is equal to the plaintext.
        });
        let shuffled_deck = shuffle::result_cloned(last_shuffle);
        let alive_player_chips = vector::map(alive_player_idxs, |idx|room.player_chips[idx]);
        let new_hand_id = room.num_hands_done;
        let new_hand = hand::new_session(alive_players, alive_player_chips, secret_info, card_reprs, shuffled_deck);
        table::add(&mut room.hands, new_hand_id, new_hand);

        let now_secs = timestamp::now_seconds();
        let (agg_ek, _) = dkg_v0::unpack_shared_secret_public_info(secret_info);
        let card_reprs = vector::map(vector::range(0, 52), |_|group::rand_element());
        let initial_ciphertexts = vector::map_ref(&card_reprs, |plain| encryption::enc(&agg_ek, &group::scalar_from_u64(0), plain));
        let deadlines = vector::map(vector::range(0, room.num_players), |i| now_secs + 5 * i);
        let new_shuffle_id = room.num_shuffles_done;
        let new_shuffle = shuffle::new_session(agg_ek, initial_ciphertexts, alive_players, deadlines);
        table::add(&mut room.shuffle_sessions, new_shuffle_id, new_shuffle);

        room.state = STATE__HAND_AND_SHUFFLE_IN_PROGRESS;
    }

    fun apply_hand_result() {

    }

    /// Anyone can call this to trigger state transitions in the given poker room.
    #[randomness]
    entry fun state_update(room_addr: address) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room_addr);
        if (room.state == STATE__WAITING_FOR_PLAYERS) {
            if (vector::all(&room.player_livenesses, |liveness|*liveness)) {
                //TODO: shuffle the seats?
                start_dkg(room);
            }
        } else if (room.state == STATE__DKG_IN_PROGRESS) {
            let cur_dkg = table::borrow_mut(&mut room.dkg_sessions, room.num_dkgs_done);
            dkg_v0::state_update(cur_dkg);
            if (dkg_v0::succeeded(cur_dkg)) {
                room.num_dkgs_done = room.num_dkgs_done + 1;
                start_shuffle(room);
            } else if (dkg_v0::failed(cur_dkg)) {
                punish_culprits(room, dkg_v0::get_culprits(cur_dkg));
                room.num_dkgs_done = room.num_dkgs_done + 1;
                start_dkg(room);
            } else {
                // DKG is still in progress...
            }
        } else if (room.state == STATE__SHUFFLE_IN_PROGRESS) {
            let cur_shuffle = table::borrow_mut(&mut room.shuffle_sessions, room.num_shuffles_done);
            shuffle::state_update(cur_shuffle);
            if (shuffle::succeeded(cur_shuffle)) {
                room.num_shuffles_done = room.num_shuffles_done + 1;
                start_hand_and_shuffle(room);
            } else if (shuffle::failed(cur_shuffle)) {
                let culprit = shuffle::get_culprit(cur_shuffle);
                punish_culprits(room, vector[culprit]);
                room.num_shuffles_done = room.num_shuffles_done + 1;
                start_dkg(room);
            } else {
                // Shuffle still in progress...
            }
        } else if (room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS) {
            let cur_hand = table::borrow_mut(&mut room.hands, room.num_hands_done);
            let cur_shuffle = table::borrow_mut(&mut room.shuffle_sessions, room.num_shuffles_done);
            shuffle::state_update(cur_shuffle);
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
                room.state = STATE__SHUFFLE_IN_PROGRESS;
            } else if (hand::failed(cur_hand)) {
                // Since we need a new DKG, we don't care about the x+1 shuffle any more, even if it has succeeded/failed.
                room.num_shuffles_done = room.num_shuffles_done + 1;
                punish_culprits(room, hand::get_culprits(cur_hand));
                room.num_hands_done = room.num_hands_done + 1;
                start_dkg(room);
            } else {
                // Hand is in progress...
                // We worry about the shuffle later, even if it is done.
            }
        }
    }

    /// For every troublemaker, mark it offline and remove some of its chips.
    fun punish_culprits(room: &mut PokerRoomState, troublemakers: vector<address>) {
        vector::for_each(troublemakers, |player_addr|{
            let (found, player_idx) = vector::index_of(&room.expected_player_addresses, &player_addr);
            assert!(found, 192725);
            *vector::borrow_mut(&mut room.player_livenesses, player_idx) = false;
            let player_chip_amount = vector::borrow_mut(&mut room.player_chips, player_idx);
            let chips_to_burn = min(*player_chip_amount, room.misbehavior_penalty);
            *player_chip_amount = *player_chip_amount - chips_to_burn;
            room.burned_chips = room.burned_chips + chips_to_burn;
        });
    }

    /// A host calls this to create a room. Room state will be stored as a resource under the host's address.
    #[randomness]
    entry fun create(host: &signer, allowed_players: vector<address>) {
        let player_livenesses = vector::map_ref(&allowed_players, |_| false);
        let player_chips = vector::map_ref<address, u64>(&allowed_players, |_| 100); //TODO: real implementation
        let num_players = vector::length(&allowed_players);
        let room = PokerRoomState {
            num_players,
            last_button_position: num_players - 1,
            expected_player_addresses: allowed_players,
            misbehavior_penalty: 8000,
            card_enc_base: group::rand_element(),
            player_livenesses,
            player_chips,
            burned_chips: 0,
            state: STATE__WAITING_FOR_PLAYERS,
            hands: table::new(),
            dkg_sessions: table::new(),
            shuffle_sessions: table::new(),
            num_dkgs_done: 0,
            num_hands_done: 0,
            num_shuffles_done: 0,
        };
        move_to(host, room)
    }

    /// A player calls this to join a poker room.
    #[randomness]
    entry fun join(player: &signer, room: address) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__WAITING_FOR_PLAYERS, 174045);
        let player_addr = address_of(player);
        let (found, player_idx) = vector::index_of(&room.expected_player_addresses, &player_addr);
        assert!(found, 174046);
        *vector::borrow_mut(&mut room.player_livenesses, player_idx) = true;
        *vector::borrow_mut(&mut room.player_chips, player_idx) = 25000; //TODO: what's the initial value to start the table with?
        // state_transition(room);
    }

    #[randomness]
    entry fun process_dkg_contribution(player: &signer, room: address, session_id: u64, contribution_bytes: vector<u8>) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__DKG_IN_PROGRESS, 174737);
        assert!(room.num_dkgs_done == session_id, 174738);
        let dkg_session = table::borrow_mut(&mut room.dkg_sessions, session_id);
        let (errors, contribution, remainder) = dkg_v0::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 174739);
        assert!(vector::is_empty(&remainder), 174740);
        dkg_v0::process_contribution(player, dkg_session, contribution);
    }

    #[randomness]
    entry fun process_shuffle_contribution(player: &signer, room: address, shuffle_idx: u64, contribution_bytes: vector<u8>) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS || room.state == STATE__SHUFFLE_IN_PROGRESS, 180918);
        assert!(room.num_shuffles_done == shuffle_idx, 180919);
        let shuffle = table::borrow_mut(&mut room.shuffle_sessions, shuffle_idx);
        let (errors, contribution, remainder) = shuffle::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 180920);
        assert!(vector::is_empty(&remainder), 180921);
        shuffle::process_contribution(player, shuffle, contribution);
    }

    entry fun process_private_dealing_reencryption(player: &signer, room: address, hand_idx: u64, dealing_idx: u64, reencyption_bytes: vector<u8>) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS, 124642);
        assert!(room.num_hands_done == hand_idx, 124643);
        let hand = table::borrow_mut(&mut room.hands, hand_idx);
        let (errors, contribution, remainder) = private_card_dealing::decode_reencyption(reencyption_bytes);
        assert!(vector::is_empty(&errors), 124644);
        assert!(vector::is_empty(&remainder), 124645);
        hand::process_private_dealing_reencryption(player, hand, dealing_idx, contribution);
    }

    entry fun process_private_dealing_contribution(player: &signer, room: address, hand_idx: u64, dealing_idx: u64, contribution_bytes: vector<u8>) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS, 124642);
        assert!(room.num_hands_done == hand_idx, 124643);
        let hand = table::borrow_mut(&mut room.hands, hand_idx);
        let (errors, contribution, remainder) = threshold_scalar_mul::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 124644);
        assert!(vector::is_empty(&remainder), 124645);
        hand::process_private_dealing_contribution(player, hand, dealing_idx, contribution);
    }

    entry fun process_public_opening_contribution(player: &signer, room: address, hand_idx: u64, opening_idx: u64, contribution_bytes: vector<u8>) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS, 124642);
        assert!(room.num_hands_done == hand_idx, 124643);
        let hand = table::borrow_mut(&mut room.hands, hand_idx);
        let (errors, contribution, remainder) = threshold_scalar_mul::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 124644);
        assert!(vector::is_empty(&remainder), 124645);
        hand::process_public_opening_contribution(player, hand, opening_idx, contribution);
    }

    #[view]
    public fun get_room_brief(room: address): PokerRoomStateBrief acquires PokerRoomState {
        let room = borrow_global<PokerRoomState>(room);
        let cur_hand = if (room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS) {
            *table::borrow(&room.hands, room.num_hands_done)
        } else {
            hand::dummy_session()
        };
        let cur_dkg_session = if (room.state == STATE__DKG_IN_PROGRESS) {
            *table::borrow(&room.dkg_sessions, room.num_dkgs_done)
        } else {
            dkg_v0::dummy_session()
        };
        let cur_shuffle_session = if (room.state == STATE__SHUFFLE_IN_PROGRESS || room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS) {
            *table::borrow(&room.shuffle_sessions, room.num_shuffles_done)
        } else {
            shuffle::dummy_session()
        };
        PokerRoomStateBrief {
            num_players: room.num_players,
            expected_player_addresses: room.expected_player_addresses,
            player_livenesses: room.player_livenesses,
            card_enc_base: room.card_enc_base,
            player_chips: room.player_chips,
            last_button_position: room.last_button_position,
            state: room.state,
            cur_hand: cur_hand,
            num_hands_done: room.num_hands_done,
            num_dkgs_done: room.num_dkgs_done,
            num_shuffles_done: room.num_shuffles_done,
            cur_dkg_session,
            cur_shuffle_session,
        }
    }

    #[view]
    public fun get_dkg_session(room: address, session_id: u64): contract_owner::dkg_v0::DKGSession acquires PokerRoomState {
        let room = borrow_global<PokerRoomState>(room);
        *table::borrow(&room.dkg_sessions, session_id)
    }

    public fun process_new_invest(player: &signer, room: address, hand_idx: u64, bet: u64) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS, 120142);
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

        // Alice, Bob, Eric join the room.
        join(&alice, host_addr);
        join(&bob, host_addr);
        join(&eric, host_addr);

        state_update(host_addr);

        // Anyone sees we now need to do DKG 0.
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__DKG_IN_PROGRESS, 999);
        assert!(room.num_dkgs_done == 0, 999);

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

        // Anyone sees that DKG 0 finished and shuffle 0 started.
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__SHUFFLE_IN_PROGRESS, 999);
        assert!(room.num_shuffles_done == 0, 999);
        assert!(shuffle::is_waiting_for_contribution(&room.cur_shuffle_session, alice_addr), 999);

        // Alice shuffles first.
        let hand_0_alice_shuffle_contri = shuffle::generate_contribution_locally(&alice, &room.cur_shuffle_session);
        process_shuffle_contribution(&alice, host_addr, 0, shuffle::encode_contribution(&hand_0_alice_shuffle_contri));

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__SHUFFLE_IN_PROGRESS, 999);
        assert!(room.num_shuffles_done == 0, 999);
        assert!(shuffle::is_waiting_for_contribution(&room.cur_shuffle_session, bob_addr), 999);

        // Bob follows.
        let hand_0_bob_shuffle_contri = shuffle::generate_contribution_locally(&bob, &room.cur_shuffle_session);
        process_shuffle_contribution(&bob, host_addr, 0, shuffle::encode_contribution(&hand_0_bob_shuffle_contri));

        state_update(host_addr);
        let room = get_room_brief(host_addr);

        // Eric concludes shuffle 0.
        let hand_0_eric_shuffle_contri = shuffle::generate_contribution_locally(&eric, &room.cur_shuffle_session);
        process_shuffle_contribution(&eric, host_addr, 0, shuffle::encode_contribution(&hand_0_eric_shuffle_contri));

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS, 999);
        assert!(room.num_hands_done == 0, 999);
        hand::is_dealing_private_cards(&room.cur_hand);

        // Initiate 6 private card dealings in parallel.
        let (hand_0_deal_0_alice_secret, hand_0_deal_0_alice_reenc) = private_card_dealing::reencrypt(&alice, hand::borrow_private_dealing_session(&room.cur_hand, 0));
        let (hand_0_deal_1_alice_secret, hand_0_deal_1_alice_reenc) = private_card_dealing::reencrypt(&alice, hand::borrow_private_dealing_session(&room.cur_hand, 1));
        let (hand_0_deal_2_bob_secret, hand_0_deal_2_bob_reenc) = private_card_dealing::reencrypt(&bob, hand::borrow_private_dealing_session(&room.cur_hand, 2));
        let (hand_0_deal_3_bob_secret, hand_0_deal_3_bob_reenc) = private_card_dealing::reencrypt(&bob, hand::borrow_private_dealing_session(&room.cur_hand, 3));
        let (hand_0_deal_4_eric_secret, hand_0_deal_4_eric_reenc) = private_card_dealing::reencrypt(&eric, hand::borrow_private_dealing_session(&room.cur_hand, 4));
        let (hand_0_deal_5_eric_secret, hand_0_deal_5_eric_reenc) = private_card_dealing::reencrypt(&eric, hand::borrow_private_dealing_session(&room.cur_hand, 5));
        process_private_dealing_reencryption(&alice, host_addr, 0, 0, private_card_dealing::encode_reencryption(&hand_0_deal_0_alice_reenc));
        process_private_dealing_reencryption(&alice, host_addr, 0, 1, private_card_dealing::encode_reencryption(&hand_0_deal_1_alice_reenc));
        process_private_dealing_reencryption(&bob, host_addr, 0, 2, private_card_dealing::encode_reencryption(&hand_0_deal_2_bob_reenc));
        process_private_dealing_reencryption(&bob, host_addr, 0, 3, private_card_dealing::encode_reencryption(&hand_0_deal_3_bob_reenc));
        process_private_dealing_reencryption(&eric, host_addr, 0, 4, private_card_dealing::encode_reencryption(&hand_0_deal_4_eric_reenc));
        process_private_dealing_reencryption(&eric, host_addr, 0, 5, private_card_dealing::encode_reencryption(&hand_0_deal_5_eric_reenc));
        state_update(host_addr);
        let room = get_room_brief(host_addr);
        // Everyone does its card dealing duties.
        vector::for_each(vector::range(0, 6), |i| {
            let hand_0_deal_i_scalar_mul_session = private_card_dealing::borrow_scalar_mul_session(hand::borrow_private_dealing_session(&room.cur_hand, i));
            let hand_0_deal_i_player_share = threshold_scalar_mul::generate_contribution(&alice, hand_0_deal_i_scalar_mul_session, &dkg_0_alice_secret_share);
            process_private_dealing_contribution(&alice, host_addr, 0, i, threshold_scalar_mul::encode_contribution(&hand_0_deal_i_player_share));
        });
        vector::for_each(vector::range(0, 6), |i| {
            let hand_0_deal_i_scalar_mul_session = private_card_dealing::borrow_scalar_mul_session(hand::borrow_private_dealing_session(&room.cur_hand, i));
            let hand_0_deal_i_player_share = threshold_scalar_mul::generate_contribution(&bob, hand_0_deal_i_scalar_mul_session, &dkg_0_bob_secret_share);
            process_private_dealing_contribution(&bob, host_addr, 0, i, threshold_scalar_mul::encode_contribution(&hand_0_deal_i_player_share));
        });
        vector::for_each(vector::range(0, 6), |i| {
            let hand_0_deal_i_scalar_mul_session = private_card_dealing::borrow_scalar_mul_session(hand::borrow_private_dealing_session(&room.cur_hand, i));
            let hand_0_deal_i_player_share = threshold_scalar_mul::generate_contribution(&eric, hand_0_deal_i_scalar_mul_session, &dkg_0_eric_secret_share);
            process_private_dealing_contribution(&eric, host_addr, 0, i, threshold_scalar_mul::encode_contribution(&hand_0_deal_i_player_share));
        });

        timestamp::fast_forward_seconds(10);
        state_update(host_addr);

        let room = get_room_brief(host_addr);
        // Assert: Hand 0 is still in progress, in phase 1 betting, Alice's turn.
        assert!(room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS, 999);
        assert!(room.num_hands_done == 0, 999);
        assert!(vector[0, 125, 250] == hand::get_bets(&room.cur_hand), 999);
        assert!(vector[false, false, false] == hand::get_fold_statuses(&room.cur_hand), 999);
        assert!(hand::is_phase_1_betting(&room.cur_hand, option::some(alice_addr)), 999);

        // Alice takes a look at her private cards.
        let hand_0_alice_card_0 = hand::reveal_dealed_card_locally(&alice, &room.cur_hand, 0, hand_0_deal_0_alice_secret);
        let hand_0_alice_card_1 = hand::reveal_dealed_card_locally(&alice, &room.cur_hand, 1, hand_0_deal_1_alice_secret);
        debug::print(&utf8(b"hand_0_alice_card_0:"));
        debug::print(&utils::get_card_text(hand_0_alice_card_0));
        debug::print(&utf8(b"hand_0_alice_card_1:"));
        debug::print(&utils::get_card_text(hand_0_alice_card_1));

        // Bob takes a look at his private cards.
        let hand_0_bob_card_0 = hand::reveal_dealed_card_locally(&bob, &room.cur_hand, 2, hand_0_deal_2_bob_secret);
        let hand_0_bob_card_1 = hand::reveal_dealed_card_locally(&bob, &room.cur_hand, 3, hand_0_deal_3_bob_secret);
        debug::print(&utf8(b"hand_0_bob_card_0:"));
        debug::print(&utils::get_card_text(hand_0_bob_card_0));
        debug::print(&utf8(b"hand_0_bob_card_1:"));
        debug::print(&utils::get_card_text(hand_0_bob_card_1));

        // Eric takes a look at his private cards.
        let hand_0_eric_card_0 = hand::reveal_dealed_card_locally(&eric, &room.cur_hand, 4, hand_0_deal_4_eric_secret);
        let hand_0_eric_card_1 = hand::reveal_dealed_card_locally(&eric, &room.cur_hand, 5, hand_0_deal_5_eric_secret);
        debug::print(&utf8(b"hand_0_eric_card_0:"));
        debug::print(&utils::get_card_text(hand_0_eric_card_0));
        debug::print(&utf8(b"hand_0_eric_card_1:"));
        debug::print(&utils::get_card_text(hand_0_eric_card_1));

        // Alice folds.
        process_new_invest(&alice, host_addr, 0, 0);

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS && room.num_hands_done == 0, 999);
        assert!(vector[0, 125, 250] == hand::get_bets(&room.cur_hand), 999);
        assert!(vector[true, false, false] == hand::get_fold_statuses(&room.cur_hand), 999);
        assert!(hand::is_phase_1_betting(&room.cur_hand, option::some(bob_addr)), 999);


        // Bob raises.
        process_new_invest(&bob, host_addr, 0, 500);

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS && room.num_hands_done == 0, 999);
        assert!(vector[0, 500, 250] == hand::get_bets(&room.cur_hand), 999);
        assert!(vector[true, false, false] == hand::get_fold_statuses(&room.cur_hand), 999);
        assert!(hand::is_phase_1_betting(&room.cur_hand, option::some(eric_addr)), 999);

        // Eric calls.
        process_new_invest(&eric, host_addr, 0, 500);

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS && room.num_hands_done == 0, 999);
        assert!(vector[0, 500, 500] == hand::get_bets(&room.cur_hand), 999);
        assert!(vector[true, false, false] == hand::get_fold_statuses(&room.cur_hand), 999);

        // Time to open 3 community cards.
        assert!(hand::is_dealing_community_cards(&room.cur_hand), 999);

        // Everyone does his card opening duty.
        vector::for_each(vector[0,1,2], |opening_idx|{
            let scalar_mul_session = public_card_opening::borrow_scalar_mul_session(hand::borrow_public_opening_session(&room.cur_hand, opening_idx));
            let share = threshold_scalar_mul::generate_contribution(&bob, scalar_mul_session, &dkg_0_bob_secret_share);
            process_public_opening_contribution(&bob, host_addr, 0, opening_idx, threshold_scalar_mul::encode_contribution(&share));
        });
        vector::for_each(vector[0,1,2], |opening_idx|{
            let scalar_mul_session = public_card_opening::borrow_scalar_mul_session(hand::borrow_public_opening_session(&room.cur_hand, opening_idx));
            let share = threshold_scalar_mul::generate_contribution(&eric, scalar_mul_session, &dkg_0_eric_secret_share);
            process_public_opening_contribution(&eric, host_addr, 0, opening_idx, threshold_scalar_mul::encode_contribution(&share));
        });
        vector::for_each(vector[0,1,2], |opening_idx|{
            let scalar_mul_session = public_card_opening::borrow_scalar_mul_session(hand::borrow_public_opening_session(&room.cur_hand, opening_idx));
            let share = threshold_scalar_mul::generate_contribution(&alice, scalar_mul_session, &dkg_0_alice_secret_share);
            process_public_opening_contribution(&alice, host_addr, 0, opening_idx, threshold_scalar_mul::encode_contribution(&share));
        });

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__HAND_AND_SHUFFLE_IN_PROGRESS && room.num_hands_done == 0, 999);
        assert!(hand::is_phase_2_betting(&room.cur_hand, option::some(bob_addr)), 999);
        let public_card_0 = public_card_opening::get_result(hand::borrow_public_opening_session(&room.cur_hand, 0));
        let public_card_1 = public_card_opening::get_result(hand::borrow_public_opening_session(&room.cur_hand, 1));
        let public_card_2 = public_card_opening::get_result(hand::borrow_public_opening_session(&room.cur_hand, 2));
        // Everyone can look at the 3 public cards.
        debug::print(&utf8(b"hand_0_public_card_0:"));
        debug::print(&utils::get_card_text(public_card_0));
        debug::print(&utf8(b"hand_0_public_card_1:"));
        debug::print(&utils::get_card_text(public_card_1));
        debug::print(&utf8(b"hand_0_public_card_2:"));
        debug::print(&utils::get_card_text(public_card_2));
    }
}
