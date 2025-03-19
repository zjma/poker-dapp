/// On-chain states and util functions of a Poker room, where:
/// - a host creates a Poker room and defines the users allowed to join and play;
/// - players join and play.
module contract_owner::poker_room {
    use std::signer::address_of;
    use std::vector;
    use aptos_std::debug::print;
    use aptos_std::math64::min;
    use aptos_std::table;
    use aptos_std::table::Table;
    use aptos_framework::timestamp;
    use contract_owner::elgamal;
    use contract_owner::shuffle;
    use contract_owner::reencryption;
    use contract_owner::threshold_scalar_mul;
    use contract_owner::group;
    use contract_owner::game;
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
    /// For lower latency, we initiate the shuffle for game `x+1` as soon as we start game `x`.
    const STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS: u64 = 4;
    const STATE__CLOSED: u64 = 5;

    struct PokerRoomStateBrief has drop {
        num_players: u64,
        expected_player_addresses: vector<address>,
        player_livenesses: vector<bool>,
        card_enc_base: group::Element,
        player_chips: vector<u64>,
        last_button_position: u64,
        state: u64,
        cur_game: game::Session,
        num_games_done: u64,
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
        games: Table<u64, game::Session>,
        num_games_done: u64, // Including successes and failures.
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
        let initial_ciphertexts = vector::map_ref(&card_reprs, |plain| elgamal::enc(&agg_ek, &group::scalar_from_u64(0), plain));
        let deadlines = vector::map(vector::range(0, room.num_players), |i| now_secs + 5 * (i + 1));
        let new_shuffle = shuffle::new_session(agg_ek, initial_ciphertexts, alive_players, deadlines);
        let new_shuffle_id = room.num_shuffles_done;
        table::add(&mut room.shuffle_sessions, new_shuffle_id, new_shuffle);
        room.state = STATE__SHUFFLE_IN_PROGRESS;
    }

    fun start_game_and_shuffle_together(room: &mut PokerRoomState) {
        let last_dkg = table::borrow(&room.dkg_sessions, room.num_dkgs_done - 1);
        let last_dkg_contributors = dkg_v0::get_contributors(last_dkg);
        let alive_player_idxs = vector::filter(vector::range(0, room.num_players), |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0);
        let alive_players = vector::map(alive_player_idxs, |idx|*vector::borrow(&room.expected_player_addresses, idx));
        assert!(last_dkg_contributors == alive_players, 311540);

        let secret_info = dkg_v0::get_shared_secret_public_info(last_dkg);
        let last_shuffle = table::borrow(&room.shuffle_sessions, room.num_shuffles_done - 1);
        let card_reprs = vector::map(shuffle::input_cloned(last_shuffle), |ciph|{
            let (_, _, c_1) = elgamal::unpack_ciphertext(ciph);
            c_1 // The ciphertexts were initially generated with 0-randomizers, so c_1 is equal to the plaintext.
        });
        let shuffled_deck = shuffle::result_cloned(last_shuffle);
        let alive_player_chips = vector::map(alive_player_idxs, |idx|room.player_chips[idx]);
        let new_game_id = room.num_games_done;
        //TODO: calculate who is the BUTTON.
        let new_game = game::new_session(alive_players, alive_player_chips, secret_info, card_reprs, shuffled_deck);
        table::add(&mut room.games, new_game_id, new_game);

        let now_secs = timestamp::now_seconds();
        let (agg_ek, _) = dkg_v0::unpack_shared_secret_public_info(secret_info);
        let card_reprs = vector::map(vector::range(0, 52), |_|group::rand_element());
        let initial_ciphertexts = vector::map_ref(&card_reprs, |plain| elgamal::enc(&agg_ek, &group::scalar_from_u64(0), plain));
        let deadlines = vector::map(vector::range(0, room.num_players), |i| now_secs + 5 * (i + 1));
        let new_shuffle_id = room.num_shuffles_done;
        let new_shuffle = shuffle::new_session(agg_ek, initial_ciphertexts, alive_players, deadlines);
        table::add(&mut room.shuffle_sessions, new_shuffle_id, new_shuffle);

        room.state = STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS;
    }

    /// Anyone can call this to trigger state transitions in the given poker room.
    /// dapp TODO: decide whether the host should run a separate thread to trigger it every x sec, or players should be responsible for it.
    #[randomness]
    entry fun state_update(room_addr: address) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room_addr);
        if (room.state == STATE__WAITING_FOR_PLAYERS) {
            if (vector::all(&room.player_livenesses, |liveness|*liveness)) {
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
                start_game_and_shuffle_together(room);
            } else if (shuffle::failed(cur_shuffle)) {
                let culprit = shuffle::get_culprit(cur_shuffle);
                punish_culprits(room, vector[culprit]);
                room.num_shuffles_done = room.num_shuffles_done + 1;
                start_dkg(room);
            } else {
                // Shuffle still in progress...
            }
        } else if (room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS) {
            let cur_game = table::borrow_mut(&mut room.games, room.num_games_done);
            let cur_shuffle = table::borrow_mut(&mut room.shuffle_sessions, room.num_shuffles_done);
            shuffle::state_update(cur_shuffle);
            game::state_update(cur_game);
            if (game::succeeded(cur_game)) {
                // Apply the game result.
                let (players, new_chip_amounts) = game::get_ending_chips(cur_game);
                let n = vector::length(&players);
                vector::for_each(vector::range(0, n), |i|{
                    let player = *vector::borrow(&players, i);
                    let new_chip_amount = *vector::borrow(&new_chip_amounts, i);
                    let (found, player_idx) = vector::index_of(&room.expected_player_addresses, &player);
                    assert!(found, 192724);
                    room.player_chips[player_idx] = new_chip_amount;
                });
                room.num_games_done = room.num_games_done + 1;
                if (shuffle::succeeded(cur_shuffle)) {
                    room.num_shuffles_done = room.num_shuffles_done + 1;
                    start_game_and_shuffle_together(room);
                } else if (shuffle::failed(cur_shuffle)) {
                    room.num_shuffles_done = room.num_shuffles_done + 1;
                    let culprit = shuffle::get_culprit(cur_shuffle);
                    punish_culprits(room, vector[culprit]);
                    start_dkg(room);
                } else {
                    room.state = STATE__SHUFFLE_IN_PROGRESS;
                }
            } else if (game::failed(cur_game)) {
                // Since we need a new DKG, we don't care about the x+1 shuffle any more, even if it has succeeded/failed.
                room.num_shuffles_done = room.num_shuffles_done + 1;
                punish_culprits(room, game::get_culprits(cur_game));
                room.num_games_done = room.num_games_done + 1;
                start_dkg(room);
            } else {
                // Gand is in progress...
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
            games: table::new(),
            dkg_sessions: table::new(),
            shuffle_sessions: table::new(),
            num_dkgs_done: 0,
            num_games_done: 0,
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
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS || room.state == STATE__SHUFFLE_IN_PROGRESS, 180918);
        assert!(room.num_shuffles_done == shuffle_idx, 180919);
        let shuffle = table::borrow_mut(&mut room.shuffle_sessions, shuffle_idx);
        let (errors, contribution, remainder) = shuffle::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 180920);
        assert!(vector::is_empty(&remainder), 180921);
        shuffle::process_contribution(player, shuffle, contribution);
    }

    entry fun process_private_dealing_reencryption(player: &signer, room: address, game_idx: u64, dealing_idx: u64, reencyption_bytes: vector<u8>) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS, 124642);
        assert!(room.num_games_done == game_idx, 124643);
        let game = table::borrow_mut(&mut room.games, game_idx);
        let (errors, contribution, remainder) = reencryption::decode_reencyption(reencyption_bytes);
        assert!(vector::is_empty(&errors), 124644);
        assert!(vector::is_empty(&remainder), 124645);
        game::process_private_dealing_reencryption(player, game, dealing_idx, contribution);
    }

    entry fun process_private_dealing_contribution(player: &signer, room: address, game_idx: u64, dealing_idx: u64, contribution_bytes: vector<u8>) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS, 124642);
        assert!(room.num_games_done == game_idx, 124643);
        let game = table::borrow_mut(&mut room.games, game_idx);
        let (errors, contribution, remainder) = threshold_scalar_mul::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 124644);
        assert!(vector::is_empty(&remainder), 124645);
        game::process_private_dealing_contribution(player, game, dealing_idx, contribution);
    }

    entry fun process_public_opening_contribution(player: &signer, room: address, game_idx: u64, opening_idx: u64, contribution_bytes: vector<u8>) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS, 124642);
        assert!(room.num_games_done == game_idx, 124643);
        let game = table::borrow_mut(&mut room.games, game_idx);
        let (errors, contribution, remainder) = threshold_scalar_mul::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 124644);
        assert!(vector::is_empty(&remainder), 124645);
        game::process_public_opening_contribution(player, game, opening_idx, contribution);
    }

    entry fun process_showdown_reveal(player: &signer, room: address, game_idx: u64, dealing_idx: u64, private_card_revealing_bytes: vector<u8>) acquires PokerRoomState {
        let (errors, reenc_private_state, remainder) = reencryption::decode_private_state(private_card_revealing_bytes);
        assert!(vector::is_empty(&errors), 102202);
        assert!(vector::is_empty(&remainder), 102203);
        let room = borrow_global_mut<PokerRoomState>(room);
        let game = table::borrow_mut(&mut room.games, game_idx);
        game::process_showdown_reveal(player, game, dealing_idx, reenc_private_state);
    }

    #[view]
    public fun get_room_brief(room: address): PokerRoomStateBrief acquires PokerRoomState {
        let room = borrow_global<PokerRoomState>(room);
        let cur_game = if (room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS) {
            *table::borrow(&room.games, room.num_games_done)
        } else {
            game::dummy_session()
        };
        let cur_dkg_session = if (room.state == STATE__DKG_IN_PROGRESS) {
            *table::borrow(&room.dkg_sessions, room.num_dkgs_done)
        } else {
            dkg_v0::dummy_session()
        };
        let cur_shuffle_session = if (room.state == STATE__SHUFFLE_IN_PROGRESS || room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS) {
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
            cur_game: cur_game,
            num_games_done: room.num_games_done,
            num_dkgs_done: room.num_dkgs_done,
            num_shuffles_done: room.num_shuffles_done,
            cur_dkg_session,
            cur_shuffle_session,
        }
    }

    public fun process_new_bet(player: &signer, room: address, game_idx: u64, bet: u64) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS, 120142);
        assert!(room.num_games_done == game_idx, 120143);
        let game = table::borrow_mut(&mut room.games, game_idx);
        game::process_bet_action(player, game, bet);
    }

    #[test(framework=@0x1, host=@0xcafe, alice=@0xaaaa, bob=@0xbbbb, eric=@0xeeee)]
    fun example(framework: signer, host: signer, alice: signer, bob: signer, eric: signer) acquires PokerRoomState {
        randomness::initialize_for_testing(&framework);
        timestamp::set_time_has_started_for_testing(&framework);

        print(&utf8(b"Host creates a room with a player allowlist."));
        let alice_addr = address_of(&alice);
        let bob_addr = address_of(&bob);
        let eric_addr = address_of(&eric);
        let host_addr = address_of(&host);
        create(&host, vector[alice_addr, bob_addr, eric_addr]);

        print(&utf8(b"Alice, Bob, Eric join the room."));
        join(&alice, host_addr);
        join(&bob, host_addr);
        join(&eric, host_addr);

        state_update(host_addr);

        print(&utf8(b"Anyone sees we now need to do DKG 0."));
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__DKG_IN_PROGRESS, 999);
        assert!(room.num_dkgs_done == 0, 999);

        state_update(host_addr);

        print(&utf8(b"Eric contributes to DKG 0."));
        let (dkg_0_eric_secret_share, dkg_0_eric_contribution) = dkg_v0::generate_contribution(&room.cur_dkg_session);
        process_dkg_contribution(&eric, host_addr, 0, dkg_v0::encode_contribution(&dkg_0_eric_contribution));

        state_update(host_addr);

        print(&utf8(b"Alice contributes to DKG 0."));
        let (dkg_0_alice_secret_share, dkg_0_alice_contribution) = dkg_v0::generate_contribution(&room.cur_dkg_session);
        process_dkg_contribution(&alice, host_addr, 0, dkg_v0::encode_contribution(&dkg_0_alice_contribution));

        state_update(host_addr);

        print(&utf8(b"Bob contributes to DKG 0."));
        let (dkg_0_bob_secret_share, dkg_0_bob_contribution) = dkg_v0::generate_contribution(&room.cur_dkg_session);
        process_dkg_contribution(&bob, host_addr, 0, dkg_v0::encode_contribution(&dkg_0_bob_contribution));

        state_update(host_addr);

        print(&utf8(b"Anyone sees that DKG 0 finished and shuffle 0 started."));
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__SHUFFLE_IN_PROGRESS, 999);
        assert!(room.num_shuffles_done == 0, 999);
        assert!(shuffle::is_waiting_for_contribution(&room.cur_shuffle_session, alice_addr), 999);

        print(&utf8(b"Alice contributes to shuffle 0."));
        let game_0_alice_shuffle_contri = shuffle::generate_contribution_locally(&alice, &room.cur_shuffle_session);
        process_shuffle_contribution(&alice, host_addr, 0, shuffle::encode_contribution(&game_0_alice_shuffle_contri));

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__SHUFFLE_IN_PROGRESS, 999);
        assert!(room.num_shuffles_done == 0, 999);
        assert!(shuffle::is_waiting_for_contribution(&room.cur_shuffle_session, bob_addr), 999);

        print(&utf8(b"Bob contributes to shuffle 0."));
        let game_0_bob_shuffle_contri = shuffle::generate_contribution_locally(&bob, &room.cur_shuffle_session);
        process_shuffle_contribution(&bob, host_addr, 0, shuffle::encode_contribution(&game_0_bob_shuffle_contri));

        state_update(host_addr);
        let room = get_room_brief(host_addr);

        print(&utf8(b"Eric contributes to shuffle 0."));
        let game_0_eric_shuffle_contri = shuffle::generate_contribution_locally(&eric, &room.cur_shuffle_session);
        process_shuffle_contribution(&eric, host_addr, 0, shuffle::encode_contribution(&game_0_eric_shuffle_contri));

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        print(&utf8(b"Game 0 officially starts. So does shuffle 1."));
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS, 999);
        assert!(room.num_games_done == 0, 999);
        game::is_dealing_private_cards(&room.cur_game);

        print(&utf8(b"Initiate 6 private card dealings in parallel."));
        let (game_0_deal_0_alice_secret, game_0_deal_0_alice_reenc) = reencryption::reencrypt(&alice, game::borrow_private_dealing_session(&room.cur_game, 0));
        let (game_0_deal_1_alice_secret, game_0_deal_1_alice_reenc) = reencryption::reencrypt(&alice, game::borrow_private_dealing_session(&room.cur_game, 1));
        let (game_0_deal_2_bob_secret, game_0_deal_2_bob_reenc) = reencryption::reencrypt(&bob, game::borrow_private_dealing_session(&room.cur_game, 2));
        let (game_0_deal_3_bob_secret, game_0_deal_3_bob_reenc) = reencryption::reencrypt(&bob, game::borrow_private_dealing_session(&room.cur_game, 3));
        let (game_0_deal_4_eric_secret, game_0_deal_4_eric_reenc) = reencryption::reencrypt(&eric, game::borrow_private_dealing_session(&room.cur_game, 4));
        let (game_0_deal_5_eric_secret, game_0_deal_5_eric_reenc) = reencryption::reencrypt(&eric, game::borrow_private_dealing_session(&room.cur_game, 5));
        process_private_dealing_reencryption(&alice, host_addr, 0, 0, reencryption::encode_reencryption(&game_0_deal_0_alice_reenc));
        process_private_dealing_reencryption(&alice, host_addr, 0, 1, reencryption::encode_reencryption(&game_0_deal_1_alice_reenc));
        process_private_dealing_reencryption(&bob, host_addr, 0, 2, reencryption::encode_reencryption(&game_0_deal_2_bob_reenc));
        process_private_dealing_reencryption(&bob, host_addr, 0, 3, reencryption::encode_reencryption(&game_0_deal_3_bob_reenc));
        process_private_dealing_reencryption(&eric, host_addr, 0, 4, reencryption::encode_reencryption(&game_0_deal_4_eric_reenc));
        process_private_dealing_reencryption(&eric, host_addr, 0, 5, reencryption::encode_reencryption(&game_0_deal_5_eric_reenc));
        state_update(host_addr);
        let room = get_room_brief(host_addr);
        print(&utf8(b"Everyone does its card dealing duties."));
        vector::for_each(vector::range(0, 6), |i| {
            let game_0_deal_i_scalar_mul_session = reencryption::borrow_scalar_mul_session(
                game::borrow_private_dealing_session(&room.cur_game, i));
            let game_0_deal_i_player_share = threshold_scalar_mul::generate_contribution(&alice, game_0_deal_i_scalar_mul_session, &dkg_0_alice_secret_share);
            process_private_dealing_contribution(&alice, host_addr, 0, i, threshold_scalar_mul::encode_contribution(&game_0_deal_i_player_share));
        });
        vector::for_each(vector::range(0, 6), |i| {
            let game_0_deal_i_scalar_mul_session = reencryption::borrow_scalar_mul_session(
                game::borrow_private_dealing_session(&room.cur_game, i));
            let game_0_deal_i_player_share = threshold_scalar_mul::generate_contribution(&bob, game_0_deal_i_scalar_mul_session, &dkg_0_bob_secret_share);
            process_private_dealing_contribution(&bob, host_addr, 0, i, threshold_scalar_mul::encode_contribution(&game_0_deal_i_player_share));
        });
        vector::for_each(vector::range(0, 6), |i| {
            let game_0_deal_i_scalar_mul_session = reencryption::borrow_scalar_mul_session(
                game::borrow_private_dealing_session(&room.cur_game, i));
            let game_0_deal_i_player_share = threshold_scalar_mul::generate_contribution(&eric, game_0_deal_i_scalar_mul_session, &dkg_0_eric_secret_share);
            process_private_dealing_contribution(&eric, host_addr, 0, i, threshold_scalar_mul::encode_contribution(&game_0_deal_i_player_share));
        });

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        print(&utf8(b"Assert: Game 0 is still in progress, in phase 1 betting, Alice's turn."));
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS, 999);
        assert!(room.num_games_done == 0, 999);
        assert!(vector[false, false, false] == game::get_fold_statuses(&room.cur_game), 999);
        assert!(game::is_phase_1_betting(&room.cur_game, alice_addr), 999);
        print(&game::get_bets(&room.cur_game));
        assert!(vector[0, 125, 250] == game::get_bets(&room.cur_game), 999);

        print(&utf8(b"Alice takes a look at her private cards."));
        let game_0_alice_card_0 = game::reveal_dealed_card_locally(&alice, &room.cur_game, 0, game_0_deal_0_alice_secret);
        let game_0_alice_card_1 = game::reveal_dealed_card_locally(&alice, &room.cur_game, 1, game_0_deal_1_alice_secret);
        print(&utf8(b"game_0_alice_card_0:"));
        print(&utils::get_card_text(game_0_alice_card_0));
        print(&utf8(b"game_0_alice_card_1:"));
        print(&utils::get_card_text(game_0_alice_card_1));

        print(&utf8(b"Bob takes a look at his private cards."));
        let game_0_bob_card_0 = game::reveal_dealed_card_locally(&bob, &room.cur_game, 2, game_0_deal_2_bob_secret);
        let game_0_bob_card_1 = game::reveal_dealed_card_locally(&bob, &room.cur_game, 3, game_0_deal_3_bob_secret);
        print(&utf8(b"game_0_bob_card_0:"));
        print(&utils::get_card_text(game_0_bob_card_0));
        print(&utf8(b"game_0_bob_card_1:"));
        print(&utils::get_card_text(game_0_bob_card_1));

        print(&utf8(b"Eric takes a look at his private cards."));
        let game_0_eric_card_0 = game::reveal_dealed_card_locally(&eric, &room.cur_game, 4, game_0_deal_4_eric_secret);
        let game_0_eric_card_1 = game::reveal_dealed_card_locally(&eric, &room.cur_game, 5, game_0_deal_5_eric_secret);
        print(&utf8(b"game_0_eric_card_0:"));
        print(&utils::get_card_text(game_0_eric_card_0));
        print(&utf8(b"game_0_eric_card_1:"));
        print(&utils::get_card_text(game_0_eric_card_1));

        print(&utf8(b"Alice folds."));
        process_new_bet(&alice, host_addr, 0, 0);

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        print(&utf8(b"They also find some cycles to do shuffle 1."));
        print(&utf8(b"Alice contributes to shuffle 1."));
        assert!(shuffle::is_waiting_for_contribution(&room.cur_shuffle_session, alice_addr), 999);
        let game_1_alice_shuffle_contri = shuffle::generate_contribution_locally(&alice, &room.cur_shuffle_session);
        process_shuffle_contribution(&alice, host_addr, 1, shuffle::encode_contribution(&game_1_alice_shuffle_contri));

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        print(&utf8(b"Bob contributes to shuffle 1."));
        assert!(shuffle::is_waiting_for_contribution(&room.cur_shuffle_session, bob_addr), 999);
        let game_1_bob_shuffle_contri = shuffle::generate_contribution_locally(&bob, &room.cur_shuffle_session);
        process_shuffle_contribution(&bob, host_addr, 1, shuffle::encode_contribution(&game_1_bob_shuffle_contri));

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        print(&utf8(b"Eric contributes to shuffle 1."));
        assert!(shuffle::is_waiting_for_contribution(&room.cur_shuffle_session, eric_addr), 999);
        let game_1_eric_shuffle_contri = shuffle::generate_contribution_locally(&eric, &room.cur_shuffle_session);
        process_shuffle_contribution(&eric, host_addr, 1, shuffle::encode_contribution(&game_1_eric_shuffle_contri));

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS && room.num_games_done == 0, 999);
        print(&utf8(b"Anyone can see shuffle 1 is done."));
        assert!(shuffle::succeeded(&room.cur_shuffle_session), 999);
        assert!(vector[0, 125, 250] == game::get_bets(&room.cur_game), 999);
        assert!(vector[true, false, false] == game::get_fold_statuses(&room.cur_game), 999);
        assert!(game::is_phase_1_betting(&room.cur_game, bob_addr), 999);


        print(&utf8(b"Bob raises."));
        process_new_bet(&bob, host_addr, 0, 500);

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS && room.num_games_done == 0, 999);
        assert!(vector[0, 500, 250] == game::get_bets(&room.cur_game), 999);
        assert!(vector[true, false, false] == game::get_fold_statuses(&room.cur_game), 999);
        assert!(game::is_phase_1_betting(&room.cur_game, eric_addr), 999);

        print(&utf8(b"Eric calls."));
        process_new_bet(&eric, host_addr, 0, 500);

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS && room.num_games_done == 0, 999);
        assert!(vector[0, 500, 500] == game::get_bets(&room.cur_game), 999);
        assert!(vector[true, false, false] == game::get_fold_statuses(&room.cur_game), 999);

        print(&utf8(b"Time to open 3 community cards."));
        assert!(game::is_dealing_community_cards(&room.cur_game), 999);

        print(&utf8(b"Everyone does his card opening duty."));
        vector::for_each(vector[0,1,2], |opening_idx|{
            let scalar_mul_session = public_card_opening::borrow_scalar_mul_session(
                game::borrow_public_opening_session(&room.cur_game, opening_idx));
            let share = threshold_scalar_mul::generate_contribution(&bob, scalar_mul_session, &dkg_0_bob_secret_share);
            process_public_opening_contribution(&bob, host_addr, 0, opening_idx, threshold_scalar_mul::encode_contribution(&share));
        });
        vector::for_each(vector[0,1,2], |opening_idx|{
            let scalar_mul_session = public_card_opening::borrow_scalar_mul_session(
                game::borrow_public_opening_session(&room.cur_game, opening_idx));
            let share = threshold_scalar_mul::generate_contribution(&eric, scalar_mul_session, &dkg_0_eric_secret_share);
            process_public_opening_contribution(&eric, host_addr, 0, opening_idx, threshold_scalar_mul::encode_contribution(&share));
        });
        vector::for_each(vector[0,1,2], |opening_idx|{
            let scalar_mul_session = public_card_opening::borrow_scalar_mul_session(
                game::borrow_public_opening_session(&room.cur_game, opening_idx));
            let share = threshold_scalar_mul::generate_contribution(&alice, scalar_mul_session, &dkg_0_alice_secret_share);
            process_public_opening_contribution(&alice, host_addr, 0, opening_idx, threshold_scalar_mul::encode_contribution(&share));
        });

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS && room.num_games_done == 0, 999);
        assert!(game::is_phase_2_betting(&room.cur_game, bob_addr), 999);
        print(&utf8(b"Everyone can see the 3 public cards."));
        let public_card_0 = public_card_opening::get_result(game::borrow_public_opening_session(&room.cur_game, 0));
        let public_card_1 = public_card_opening::get_result(game::borrow_public_opening_session(&room.cur_game, 1));
        let public_card_2 = public_card_opening::get_result(game::borrow_public_opening_session(&room.cur_game, 2));
        print(&utf8(b"game_0_public_card_0:"));
        print(&utils::get_card_text(public_card_0));
        print(&utf8(b"game_0_public_card_1:"));
        print(&utils::get_card_text(public_card_1));
        print(&utf8(b"game_0_public_card_2:"));
        print(&utils::get_card_text(public_card_2));

        print(&utf8(b"Game 0 post-flop betting starts."));
        print(&utf8(b"Bob checks."));
        process_new_bet(&bob, host_addr, 0, 500);

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS && room.num_games_done == 0, 999);
        assert!(game::is_phase_2_betting(&room.cur_game, eric_addr), 999);

        print(&utf8(b"Eric bet 300 more chips."));
        process_new_bet(&eric, host_addr, 0, 800);

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS && room.num_games_done == 0, 999);
        assert!(game::is_phase_2_betting(&room.cur_game, bob_addr), 999);

        print(&utf8(b"Bob calls."));
        process_new_bet(&bob, host_addr, 0, 800);

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS && room.num_games_done == 0, 999);
        assert!(game::is_opening_4th_community_card(&room.cur_game), 999);

        print(&utf8(b"Opening the 4th public card."));
        let game_0_opening_3 = public_card_opening::borrow_scalar_mul_session(
            game::borrow_public_opening_session(&room.cur_game, 3));

        let game_0_opening_3_alice_share = threshold_scalar_mul::generate_contribution(&alice, game_0_opening_3, &dkg_0_alice_secret_share);
        process_public_opening_contribution(&alice, host_addr, 0, 3, threshold_scalar_mul::encode_contribution(&game_0_opening_3_alice_share));
        let game_0_opening_3_bob_share = threshold_scalar_mul::generate_contribution(&bob, game_0_opening_3, &dkg_0_bob_secret_share);
        process_public_opening_contribution(&bob, host_addr, 0, 3, threshold_scalar_mul::encode_contribution(&game_0_opening_3_bob_share));
        let game_0_opening_3_eric_share = threshold_scalar_mul::generate_contribution(&eric, game_0_opening_3, &dkg_0_eric_secret_share);
        process_public_opening_contribution(&eric, host_addr, 0, 3, threshold_scalar_mul::encode_contribution(&game_0_opening_3_eric_share));

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS && room.num_games_done == 0, 999);
        assert!(game::is_phase_3_betting(&room.cur_game, bob_addr), 999);

        print(&utf8(b"Anyone can see the 4th public card."));
        let public_card_3 = public_card_opening::get_result(game::borrow_public_opening_session(&room.cur_game, 3));
        print(&utf8(b"game_0_public_card_3:"));
        print(&utils::get_card_text(public_card_3));

        print(&utf8(b"Game 0 post-turn betting starts."));
        print(&utf8(b"Bob raises."));
        process_new_bet(&bob, host_addr, 0, 20000);

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS && room.num_games_done == 0, 999);
        assert!(game::is_phase_3_betting(&room.cur_game, eric_addr), 999);

        print(&utf8(b"Eric calls."));
        process_new_bet(&eric, host_addr, 0, 20000);

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS && room.num_games_done == 0, 999);
        assert!(game::is_opening_5th_community_card(&room.cur_game), 999);

        print(&utf8(b"Opening the 5th public card."));
        let game_0_opening_4 = public_card_opening::borrow_scalar_mul_session(
            game::borrow_public_opening_session(&room.cur_game, 4));

        let game_0_opening_4_eric_share = threshold_scalar_mul::generate_contribution(&eric, game_0_opening_4, &dkg_0_eric_secret_share);
        process_public_opening_contribution(&eric, host_addr, 0, 4, threshold_scalar_mul::encode_contribution(&game_0_opening_4_eric_share));
        let game_0_opening_4_alice_share = threshold_scalar_mul::generate_contribution(&alice, game_0_opening_4, &dkg_0_alice_secret_share);
        process_public_opening_contribution(&alice, host_addr, 0, 4, threshold_scalar_mul::encode_contribution(&game_0_opening_4_alice_share));
        let game_0_opening_4_bob_share = threshold_scalar_mul::generate_contribution(&bob, game_0_opening_4, &dkg_0_bob_secret_share);
        process_public_opening_contribution(&bob, host_addr, 0, 4, threshold_scalar_mul::encode_contribution(&game_0_opening_4_bob_share));

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS && room.num_games_done == 0, 999);
        assert!(game::is_phase_4_betting(&room.cur_game, bob_addr), 999);

        print(&utf8(b"Anyone can see the 5th public card."));
        let public_card_4 = public_card_opening::get_result(game::borrow_public_opening_session(&room.cur_game, 4));
        print(&utf8(b"game_0_public_card_4:"));
        print(&utils::get_card_text(public_card_4));

        print(&utf8(b"Game 0 post-river betting starts."));
        print(&utf8(b"Bob checks."));
        process_new_bet(&bob, host_addr, 0, 20000);
        state_update(host_addr);
        print(&utf8(b"Eric checks."));
        process_new_bet(&eric, host_addr, 0, 20000);

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        print(&utf8(b"Game 0 showdown."));
        assert!(game::is_at_showdown(&room.cur_game), 999);

        print(&utf8(b"Bob and Eric reveal their private cards"));
        process_showdown_reveal(&eric, host_addr, 0, 4, reencryption::encode_private_state(&game_0_deal_4_eric_secret));
        process_showdown_reveal(&eric, host_addr, 0, 5, reencryption::encode_private_state(&game_0_deal_5_eric_secret));
        process_showdown_reveal(&bob, host_addr, 0, 3, reencryption::encode_private_state(&game_0_deal_3_bob_secret));
        process_showdown_reveal(&bob, host_addr, 0, 2, reencryption::encode_private_state(&game_0_deal_2_bob_secret));

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS && room.num_games_done == 1, 999);
    }
}
