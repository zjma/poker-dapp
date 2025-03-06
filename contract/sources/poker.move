module contract_owner::poker {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::vector;
    use aptos_std::table;
    use aptos_std::table::Table;
    use contract_owner::deck;
    use contract_owner::group;
    use contract_owner::round;
    use contract_owner::round::PokerRoundSession;
    use contract_owner::dkg_v0;
    use contract_owner::encryption;

    const ROOM_STATE__WAITING_FOR_PLAYERS: u64 = 1;
    const ROOM_STATE__DKG_X_IN_PROGRESS_BEFORE_ROUND_Y: u64 = 2;
    const ROOM_STATE__ROUND_X_IN_PROGRESS: u64 = 3;
    const ROOM_STATE__TERMINATED: u64 = 4;


    struct NestedStateCode has copy, drop, store {
        main: u64,
        x: u64,
        y: u64,
    }

    struct GameRoomStateBrief has drop {
        num_players: u64,
        expected_player_addresses: vector<address>,
        card_enc_base: group::Element,
        player_enc_keys: vector<Option<encryption::EncKey>>,
        player_chips: vector<u64>,
        last_button_position: u64,
        state: NestedStateCode,
        cur_round: round::PokerRoundSession,
        num_rounds_done: u64,
        num_dkgs_done: u64,
        cur_dkg_session: dkg_v0::DKGSession,
    }

    struct GameRoomState has key {
        num_players: u64,
        expected_player_addresses: vector<address>,
        card_enc_base: group::Element,
        player_enc_keys: vector<Option<encryption::EncKey>>,
        player_chips: vector<u64>,
        last_button_position: u64,
        state: NestedStateCode,
        game_rounds: Table<u64, PokerRoundSession>,
        num_rounds_done: u64,
        num_dkgs_done: u64,
        dkg_sessions: Table<u64, dkg_v0::DKGSession>,
    }

    fun start_dkg(room: &mut GameRoomState, dkg_id: u64, participant_indices: vector<u64>, next_round_id: u64) {
        let n = vector::length(&participant_indices);
        let addrs = vector::map<u64, address>(participant_indices, |idx|{*vector::borrow(&room.expected_player_addresses, idx)});
        let dkg_session = dkg_v0::new_session(addrs);
        table::add(&mut room.dkg_sessions, dkg_id, dkg_session);
        room.state = NestedStateCode {
            main: ROOM_STATE__DKG_X_IN_PROGRESS_BEFORE_ROUND_Y,
            x: dkg_id,
            y: next_round_id,
        };
    }

    fun next_alive_player(room: &GameRoomState, pos: u64): u64 {
        let original = pos;
        loop {
            pos = (pos + 1) % room.num_players;
            if (*vector::borrow(&room.player_chips, pos) > 0) return pos;
            // if (pos == original) abort(E_NOBODY_IS_ALIVE);
        }
    }

    fun start_round(room: &mut GameRoomState) {
        let player_addrs = vector[];
        let player_chips = vector[];
        let new_btn_pos = 0xffff;
        let n = 0;
        while (true) {
            let pos = next_alive_player(room, room.last_button_position);
            if (new_btn_pos == 0xffff) {
                new_btn_pos = pos;
            } else if (pos == new_btn_pos) {
                break;
            };
            n = n + 1;
            vector::push_back(&mut player_addrs, *vector::borrow(&room.expected_player_addresses, pos));
            vector::push_back(&mut player_chips, *vector::borrow(&room.player_chips, pos));
        };
        let round_id = room.num_rounds_done;
        let secret_id = room.num_dkgs_done;
        let dkg_session = table::borrow(&room.dkg_sessions, secret_id);
        let (card_ek, ek_shares) = dkg_v0::get_ek_and_shares(dkg_session);
        let (errors, new_round) = round::new_session(player_addrs, player_chips, card_ek, ek_shares);
        table::add(&mut room.game_rounds, round_id, new_round);
        room.state = NestedStateCode {
            main: ROOM_STATE__ROUND_X_IN_PROGRESS,
            x: round_id,
            y: 0,
        }
    }

    /// A host calls this to create a room. Room state will be stored as a resource under the host's address.
    public entry fun create(host: &signer, allowed_players: vector<address>) {
        let player_enc_keys = vector::map_ref<address, Option<encryption::EncKey>>(&allowed_players, |_| option::none());
        let player_chips = vector::map_ref<address, u64>(&allowed_players, |_| 100); //TODO: real implementation
        let num_players = vector::length(&allowed_players);
        let room = GameRoomState {
            num_players,
            last_button_position: num_players - 1,
            expected_player_addresses: allowed_players,
            card_enc_base: group::rand_element(),
            player_enc_keys,
            player_chips,
            state: NestedStateCode {
                main: ROOM_STATE__WAITING_FOR_PLAYERS,
                x: 0,
                y: 0,
            },
            game_rounds: table::new(),
            dkg_sessions: table::new(),
            num_dkgs_done: 0,
            num_rounds_done: 0,
        };
        move_to(host, room)
    }

    /// A player calls this to join a game.
    public entry fun join(player: &signer, game_addr: address, ek: vector<u8>) acquires GameRoomState {
        let room = borrow_global_mut<GameRoomState>(game_addr);
        let num_players = room.num_players;
        assert!(room.state.main == ROOM_STATE__WAITING_FOR_PLAYERS, 174045);
        let player_addr = address_of(player);
        let (found, player_idx) = vector::index_of(&room.expected_player_addresses, &player_addr);
        assert!(found, 174046);
        let (error, ek, remainder) = encryption::decode_enc_key(ek);
        assert!(vector::is_empty(&error), 174047);
        assert!(vector::is_empty(&remainder), 174048);
        *vector::borrow_mut(&mut room.player_enc_keys, player_idx) = option::some(ek);
        if (vector::all(&room.player_enc_keys, |maybe_enc_key|option::is_some(maybe_enc_key))) {
            start_dkg(room, 0, vector::range(0, num_players), 0);
            room.state = NestedStateCode {
                main: ROOM_STATE__DKG_X_IN_PROGRESS_BEFORE_ROUND_Y,
                x: 0,
                y: 0,
            };
        }
    }

    public entry fun process_dkg_contribution(player: &signer, game_addr: address, session_id: u64, contribution_bytes: vector<u8>, proof_bytes: vector<u8>) acquires GameRoomState {
        let room = borrow_global_mut<GameRoomState>(game_addr);
        assert!(room.state.main == ROOM_STATE__DKG_X_IN_PROGRESS_BEFORE_ROUND_Y, 174737);
        assert!(room.num_dkgs_done == session_id, 174738);
        let dkg_session = table::borrow_mut(&mut room.dkg_sessions, session_id);
        let (errors, contribution, remainder) = dkg_v0::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 174739);
        assert!(vector::is_empty(&remainder), 174740);
        let (errors, proof, remainder) = dkg_v0::decode_proof(proof_bytes);
        assert!(vector::is_empty(&errors), 174741);
        assert!(vector::is_empty(&remainder), 174742);
        let (errors, status) = dkg_v0::apply_contribution(player, dkg_session, contribution, proof);
        assert!(vector::is_empty(&errors), 174743);
        if (status == 1) { // Finished!
            start_round(room);
        } else if (status == 2) { // Aborted!!

        }
    }

    public entry fun process_shuffle_contribution(player: &signer, game_addr: address, session_id: u64, shuffle_result_bytes: vector<u8>, proof_bytes: vector<u8>) acquires GameRoomState {
        let room = borrow_global_mut<GameRoomState>(game_addr);
        assert!(room.state.main == ROOM_STATE__ROUND_X_IN_PROGRESS, 180918);
        assert!(room.state.x == session_id, 180919);
        let round = table::borrow_mut(&mut room.game_rounds, session_id);
        let (errors, new_draw_pile, remainder) = deck::decode_shuffle_result(shuffle_result_bytes);
        assert!(vector::is_empty(&errors), 180920);
        assert!(vector::is_empty(&remainder), 180921);
        let (errors, proof, remainder) = deck::decode_shuffle_proof(proof_bytes);
        assert!(vector::is_empty(&errors), 180920);
        assert!(vector::is_empty(&remainder), 180921);
        let (errors, major_state_change) = round::process_shuffle_contribution(player, round, new_draw_pile, proof);
        assert!(vector::is_empty(&errors), 180920);
        if (major_state_change == 1) { // Finished!
            // should no happen
            assert!(vector::is_empty(&errors), 180921);
        } else if (major_state_change == 2) { // Aborted!!
            // must be an uncontinuable shuffle.
            //TODO: publish the culprit.
            // start the next round.
            start_round(room);
        }
    }

    public entry fun threshold_decryption_action(player: &signer, game_addr: address, session_id: vector<u8>, action: vector<u8>) {

    }

    public entry fun verifiable_shuffle_action(player: &signer, game_addr: address, session_id: vector<u8>, action: vector<u8>) {

    }

    #[view]
    public fun get_room_state(room: address): GameRoomStateBrief acquires GameRoomState {
        let room = borrow_global<GameRoomState>(room);
        let cur_round = if (room.state.main == ROOM_STATE__ROUND_X_IN_PROGRESS) {
            *table::borrow(&room.game_rounds, room.state.x)
        } else {
            round::dummy_session()
        };
        let cur_dkg_session = if (room.state.main == ROOM_STATE__DKG_X_IN_PROGRESS_BEFORE_ROUND_Y) {
            *table::borrow(&room.dkg_sessions, room.state.x)
        } else {
            dkg_v0::dummy_session()
        };
        GameRoomStateBrief {
            num_players: room.num_players,
            expected_player_addresses: room.expected_player_addresses,
            card_enc_base: room.card_enc_base,
            player_enc_keys: room.player_enc_keys,
            player_chips: room.player_chips,
            last_button_position: room.last_button_position,
            state: room.state,
            cur_round,
            num_rounds_done: room.num_rounds_done,
            num_dkgs_done: room.num_dkgs_done,
            cur_dkg_session,
        }
    }

    #[view]
    public fun get_round_session(room: address, session_id: u64): PokerRoundSession acquires GameRoomState {
        let room = borrow_global<GameRoomState>(room);
        *table::borrow(&room.game_rounds, session_id)
    }

    #[view]
    public fun get_dkg_session(room: address, session_id: u64): contract_owner::dkg_v0::DKGSession acquires GameRoomState {
        let room = borrow_global<GameRoomState>(room);
        *table::borrow(&room.dkg_sessions, session_id)
    }

    #[test(framework=@0x1, host=@0xcafe, alice=@0xaaaa, bob=@0xbbbb, eric=@0xeeee)]
    fun end_to_end(framework: signer, host: signer, alice: signer, bob: signer, eric: signer) acquires GameRoomState {
        // Host creates a room with a player allowlist.
        let alice_addr = address_of(&alice);
        let bob_addr = address_of(&bob);
        let eric_addr = address_of(&eric);
        let host_addr = address_of(&host);
        create(&host, vector[alice_addr, bob_addr, eric_addr]);

        // Anyone can see the initial room states, including the encryption base.
        let room = get_room_state(host_addr);

        // Alice joins the room.
        let (alice_dk, alice_ek) = encryption::key_gen(room.card_enc_base);
        join(&alice, host_addr, encryption::encode_enc_key(&alice_ek));

        // Bob joins the room.
        let (bob_dk, bob_ek) = encryption::key_gen(room.card_enc_base);
        join(&bob, host_addr, encryption::encode_enc_key(&bob_ek));

        // Eric joins the room.
        let (eric_dk, eric_ek) = encryption::key_gen(room.card_enc_base);
        join(&eric, host_addr, encryption::encode_enc_key(&eric_ek));

        // Anyone sees we now need to do DKG 0.
        let room = get_room_state(host_addr);
        assert!(room.state == NestedStateCode {main: ROOM_STATE__DKG_X_IN_PROGRESS_BEFORE_ROUND_Y, x: 0, y: 0}, 999);

        let dkg_session = get_dkg_session(host_addr, room.state.x);
        // Eric contributes to DKG 0.
        let (dkg_0_eric_contri, dkg_0_eric_proof) = dkg_v0::generate_contribution(&dkg_session);
        process_dkg_contribution(&eric, host_addr, 0, dkg_v0::encode_contribution(&dkg_0_eric_contri), dkg_v0::encode_proof(&dkg_0_eric_proof));

        // Alice contributes to DKG 0.
        let (dkg_0_alice_contri, dkg_0_alice_proof) = dkg_v0::generate_contribution(&dkg_session);
        process_dkg_contribution(&alice, host_addr, 0, dkg_v0::encode_contribution(&dkg_0_alice_contri), dkg_v0::encode_proof(&dkg_0_alice_proof));

        // Bob contributes to DKG 0.
        let (dkg_0_bob_contri, dkg_0_bob_proof) = dkg_v0::generate_contribution(&dkg_session);
        process_dkg_contribution(&bob, host_addr, 0, dkg_v0::encode_contribution(&dkg_0_bob_contri), dkg_v0::encode_proof(&dkg_0_bob_proof));

        // Anyone sees that DKG 0 finished and round 0 started.
        let room = get_room_state(host_addr);
        assert!(room.state == NestedStateCode {main: ROOM_STATE__ROUND_X_IN_PROGRESS, x: 0, y: 0}, 999);
        // Anyone sees that round 0 shuffle needs to be done.
        // Eric shuffles first.
        let round = get_round_session(host_addr, 0);
        assert!(round::is_waiting_for_shuffle_contribution_from(&round, eric_addr), 999);
        let deck = round::borrow_deck(&round);
        let (round_0_eric_shuffle_contri, round_0_eric_shuffle_contri_proof) = deck::shuffle(deck);
        process_shuffle_contribution(&eric, host_addr, 0, deck::encode_shuffle_result(&round_0_eric_shuffle_contri), deck::encode_shuffle_proof(&round_0_eric_shuffle_contri_proof));

        // Alice follows.
        let round = get_round_session(host_addr, 0);
        assert!(round::is_waiting_for_shuffle_contribution_from(&round, alice_addr), 999);
        let deck = round::borrow_deck(&round);
        let (round_0_alice_shuffle_contri, round_0_alice_shuffle_contri_proof) = deck::shuffle(deck);
        process_shuffle_contribution(&alice, host_addr, 0, deck::encode_shuffle_result(&round_0_alice_shuffle_contri), deck::encode_shuffle_proof(&round_0_alice_shuffle_contri_proof));

        // Bob concludes.
        let round = get_round_session(host_addr, 0);
        assert!(round::is_waiting_for_shuffle_contribution_from(&round, bob_addr), 999);
        let deck = round::borrow_deck(&round);
        let (round_0_bob_shuffle_contri, round_0_bob_shuffle_contri_proof) = deck::shuffle(deck);
        process_shuffle_contribution(&bob, host_addr, 0, deck::encode_shuffle_result(&round_0_bob_shuffle_contri), deck::encode_shuffle_proof(&round_0_bob_shuffle_contri_proof));
    }


}
