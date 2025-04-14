/// On-chain states and util functions of a Poker room, where:
/// - a host creates a Poker room and defines the users allowed to join and play;
/// - players join and play.
module contract_owner::poker_room {
    use std::signer::address_of;
    use std::vector;
    use aptos_std::math64::min;
    use aptos_std::table;
    use aptos_std::table::Table;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::coin;
    use aptos_framework::coin::Coin;
    use aptos_framework::timestamp;
    use contract_owner::elgamal;
    use contract_owner::shuffle;
    use contract_owner::reencryption;
    use contract_owner::threshold_scalar_mul;
    use contract_owner::group;
    use contract_owner::game;
    use contract_owner::dkg_v0;

    friend contract_owner::poker_room_examples;

    // Poker room state codes begin.
    // // //
    // //
    //

    /// Waiting for all players to initially join.
    const STATE__WAITING_FOR_PLAYERS: u64 = 1;

    const STATE__DKG_IN_PROGRESS: u64 = 2;

    const STATE__SHUFFLE_IN_PROGRESS: u64 = 3;

    /// For lower latency, we initiate the shuffle for game `x+1` as soon as we start game `x`.
    const STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS: u64 = 4;

    /// Winner has been determined.
    const STATE__CLOSED: u64 = 5;

    //
    // //
    // // //
    // Poker room state codes end.

    /// A quick summary of A poker room, but informative enough for a client to figure out what to do next.
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

    /// The full state of a poker room.
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
        escrewed_funds: Coin<AptosCoin>
    }

    // User action entry functions begin.
    // // //
    // //
    //

    #[randomness]
    /// A host calls this to create a room. Room state will be stored as a resource under the host's address.
    public(friend) entry fun create(
        host: &signer, allowed_players: vector<address>
    ) {
        let player_livenesses = vector::map_ref(&allowed_players, |_| false);
        let player_chips = vector::map_ref<address, u64>(&allowed_players, |_| 0);
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
            escrewed_funds: coin::zero()
        };
        move_to(host, room)
    }

    #[randomness]
    /// A player calls this to join/re-connect to a poker room.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L79
    public(friend) entry fun join(player: &signer, room: address) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__WAITING_FOR_PLAYERS, 174045);
        let player_addr = address_of(player);
        let (found, player_idx) = vector::index_of(
            &room.expected_player_addresses, &player_addr
        );
        assert!(found, 174046);
        room.player_livenesses[player_idx] = true;
        room.player_chips[player_idx] = 25000;
        coin::merge(&mut room.escrewed_funds, coin::withdraw<AptosCoin>(player, 25000));
    }

    #[randomness]
    /// A player calls this to submit a contribution to the `dkg_id`-th DKG in `room`.
    /// Param `contribution_bytes` is an encoded `dkg_v0::VerifiableContribution`.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L94
    public(friend) entry fun process_dkg_contribution(
        player: &signer,
        room: address,
        dkg_id: u64,
        contribution_bytes: vector<u8>
    ) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__DKG_IN_PROGRESS, 174737);
        assert!(room.num_dkgs_done == dkg_id, 174738);
        let dkg_session = table::borrow_mut(&mut room.dkg_sessions, dkg_id);
        let (errors, contribution, remainder) =
            dkg_v0::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 174739);
        assert!(vector::is_empty(&remainder), 174740);
        dkg_v0::process_contribution(player, dkg_session, contribution);
    }

    #[randomness]
    /// A player calls this to submit a contribution to the `shuffle_idx`-th shuffle in `room`.
    /// Param `contribution_bytes` is an encoded `shuffle::VerifiableContribution`.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L135
    public(friend) entry fun process_shuffle_contribution(
        player: &signer,
        room: address,
        shuffle_idx: u64,
        contribution_bytes: vector<u8>
    ) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(
            room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS
                || room.state == STATE__SHUFFLE_IN_PROGRESS,
            180918
        );
        assert!(room.num_shuffles_done == shuffle_idx, 180919);
        let shuffle = table::borrow_mut(&mut room.shuffle_sessions, shuffle_idx);
        let (errors, contribution, remainder) =
            shuffle::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 180920);
        assert!(vector::is_empty(&remainder), 180921);
        shuffle::process_contribution(player, shuffle, contribution);
    }


    /// The target player calls this to transform the encrypted card in the `dealing_idx`-th private card dealing in `room`.
    /// Param `reencyption_bytes` is an encoded `reencryption::VerifiableReencrpytion`.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L206
    public(friend) entry fun process_private_dealing_reencryption(
        player: &signer,
        room: address,
        game_idx: u64,
        dealing_idx: u64,
        reencyption_bytes: vector<u8>
    ) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS, 124642);
        assert!(room.num_games_done == game_idx, 124643);
        let game = table::borrow_mut(&mut room.games, game_idx);
        let (errors, contribution, remainder) =
            reencryption::decode_reencyption(reencyption_bytes);
        assert!(vector::is_empty(&errors), 124644);
        assert!(vector::is_empty(&remainder), 124645);
        game::process_private_dealing_reencryption(
            player, game, dealing_idx, contribution
        );
    }

    /// Every player calls this to submit its contribution to the `dealing_idx`-th private card dealing in `room`.
    /// Param `reencyption_bytes` is an encoded `threshold_scalar_mul::VerifiableContribution`.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L268
    public(friend) entry fun process_private_dealing_contribution(
        player: &signer,
        room: address,
        game_idx: u64,
        dealing_idx: u64,
        contribution_bytes: vector<u8>
    ) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS, 124642);
        assert!(room.num_games_done == game_idx, 124643);
        let game = table::borrow_mut(&mut room.games, game_idx);
        let (errors, contribution, remainder) =
            threshold_scalar_mul::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 124644);
        assert!(vector::is_empty(&remainder), 124645);
        game::process_private_dealing_contribution(
            player, game, dealing_idx, contribution
        );
    }

    /// A player calls this to submit its contribution to the `opening_idx`-th public card opening in `room`.
    /// Param `reencyption_bytes` is an encoded `threshold_scalar_mul::VerifiableContribution`.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L509
    public(friend) entry fun process_public_opening_contribution(
        player: &signer,
        room: address,
        game_idx: u64,
        opening_idx: u64,
        contribution_bytes: vector<u8>
    ) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS, 124642);
        assert!(room.num_games_done == game_idx, 124643);
        let game = table::borrow_mut(&mut room.games, game_idx);
        let (errors, contribution, remainder) =
            threshold_scalar_mul::decode_contribution(contribution_bytes);
        assert!(vector::is_empty(&errors), 124644);
        assert!(vector::is_empty(&remainder), 124645);
        game::process_public_opening_contribution(player, game, opening_idx, contribution);
    }

    /// A player calls this to update its bet in the `game_idx`-th hand in `room`.
    /// Param `bet` is the intended new total bet. If the value is 0 or doesn't make sense, it's considered a FOLD.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L465
    public(friend) entry fun process_new_bet(
        player: &signer,
        room: address,
        game_idx: u64,
        bet: u64
    ) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS, 120142);
        assert!(room.num_games_done == game_idx, 120143);
        let game = table::borrow_mut(&mut room.games, game_idx);
        game::process_bet_action(player, game, bet);
    }

    /// A player calls this to reveal the `dealing_idx`-th private card in showdown of the `game_idx`-th hand in `room`.
    /// Param `dealing_idx` is 0-based:  so it should be `2i` or `2i+1` for the i-th player.
    /// Param `private_card_revealing_bytes` is an encoded `reencryption::RecipientPrivateState`.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L728-L734
    public(friend) entry fun process_showdown_reveal(
        player: &signer,
        room: address,
        game_idx: u64,
        dealing_idx: u64,
        private_card_revealing_bytes: vector<u8>,
    ) acquires PokerRoomState {
        let (errors, reenc_private_state, remainder) =
            reencryption::decode_private_state(private_card_revealing_bytes);
        assert!(vector::is_empty(&errors), 102202);
        assert!(vector::is_empty(&remainder), 102203);
        let room = borrow_global_mut<PokerRoomState>(room);
        let game = table::borrow_mut(&mut room.games, game_idx);
        game::process_showdown_reveal(player, game, dealing_idx, reenc_private_state);
    }

    #[randomness]
    /// Anyone can call this to trigger state transitions in the given poker room.
    /// dapp TODO: decide whether the host should run a separate thread to trigger it every x sec, or players should be responsible for it.
    public(friend) entry fun state_update(room_addr: address) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room_addr);
        if (room.state == STATE__WAITING_FOR_PLAYERS) {
            if (vector::all(&room.player_livenesses, |liveness| *liveness)) {
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
            let cur_shuffle =
                table::borrow_mut(&mut room.shuffle_sessions, room.num_shuffles_done);
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
            let cur_shuffle =
                table::borrow_mut(&mut room.shuffle_sessions, room.num_shuffles_done);
            shuffle::state_update(cur_shuffle);
            game::state_update(cur_game);
            if (game::succeeded(cur_game)) {
                // Apply the game result.
                let (players, new_chip_amounts) = game::get_ending_chips(cur_game);
                let n = vector::length(&players);
                vector::for_each(
                    vector::range(0, n),
                    |i| {
                        let (found, player_idx) = vector::index_of(
                            &room.expected_player_addresses, &players[i]
                        );
                        assert!(found, 192724);
                        room.player_chips[player_idx] = new_chip_amounts[i];
                    }
                );
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

    #[view]
    /// This is intended for the client to make 1 call and get all the necessary info to figure out what to do next.
    public fun get_room_brief(room: address): PokerRoomStateBrief acquires PokerRoomState {
        let room = borrow_global<PokerRoomState>(room);
        let cur_game =
            if (room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS) {
                *table::borrow(&room.games, room.num_games_done)
            } else {
                game::dummy_session()
            };
        let cur_dkg_session =
            if (room.state == STATE__DKG_IN_PROGRESS) {
                *table::borrow(&room.dkg_sessions, room.num_dkgs_done)
            } else {
                dkg_v0::dummy_session()
            };
        let cur_shuffle_session =
            if (room.state == STATE__SHUFFLE_IN_PROGRESS
                || room.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS) {
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
            cur_shuffle_session
        }
    }

    //
    // //
    // // //
    // User action entry functions end.

    // Internal functions begin.
    // // //
    // //
    //

    fun start_dkg(room: &mut PokerRoomState) {
        let alive_player_idxs = vector::filter(
            vector::range(0, room.num_players),
            |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0
        );
        let alive_players = vector::map(
            alive_player_idxs, |idx| room.expected_player_addresses[idx]
        );
        if (room.num_dkgs_done >= 1) {
            let last_dkg = table::borrow(&room.dkg_sessions, room.num_dkgs_done - 1);
            let last_dkg_contributors = dkg_v0::get_contributors(last_dkg);
            assert!(&last_dkg_contributors != &alive_players, 310223);
        };
        let new_dkg_id = room.num_dkgs_done;
        let new_dkg = dkg_v0::new_session(alive_players);
        table::add(&mut room.dkg_sessions, new_dkg_id, new_dkg);
        room.state = STATE__DKG_IN_PROGRESS;
    }

    fun start_shuffle(room: &mut PokerRoomState) {
        let last_dkg = table::borrow(&room.dkg_sessions, room.num_dkgs_done - 1);
        let last_dkg_contributors = dkg_v0::get_contributors(last_dkg);
        let alive_player_idxs = vector::filter(
            vector::range(0, room.num_players),
            |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0
        );
        let alive_players = vector::map(
            alive_player_idxs, |idx| room.expected_player_addresses[idx]
        );
        assert!(&last_dkg_contributors == &alive_players, 311540);

        let now_secs = timestamp::now_seconds();
        let secret_info = dkg_v0::get_shared_secret_public_info(last_dkg);
        let (agg_ek, _ek_shares) = dkg_v0::unpack_shared_secret_public_info(secret_info);
        let card_reprs = vector::map(
            vector::range(0, 52),
            |_| group::rand_element()
        );
        let initial_ciphertexts = vector::map_ref(
            &card_reprs,
            |plain| elgamal::enc(&agg_ek, &group::scalar_from_u64(0), plain)
        );
        let deadlines = vector::map(
            vector::range(0, room.num_players),
            |i| now_secs + 5 * (i + 1)
        );
        let new_shuffle =
            shuffle::new_session(
                agg_ek,
                initial_ciphertexts,
                alive_players,
                deadlines
            );
        let new_shuffle_id = room.num_shuffles_done;
        table::add(&mut room.shuffle_sessions, new_shuffle_id, new_shuffle);
        room.state = STATE__SHUFFLE_IN_PROGRESS;
    }

    fun start_game_and_shuffle_together(room: &mut PokerRoomState) {
        let last_dkg = table::borrow(&room.dkg_sessions, room.num_dkgs_done - 1);
        let last_dkg_contributors = dkg_v0::get_contributors(last_dkg);
        let alive_player_idxs = vector::filter(
            vector::range(0, room.num_players),
            |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0
        );
        let alive_players = vector::map(
            alive_player_idxs, |idx| room.expected_player_addresses[idx]
        );
        assert!(&last_dkg_contributors == &alive_players, 311540);

        let secret_info = dkg_v0::get_shared_secret_public_info(last_dkg);
        let last_shuffle = table::borrow(
            &room.shuffle_sessions, room.num_shuffles_done - 1
        );
        let card_reprs = vector::map(
            shuffle::input_cloned(last_shuffle),
            |ciph| {
                let (_, _, c_1) = elgamal::unpack_ciphertext(ciph);
                c_1 // The ciphertexts were initially generated with 0-randomizers, so c_1 is equal to the plaintext.
            }
        );
        let shuffled_deck = shuffle::result_cloned(last_shuffle);
        let alive_player_chips = vector::map(
            alive_player_idxs, |idx| room.player_chips[idx]
        );
        let new_game_id = room.num_games_done;
        //TODO: calculate who is the BUTTON.
        let new_game =
            game::new_session(
                alive_players,
                alive_player_chips,
                secret_info,
                card_reprs,
                shuffled_deck
            );
        table::add(&mut room.games, new_game_id, new_game);

        let now_secs = timestamp::now_seconds();
        let (agg_ek, _) = dkg_v0::unpack_shared_secret_public_info(secret_info);
        let card_reprs = vector::map(
            vector::range(0, 52),
            |_| group::rand_element()
        );
        let initial_ciphertexts = vector::map_ref(
            &card_reprs,
            |plain| elgamal::enc(&agg_ek, &group::scalar_from_u64(0), plain)
        );
        let deadlines = vector::map(
            vector::range(0, room.num_players),
            |i| now_secs + 5 * (i + 1)
        );
        let new_shuffle_id = room.num_shuffles_done;
        let new_shuffle =
            shuffle::new_session(
                agg_ek,
                initial_ciphertexts,
                alive_players,
                deadlines
            );
        table::add(&mut room.shuffle_sessions, new_shuffle_id, new_shuffle);

        room.state = STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS;
    }

    /// For every troublemaker, mark it offline and remove some of its chips.
    fun punish_culprits(
        room: &mut PokerRoomState, troublemakers: vector<address>
    ) {
        vector::for_each(
            troublemakers,
            |player_addr| {
                let (found, player_idx) = vector::index_of(
                    &room.expected_player_addresses, &player_addr
                );
                assert!(found, 192725);
                room.player_livenesses[player_idx] = false;
                let player_chip_amount = &mut room.player_chips[player_idx];
                let chips_to_burn = min(*player_chip_amount, room.misbehavior_penalty);
                *player_chip_amount = *player_chip_amount - chips_to_burn;
                room.burned_chips = room.burned_chips + chips_to_burn;
            }
        );
    }

    #[test_only]
    public fun is_in_dkg(room_brief: &PokerRoomStateBrief, dkg_idx: u64): bool {
        room_brief.state == STATE__DKG_IN_PROGRESS
            && room_brief.num_dkgs_done == dkg_idx
    }

    #[test_only]
    public fun is_in_shuffle(
        room_brief: &PokerRoomStateBrief, shuffle_idx: u64
    ): bool {
        room_brief.state == STATE__SHUFFLE_IN_PROGRESS
            && room_brief.num_shuffles_done == shuffle_idx
    }

    #[test_only]
    public fun is_in_game(room_brief: &PokerRoomStateBrief, game_idx: u64): bool {
        room_brief.state == STATE__GAME_AND_NEXT_SHUFFLE_IN_PROGRESS
            && room_brief.num_games_done == game_idx
    }

    #[test_only]
    public fun cur_game(room_brief: &PokerRoomStateBrief): &game::Session {
        &room_brief.cur_game
    }

    #[test_only]
    public fun cur_dkg(room_brief: &PokerRoomStateBrief): &dkg_v0::DKGSession {
        &room_brief.cur_dkg_session
    }

    #[test_only]
    public fun cur_shuffle(room_brief: &PokerRoomStateBrief): &shuffle::Session {
        &room_brief.cur_shuffle_session
    }

    //
    // //
    // // //
    // Internal functions end.
}
