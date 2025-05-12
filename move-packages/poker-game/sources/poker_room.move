/// On-chain states and util functions of a Poker room, where:
/// - a host creates a Poker room and defines the users allowed to join and play;
/// - players join and play.
module poker_game::poker_room {
    use std::bcs;
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::vector;
    use aptos_std::math64::min;
    use aptos_std::table;
    use aptos_std::table::Table;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::coin;
    use aptos_framework::coin::Coin;
    use aptos_framework::event;
    use aptos_framework::object;
    use aptos_framework::timestamp;
    use poker_game::hand;
    use crypto_core::elgamal;
    use crypto_core::shuffle;
    use crypto_core::reencryption;
    use crypto_core::threshold_scalar_mul;
    use crypto_core::group;
    use crypto_core::dkg_v0;

    #[test_only]
    friend poker_game::poker_room_examples;

    // Poker room state codes begin.
    // // //
    // //
    //

    /// Waiting for all players to initially join.
    const STATE__WAITING_FOR_PLAYERS: u64 = 1;

    const STATE__DKG_IN_PROGRESS: u64 = 2;

    const STATE__SHUFFLE_IN_PROGRESS: u64 = 3;

    /// For lower latency, we initiate the shuffle for hand `x+1` as soon as we start hand `x`.
    const STATE__HAND_AND_NEXT_SHUFFLE_IN_PROGRESS: u64 = 4;

    /// Winner has been determined.
    const STATE__CLOSED: u64 = 5;

    const INF: u64 = 999999999;
    //
    // //
    // // //
    // Poker room state codes end.

    /// A quick summary of A poker room, but informative enough for a client to figure out what to do next.
    struct PokerRoomStateBrief has drop, store {
        expected_player_addresses: vector<address>,
        player_livenesses: vector<bool>,
        player_chips: vector<u64>,
        last_button_position: u64,
        state: u64,
        cur_hand: Option<hand::Session>,
        num_hands_done: u64,
        num_dkgs_done: u64,
        num_shuffles_done: u64,
        cur_dkg_session: Option<dkg_v0::DKGSession>,
        cur_shuffle_session: Option<shuffle::Session>,
    }

    /// The full state of a poker room.
    struct PokerRoomState has key {
        num_players: u64,
        expected_player_addresses: vector<address>,
        player_livenesses: vector<bool>,
        misbehavior_penalty: u64,
        player_chips: vector<u64>,
        burned_chips: u64,
        last_button_position: u64,
        state: u64,
        hands: Table<u64, hand::Session>,
        num_hands_done: u64, // Including successes and failures.
        num_dkgs_done: u64, // Including successes and failures.
        num_shuffles_done: u64, // Including successes and failures.
        dkg_sessions: Table<u64, dkg_v0::DKGSession>,
        shuffle_sessions: Table<u64, shuffle::Session>,
        escrewed_funds: Coin<AptosCoin>
    }

    #[event]
    struct RoomCreatedEvent has drop, store {
        room_addr: address,
    }

    // User action entry functions begin.
    // // //
    // //
    //

    #[view]
    public fun about(): std::string::String {
        std::string::utf8(b"v0.0.4")
    }

    #[randomness]
    /// A host calls this to create a room. Room state will be stored as a resource under the host's address.
    public(friend) entry fun create(
        host: &signer, seed: vector<u8>, allowed_players: vector<address>
    ) {
        let player_livenesses = allowed_players.map_ref(|_| false);
        let player_chips = allowed_players.map_ref::<address, u64>(|_| 0);
        let num_players = allowed_players.length();
        let room = PokerRoomState {
            num_players,
            last_button_position: num_players - 1,
            expected_player_addresses: allowed_players,
            misbehavior_penalty: 8000,
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
            escrewed_funds: coin::zero()
        };
        let constructor = object::create_named_object(host, seed);
        let obj_signer = object::generate_signer(&constructor);
        let room_addr = address_of(&obj_signer);
        move_to(&obj_signer, room);
        event::emit(RoomCreatedEvent { room_addr });
    }

    #[randomness]
    /// A player calls this to join/re-connect to a poker room.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L79
    public(friend) entry fun join(player: &signer, room: address) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__WAITING_FOR_PLAYERS, 174045);
        let player_addr = address_of(player);
        let (found, player_idx) = room.expected_player_addresses.index_of(&player_addr);
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
        let dkg_session = room.dkg_sessions.borrow_mut(dkg_id);
        let (errors, contribution, remainder) =
            dkg_v0::decode_contribution(contribution_bytes);
        assert!(errors.is_empty(), 174739);
        assert!(remainder.is_empty(), 174740);
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
            room.state == STATE__HAND_AND_NEXT_SHUFFLE_IN_PROGRESS
                || room.state == STATE__SHUFFLE_IN_PROGRESS,
            180918
        );
        assert!(room.num_shuffles_done == shuffle_idx, 180919);
        let shuffle = room.shuffle_sessions.borrow_mut(shuffle_idx);
        let (errors, contribution, remainder) =
            shuffle::decode_contribution(contribution_bytes);
        assert!(errors.is_empty(), 180920);
        assert!(remainder.is_empty(), 180921);
        shuffle::process_contribution(player, shuffle, contribution);
    }


    /// The target player calls this to transform the encrypted card in the `dealing_idx`-th private card dealing in `room`.
    /// Param `reencyption_bytes` is an encoded `reencryption::VerifiableReencrpytion`.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L206
    public(friend) entry fun process_private_dealing_reencryption(
        player: &signer,
        room: address,
        hand_idx: u64,
        dealing_idx: u64,
        reencyption_bytes: vector<u8>
    ) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__HAND_AND_NEXT_SHUFFLE_IN_PROGRESS, 124642);
        assert!(room.num_hands_done == hand_idx, 124643);
        let hand = room.hands.borrow_mut(hand_idx);
        let (errors, contribution, remainder) =
            reencryption::decode_reencyption(reencyption_bytes);
        assert!(errors.is_empty(), 124644);
        assert!(remainder.is_empty(), 124645);
        hand::process_private_dealing_reencryption(
            player, hand, dealing_idx, contribution
        );
    }

    /// Every player calls this to submit its contribution to the `dealing_idx`-th private card dealing in `room`.
    /// Param `reencyption_bytes` is an encoded `threshold_scalar_mul::VerifiableContribution`.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L268
    public(friend) entry fun process_private_dealing_contribution(
        player: &signer,
        room: address,
        hand_idx: u64,
        dealing_idx: u64,
        contribution_bytes: vector<u8>
    ) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__HAND_AND_NEXT_SHUFFLE_IN_PROGRESS, 293636);
        assert!(room.num_hands_done == hand_idx, 293637);
        let hand = room.hands.borrow_mut(hand_idx);
        let (errors, contribution, remainder) =
            threshold_scalar_mul::decode_contribution(contribution_bytes);
        assert!(errors.is_empty(), 293638);
        assert!(remainder.is_empty(), 293639);
        hand::process_private_dealing_contribution(
            player, hand, dealing_idx, contribution
        );
    }

    /// A player calls this to submit its contribution to the `opening_idx`-th public card opening in `room`.
    /// Param `reencyption_bytes` is an encoded `threshold_scalar_mul::VerifiableContribution`.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L509
    public(friend) entry fun process_public_opening_contribution(
        player: &signer,
        room: address,
        hand_idx: u64,
        opening_idx: u64,
        contribution_bytes: vector<u8>
    ) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__HAND_AND_NEXT_SHUFFLE_IN_PROGRESS, 293712);
        assert!(room.num_hands_done == hand_idx, 293713);
        let hand = room.hands.borrow_mut(hand_idx);
        let (errors, contribution, remainder) =
            threshold_scalar_mul::decode_contribution(contribution_bytes);
        assert!(errors.is_empty(), 293714);
        assert!(remainder.is_empty(), 293715);
        hand::process_public_opening_contribution(player, hand, opening_idx, contribution);
    }

    /// A player calls this to update its bet in the `hand_idx`-th hand in `room`.
    /// Param `bet` is the intended new total bet. If the value is 0 or doesn't make sense, it's considered a FOLD.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L465
    public(friend) entry fun process_new_bet(
        player: &signer,
        room: address,
        hand_idx: u64,
        bet: u64
    ) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room);
        assert!(room.state == STATE__HAND_AND_NEXT_SHUFFLE_IN_PROGRESS, 120142);
        assert!(room.num_hands_done == hand_idx, 120143);
        let hand = room.hands.borrow_mut(hand_idx);
        hand::process_bet_action(player, hand, bet);
    }

    /// A player calls this to reveal the `dealing_idx`-th private card in showdown of the `hand_idx`-th hand in `room`.
    /// Param `dealing_idx` is 0-based:  so it should be `2i` or `2i+1` for the i-th player.
    /// Param `private_card_revealing_bytes` is an encoded `reencryption::RecipientPrivateState`.
    ///
    /// Example usage: https://github.com/zjma/poker-dapp/blob/73b8c283fa07041d94acc81d3a0f1dec27ea7968/contract/sources/poker_room_examples.move#L728-L734
    public(friend) entry fun process_showdown_reveal(
        player: &signer,
        room: address,
        hand_idx: u64,
        dealing_idx: u64,
        private_card_revealing_bytes: vector<u8>,
    ) acquires PokerRoomState {
        let (errors, reenc_private_state, remainder) =
            reencryption::decode_private_state(private_card_revealing_bytes);
        assert!(errors.is_empty(), 102202);
        assert!(remainder.is_empty(), 102203);
        let room = borrow_global_mut<PokerRoomState>(room);
        let hand = room.hands.borrow_mut(hand_idx);
        hand::process_showdown_reveal(player, hand, dealing_idx, reenc_private_state);
    }

    #[randomness]
    /// Anyone can call this to trigger state transitions in the given poker room.
    /// dapp TODO: decide whether the host should run a separate thread to trigger it every x sec, or players should be responsible for it.
    public(friend) entry fun state_update(room_addr: address) acquires PokerRoomState {
        let room = borrow_global_mut<PokerRoomState>(room_addr);
        if (room.state == STATE__WAITING_FOR_PLAYERS) {
            if (room.player_livenesses.all(|liveness| *liveness)) {
                start_dkg(room);
            }
        } else if (room.state == STATE__DKG_IN_PROGRESS) {
            let cur_dkg = room.dkg_sessions.borrow_mut(room.num_dkgs_done);
            dkg_v0::state_update(cur_dkg);
            if (dkg_v0::succeeded(cur_dkg)) {
                room.num_dkgs_done += 1;
                start_shuffle(room);
            } else if (dkg_v0::failed(cur_dkg)) {
                punish_culprits(room, dkg_v0::get_culprits(cur_dkg));
                room.num_dkgs_done += 1;
                start_dkg(room);
            } else {
                // DKG is still in progress...
            }
        } else if (room.state == STATE__SHUFFLE_IN_PROGRESS) {
            let cur_shuffle =
                room.shuffle_sessions.borrow_mut(room.num_shuffles_done);
            shuffle::state_update(cur_shuffle);
            if (shuffle::succeeded(cur_shuffle)) {
                room.num_shuffles_done += 1;
                start_hand_and_shuffle_together(room);
            } else if (shuffle::failed(cur_shuffle)) {
                let culprit = shuffle::get_culprit(cur_shuffle);
                punish_culprits(room, vector[culprit]);
                room.num_shuffles_done += 1;
                start_dkg(room);
            } else {
                // Shuffle still in progress...
            }
        } else if (room.state == STATE__HAND_AND_NEXT_SHUFFLE_IN_PROGRESS) {
            let cur_hand = room.hands.borrow_mut(room.num_hands_done);
            let cur_shuffle =
                room.shuffle_sessions.borrow_mut(room.num_shuffles_done);
            shuffle::state_update(cur_shuffle);
            hand::state_update(cur_hand);
            if (hand::succeeded(cur_hand)) {
                // Apply the hand result.
                let (players, new_chip_amounts) = hand::get_ending_chips(cur_hand);
                let n = players.length();
                vector::range(0, n).for_each(|i| {
                    let (found, player_idx) = room.expected_player_addresses.index_of(&players[i]);
                    assert!(found, 192724);
                    room.player_chips[player_idx] = new_chip_amounts[i];
                });
                room.num_hands_done += 1;
                if (shuffle::succeeded(cur_shuffle)) {
                    room.num_shuffles_done += 1;
                    start_hand_and_shuffle_together(room);
                } else if (shuffle::failed(cur_shuffle)) {
                    room.num_shuffles_done += 1;
                    let culprit = shuffle::get_culprit(cur_shuffle);
                    punish_culprits(room, vector[culprit]);
                    start_dkg(room);
                } else {
                    room.state = STATE__SHUFFLE_IN_PROGRESS;
                }
            } else if (hand::failed(cur_hand)) {
                // Since we need a new DKG, we don't care about the x+1 shuffle any more, even if it has succeeded/failed.
                room.num_shuffles_done += 1;
                punish_culprits(room, hand::get_culprits(cur_hand));
                room.num_hands_done += 1;
                start_dkg(room);
            } else {
                // Hand is in progress...
                // We worry about the shuffle later, even if it has succeeded.
            }
        };
    }

    #[view]
    /// This is intended for the client to make 1 call and get all the necessary info to figure out what to do next.
    public fun get_room_brief(room: address): PokerRoomStateBrief acquires PokerRoomState {
        let room = borrow_global<PokerRoomState>(room);
        let cur_hand =
            if (room.state == STATE__HAND_AND_NEXT_SHUFFLE_IN_PROGRESS) {
                option::some(*room.hands.borrow(room.num_hands_done))
            } else {
                option::none()
            };
        let cur_dkg_session =
            if (room.state == STATE__DKG_IN_PROGRESS) {
                option::some(*room.dkg_sessions.borrow(room.num_dkgs_done))
            } else {
                option::none()
            };
        let cur_shuffle_session =
            if (room.state == STATE__SHUFFLE_IN_PROGRESS
                || room.state == STATE__HAND_AND_NEXT_SHUFFLE_IN_PROGRESS) {
                option::some(*room.shuffle_sessions.borrow(room.num_shuffles_done))
            } else {
                option::none()
            };
        PokerRoomStateBrief {
            expected_player_addresses: room.expected_player_addresses,
            player_livenesses: room.player_livenesses,
            player_chips: room.player_chips,
            last_button_position: room.last_button_position,
            state: room.state,
            cur_hand,
            num_hands_done: room.num_hands_done,
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
        let alive_player_idxs = vector::range(0, room.num_players).filter(
            |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0
        );
        let alive_players = alive_player_idxs.map(|idx| room.expected_player_addresses[idx]);
        if (room.num_dkgs_done >= 1) {
            let last_dkg = room.dkg_sessions.borrow(room.num_dkgs_done - 1);
            let last_dkg_contributors = dkg_v0::get_contributors(last_dkg);
            assert!(&last_dkg_contributors != &alive_players, 310223);
        };
        let new_dkg_id = room.num_dkgs_done;
        let new_dkg = dkg_v0::new_session(alive_players);
        room.dkg_sessions.add(new_dkg_id, new_dkg);
        room.state = STATE__DKG_IN_PROGRESS;
    }

    fun start_shuffle(room: &mut PokerRoomState) {
        let last_dkg = room.dkg_sessions.borrow(room.num_dkgs_done - 1);
        let last_dkg_contributors = dkg_v0::get_contributors(last_dkg);
        let alive_player_idxs = vector::range(0, room.num_players).filter(
            |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0
        );
        let alive_players = alive_player_idxs.map(|idx| room.expected_player_addresses[idx]);
        assert!(&last_dkg_contributors == &alive_players, 311540);

        let now_secs = timestamp::now_seconds();
        let secret_info = dkg_v0::get_shared_secret_public_info(last_dkg);
        let (agg_ek, _ek_shares) = dkg_v0::unpack_shared_secret_public_info(secret_info);
        let card_reprs = vector::range(0, 52).map(|_| group::rand_element());
        let initial_ciphertexts = card_reprs.map_ref(|plain| elgamal::enc(&agg_ek, &group::scalar_from_u64(0), plain));
        let deadlines = vector::range(0, room.num_players).map(|i| now_secs + INF + i);
        let new_shuffle =
            shuffle::new_session(
                agg_ek,
                initial_ciphertexts,
                alive_players,
                deadlines
            );
        let new_shuffle_id = room.num_shuffles_done;
        room.shuffle_sessions.add(new_shuffle_id, new_shuffle);
        room.state = STATE__SHUFFLE_IN_PROGRESS;
    }

    fun start_hand_and_shuffle_together(room: &mut PokerRoomState) {
        let last_dkg = room.dkg_sessions.borrow(room.num_dkgs_done - 1);
        let last_dkg_contributors = dkg_v0::get_contributors(last_dkg);
        let alive_player_idxs = vector::range(0, room.num_players).filter(
            |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0
        );
        let alive_players = alive_player_idxs.map(|idx| room.expected_player_addresses[idx]);
        assert!(&last_dkg_contributors == &alive_players, 311540);

        let secret_info = dkg_v0::get_shared_secret_public_info(last_dkg);
        let last_shuffle = room.shuffle_sessions.borrow(room.num_shuffles_done - 1);
        let card_reprs = shuffle::input_cloned(last_shuffle).map(|ciph| {
            let (_, _, c_1) = elgamal::unpack_ciphertext(ciph);
            c_1 // The ciphertexts were initially generated with 0-randomizers, so c_1 is equal to the plaintext.
        });
        let shuffled_deck = shuffle::result_cloned(last_shuffle);
        let alive_player_chips = alive_player_idxs.map(|idx| room.player_chips[idx]);
        let new_hand_id = room.num_hands_done;
        //TODO: calculate who is the BUTTON.
        let new_hand =
            hand::new_session(
                alive_players,
                alive_player_chips,
                secret_info,
                card_reprs,
                shuffled_deck
            );
        room.hands.add(new_hand_id, new_hand);

        let now_secs = timestamp::now_seconds();
        let (agg_ek, _) = dkg_v0::unpack_shared_secret_public_info(secret_info);
        let card_reprs = vector::range(0, 52).map(|_| group::rand_element());
        let initial_ciphertexts = card_reprs.map_ref(|plain| elgamal::enc(&agg_ek, &group::scalar_from_u64(0), plain));
        let deadlines = vector::range(0, room.num_players).map(|i| now_secs + INF + i);
        let new_shuffle_id = room.num_shuffles_done;
        let new_shuffle =
            shuffle::new_session(
                agg_ek,
                initial_ciphertexts,
                alive_players,
                deadlines
            );
        room.shuffle_sessions.add(new_shuffle_id, new_shuffle);

        room.state = STATE__HAND_AND_NEXT_SHUFFLE_IN_PROGRESS;
    }

    /// For every troublemaker, mark it offline and remove some of its chips.
    fun punish_culprits(
        room: &mut PokerRoomState, troublemakers: vector<address>
    ) {
        troublemakers.for_each(|player_addr| {
            let (found, player_idx) = room.expected_player_addresses.index_of(&player_addr);
            assert!(found, 192725);
            room.player_livenesses[player_idx] = false;
            let player_chip_amount = &mut room.player_chips[player_idx];
            let chips_to_burn = min(*player_chip_amount, room.misbehavior_penalty);
            *player_chip_amount -= chips_to_burn;
            room.burned_chips += chips_to_burn;
        });
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
    public fun is_in_the_middle_of_a_hand(room_brief: &PokerRoomStateBrief, hand_idx: u64): bool {
        room_brief.state == STATE__HAND_AND_NEXT_SHUFFLE_IN_PROGRESS
            && room_brief.num_hands_done == hand_idx
    }

    #[test_only]
    public fun cur_hand(room_brief: &PokerRoomStateBrief): &hand::Session {
        room_brief.cur_hand.borrow()
    }

    #[test_only]
    public fun cur_dkg(room_brief: &PokerRoomStateBrief): &dkg_v0::DKGSession {
        room_brief.cur_dkg_session.borrow()
    }

    #[test_only]
    public fun cur_shuffle(room_brief: &PokerRoomStateBrief): &shuffle::Session {
        room_brief.cur_shuffle_session.borrow()
    }

    //
    // //
    // // //
    // Internal functions end.
}
