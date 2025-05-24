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
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::coin;
    use aptos_framework::coin::Coin;
    use aptos_framework::event;
    use aptos_framework::object;
    use poker_game::deck_gen;
    use poker_game::hand;
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

    const STATE__DECKGEN_IN_PROGRESS: u64 = 3;

    /// For lower latency, we initiate the deck-gen for hand `x+1` as soon as we start hand `x`.
    const STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS: u64 = 4;

    /// Winner has been determined.
    const STATE__CLOSED: u64 = 5;

    const INF: u64 = 999999999;
    //
    // //
    // // //
    // Poker room state codes end.

    /// A quick summary of A poker room, but informative enough for a client to figure out what to do next.
    struct SessionBrief has drop, store {
        addr: address,
        expected_player_addresses: vector<address>,
        player_livenesses: vector<bool>,
        player_chips: vector<u64>,
        last_button_position: u64,
        state: u64,
        cur_hand: Option<hand::SessionBrief>,
        num_hands_done: u64,
        num_dkgs_done: u64,
        num_deckgens_done: u64,
        cur_dkg_session: Option<dkg_v0::SessionBrief>,
        cur_deckgen_session: Option<deck_gen::SessionBrief>,
    }

    /// The full state of a poker room.
    struct Session has key {
        num_players: u64,
        expected_player_addresses: vector<address>,
        player_livenesses: vector<bool>,
        misbehavior_penalty: u64,
        player_chips: vector<u64>,
        burned_chips: u64,
        last_button_position: u64,
        state: u64,
        hands: vector<address>,
        num_hands_done: u64, // Including successes and failures.
        num_dkgs_done: u64, // Including successes and failures.
        num_deckgens_done: u64, // Including successes and failures.
        dkg_sessions: vector<address>,
        deckgen_sessions: vector<address>,
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
        std::string::utf8(b"v0.0.12")
    }

    #[randomness]
    /// A host calls this to create a room. Room state will be stored as a resource under the host's address.
    public(friend) entry fun create(
        host: &signer, seed: vector<u8>, allowed_players: vector<address>
    ) {
        let player_livenesses = allowed_players.map_ref(|_| false);
        let player_chips = allowed_players.map_ref::<address, u64>(|_| 0);
        let num_players = allowed_players.length();
        let room = Session {
            num_players,
            last_button_position: num_players - 1,
            expected_player_addresses: allowed_players,
            misbehavior_penalty: 8000,
            player_livenesses,
            player_chips,
            burned_chips: 0,
            state: STATE__WAITING_FOR_PLAYERS,
            hands: vector[],
            dkg_sessions: vector[],
            deckgen_sessions: vector[],
            num_dkgs_done: 0,
            num_hands_done: 0,
            num_deckgens_done: 0,
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
    public(friend) entry fun join(player: &signer, room: address) acquires Session {
        let room = borrow_global_mut<Session>(room);
        assert!(room.state == STATE__WAITING_FOR_PLAYERS, 174045);
        let player_addr = address_of(player);
        let (found, player_idx) = room.expected_player_addresses.index_of(&player_addr);
        assert!(found, 174046);
        room.player_livenesses[player_idx] = true;
        room.player_chips[player_idx] = 25000;
        coin::merge(&mut room.escrewed_funds, coin::withdraw<AptosCoin>(player, 25000));
    }

    #[randomness]
    /// Anyone can call this to trigger state transitions in the given poker room.
    /// dapp TODO: decide whether the host should run a separate thread to trigger it every x sec, or players should be responsible for it.
    public(friend) entry fun state_update(room_addr: address) acquires Session {
        let room = borrow_global_mut<Session>(room_addr);
        if (room.state == STATE__WAITING_FOR_PLAYERS) {
            if (room.player_livenesses.all(|liveness| *liveness)) {
                start_dkg(room_addr);
            }
        } else if (room.state == STATE__DKG_IN_PROGRESS) {
            let cur_dkg_addr = *room.dkg_sessions.borrow(room.num_dkgs_done);
            dkg_v0::state_update(cur_dkg_addr);
            if (dkg_v0::succeeded(cur_dkg_addr)) {
                room.num_dkgs_done += 1;
                start_deckgen(room_addr);
            } else if (dkg_v0::failed(cur_dkg_addr)) {
                punish_culprits(room, dkg_v0::get_culprits(cur_dkg_addr));
                room.num_dkgs_done += 1;
                start_dkg(room_addr);
            } else {
                // DKG is still in progress...
            }
        } else if (room.state == STATE__DECKGEN_IN_PROGRESS) {
            let cur_deckgen_addr = *room.deckgen_sessions.borrow(room.num_deckgens_done);
            deck_gen::state_update(cur_deckgen_addr);
            if (deck_gen::succeeded(cur_deckgen_addr)) {
                room.num_deckgens_done += 1;
                start_hand_and_deckgen_together(room_addr);
            } else if (deck_gen::failed(cur_deckgen_addr)) {
                let culprit = deck_gen::culprit(cur_deckgen_addr);
                punish_culprits(room, vector[culprit]);
                room.num_deckgens_done += 1;
                start_dkg(room_addr);
            } else {
                // Deck-gen still in progress...
            }
        } else if (room.state == STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS) {
            let cur_hand_addr = *room.hands.borrow(room.num_hands_done);
            let cur_deckgen_addr = *room.deckgen_sessions.borrow(room.num_deckgens_done);
            deck_gen::state_update(cur_deckgen_addr);
            hand::state_update(cur_hand_addr);
            if (hand::succeeded(cur_hand_addr)) {
                // Apply the hand result.
                let (players, new_chip_amounts) = hand::get_ending_chips(cur_hand_addr);
                let n = players.length();
                vector::range(0, n).for_each(|i| {
                    let (found, player_idx) = room.expected_player_addresses.index_of(&players[i]);
                    assert!(found, 192724);
                    room.player_chips[player_idx] = new_chip_amounts[i];
                });
                room.num_hands_done += 1;
                if (deck_gen::succeeded(cur_deckgen_addr)) {
                    room.num_deckgens_done += 1;
                    start_hand_and_deckgen_together(room_addr);
                } else if (deck_gen::failed(cur_deckgen_addr)) {
                    room.num_deckgens_done += 1;
                    let culprit = deck_gen::culprit(cur_deckgen_addr);
                    punish_culprits(room, vector[culprit]);
                    start_dkg(room_addr);
                } else {
                    room.state = STATE__DECKGEN_IN_PROGRESS;
                }
            } else if (hand::failed(cur_hand_addr)) {
                // Since we need a new DKG, we don't care about the x+1 deckgen any more, even if it has succeeded/failed.
                room.num_deckgens_done += 1;
                punish_culprits(room, hand::get_culprits(cur_hand_addr));
                room.num_hands_done += 1;
                start_dkg(room_addr);
            } else {
                // Hand is in progress...
                // We worry about the deckgen later, even if it has succeeded.
            }
        };
    }

    #[view]
    /// This is intended for the client to make 1 call and get all the necessary info to figure out what to do next.
    public fun brief(room_addr: address): SessionBrief acquires Session {
        let room = borrow_global<Session>(room_addr);
        let cur_hand =
            if (room.state == STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS) {
                let hand_addr = *room.hands.borrow(room.num_hands_done);
                let hand_brief = hand::brief(hand_addr);
                option::some(hand_brief)
            } else {
                option::none()
            };
        let cur_dkg_session =
            if (room.state == STATE__DKG_IN_PROGRESS) {
                let dkg_addr = *room.dkg_sessions.borrow(room.num_dkgs_done);
                let dkg_brief = dkg_v0::brief(dkg_addr);
                option::some(dkg_brief)
            } else {
                option::none()
            };
        let cur_deckgen_session =
            if (room.state == STATE__DECKGEN_IN_PROGRESS
                || room.state == STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS) {
                let deckgen_addr = *room.deckgen_sessions.borrow(room.num_deckgens_done);
                let deckgen_brief = deck_gen::brief(deckgen_addr);
                option::some(deckgen_brief)
            } else {
                option::none()
            };
        SessionBrief {
            addr: room_addr,
            expected_player_addresses: room.expected_player_addresses,
            player_livenesses: room.player_livenesses,
            player_chips: room.player_chips,
            last_button_position: room.last_button_position,
            state: room.state,
            cur_hand,
            num_hands_done: room.num_hands_done,
            num_dkgs_done: room.num_dkgs_done,
            num_deckgens_done: room.num_deckgens_done,
            cur_dkg_session,
            cur_deckgen_session,
        }
    }

    #[view]
    public fun brief_bcs(room_addr: address): vector<u8> acquires Session {
        bcs::to_bytes(&brief(room_addr))
    }

    public fun cur_dkg_addr(room_addr: address): address acquires Session {
        let room = borrow_global<Session>(room_addr);
        assert!(room.state == STATE__DKG_IN_PROGRESS, 121925);
        *room.dkg_sessions.borrow(room.num_dkgs_done)
    }

    public fun cur_deckgen_addr(room_addr: address): address acquires Session {
        let room = borrow_global<Session>(room_addr);
        assert!(room.state == STATE__DECKGEN_IN_PROGRESS || room.state == STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS, 121926);
        *room.deckgen_sessions.borrow(room.num_deckgens_done)
    }

    public fun cur_hand_addr(room_addr: address): address acquires Session {
        let room = borrow_global<Session>(room_addr);
        assert!(room.state == STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS, 121927);
        *room.hands.borrow(room.num_hands_done)
    }
    //
    // //
    // // //
    // User action entry functions end.

    // Internal functions begin.
    // // //
    // //
    //

    fun start_dkg(room_addr: address) acquires Session {
        let room = borrow_global_mut<Session>(room_addr);
        let alive_player_idxs = vector::range(0, room.num_players).filter(
            |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0
        );
        let alive_players = alive_player_idxs.map(|idx| room.expected_player_addresses[idx]);
        if (room.num_dkgs_done >= 1) {
            let last_dkg = *room.dkg_sessions.borrow(room.num_dkgs_done - 1);
            let last_dkg_contributors = dkg_v0::get_contributors(last_dkg);
            assert!(&last_dkg_contributors != &alive_players, 310223);
        };
        let new_dkg_addr = dkg_v0::new_session(room_addr, alive_players);
        room.dkg_sessions.push_back(new_dkg_addr);
        room.state = STATE__DKG_IN_PROGRESS;
    }

    fun start_deckgen(room_addr: address) acquires Session {
        let room = borrow_global_mut<Session>(room_addr);
        let last_dkg_addr = *room.dkg_sessions.borrow(room.num_dkgs_done - 1);
        let last_dkg_contributors = dkg_v0::get_contributors(last_dkg_addr);
        let alive_player_idxs = vector::range(0, room.num_players).filter(
            |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0
        );
        let alive_players = alive_player_idxs.map(|idx| room.expected_player_addresses[idx]);
        assert!(&last_dkg_contributors == &alive_players, 311540);

        let secret_info = dkg_v0::get_shared_secret_public_info(last_dkg_addr);
        let (_, agg_ek, _ek_shares) = dkg_v0::unpack_shared_secret_public_info(secret_info);
        let new_deckgen = deck_gen::new_session(room_addr, agg_ek, alive_players);
        room.deckgen_sessions.push_back(new_deckgen);
        room.state = STATE__DECKGEN_IN_PROGRESS;
    }

    fun start_hand_and_deckgen_together(room_addr: address) acquires Session {
        let room = borrow_global_mut<Session>(room_addr);
        let last_dkg_addr = *room.dkg_sessions.borrow(room.num_dkgs_done - 1);
        let last_dkg_contributors = dkg_v0::get_contributors(last_dkg_addr);
        let alive_player_idxs = vector::range(0, room.num_players).filter(
            |idx| room.player_livenesses[*idx] && room.player_chips[*idx] > 0
        );
        let alive_players = alive_player_idxs.map(|idx| room.expected_player_addresses[idx]);
        assert!(&last_dkg_contributors == &alive_players, 311540);

        let secret_info = dkg_v0::get_shared_secret_public_info(last_dkg_addr);
        let last_deckgen_addr = *room.deckgen_sessions.borrow(room.num_deckgens_done - 1);
        let alive_player_chips = alive_player_idxs.map(|idx| room.player_chips[idx]);
        //TODO: calculate who is the BUTTON.
        let new_hand_addr =
            hand::new_session(
                room_addr,
                alive_players,
                alive_player_chips,
                secret_info,
                last_deckgen_addr,
            );
        room.hands.push_back(new_hand_addr);

        let (_, agg_ek, _) = dkg_v0::unpack_shared_secret_public_info(secret_info);
        let new_deckgen_addr =
            deck_gen::new_session(
                room_addr,
                agg_ek,
                alive_players,
            );
        room.deckgen_sessions.push_back(new_deckgen_addr);

        room.state = STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS;
    }

    /// For every troublemaker, mark it offline and remove some of its chips.
    fun punish_culprits(room: &mut Session, troublemakers: vector<address>) {
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
    public fun is_in_dkg(room_brief: &SessionBrief, dkg_idx: u64): bool {
        room_brief.state == STATE__DKG_IN_PROGRESS
            && room_brief.num_dkgs_done == dkg_idx
    }

    #[test_only]
    public fun is_in_deckgen(
        room_brief: &SessionBrief, deckgen_idx: u64
    ): bool {
        room_brief.state == STATE__DECKGEN_IN_PROGRESS
            && room_brief.num_deckgens_done == deckgen_idx
    }

    #[test_only]
    public fun is_in_the_middle_of_a_hand(room_brief: &SessionBrief, hand_idx: u64): bool {
        room_brief.state == STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS
            && room_brief.num_hands_done == hand_idx
    }
    //
    // //
    // // //
    // Internal functions end.
}
