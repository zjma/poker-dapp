module contract_owner::poker_room_examples {

    #[test_only]
    use std::signer::address_of;
    #[test_only]
    use std::string::utf8;
    #[test_only]
    use std::vector::range;
    #[test_only]
    use aptos_std::debug::print;
    #[test_only]
    use aptos_framework::account;
    #[test_only]
    use aptos_framework::aptos_coin;
    #[test_only]
    use aptos_framework::aptos_coin::AptosCoin;
    #[test_only]
    use aptos_framework::coin;
    #[test_only]
    use aptos_framework::randomness;
    #[test_only]
    use aptos_framework::timestamp;
    #[test_only]
    use contract_owner::dkg_v0;
    #[test_only]
    use contract_owner::game;
    #[test_only]
    use contract_owner::poker_room;
    #[test_only]
    use contract_owner::poker_room::{
        get_room_brief,
        state_update,
        process_shuffle_contribution,
        process_dkg_contribution,
        join,
        create,
        cur_game,
        process_private_dealing_reencryption,
        process_private_dealing_contribution,
        process_public_opening_contribution,
        process_new_bet,
        cur_dkg,
        cur_shuffle,
        is_in_game,
        process_showdown_reveal
    };
    #[test_only]
    use contract_owner::reencryption;
    #[test_only]
    use contract_owner::shuffle;
    #[test_only]
    use contract_owner::threshold_scalar_mul;
    #[test_only]
    use contract_owner::utils;

    #[test(framework = @0x1, host = @0xcafe)]
    fun example(framework: signer, host: signer) {
        randomness::initialize_for_testing(&framework);
        timestamp::set_time_has_started_for_testing(&framework);
        let (burn_cap, mint_cap) = aptos_coin::initialize_for_test(&framework);
        let alice = account::create_account_for_test(@0xaaaa);
        let bob = account::create_account_for_test(@0xbbbb);
        let eric = account::create_account_for_test(@0xeeee);
        coin::register<AptosCoin>(&alice);
        coin::register<AptosCoin>(&bob);
        coin::register<AptosCoin>(&eric);

        print(&utf8(b"Host creates a room with a player allowlist."));
        let alice_addr = address_of(&alice);
        let bob_addr = address_of(&bob);
        let eric_addr = address_of(&eric);
        let host_addr = address_of(&host);
        coin::deposit(alice_addr, coin::mint(25000, &mint_cap));
        coin::deposit(bob_addr, coin::mint(25000, &mint_cap));
        coin::deposit(eric_addr, coin::mint(25000, &mint_cap));
        create(&host, vector[alice_addr, bob_addr, eric_addr]);

        print(&utf8(b"Alice, Bob, Eric join the room."));
        join(&alice, host_addr);
        join(&bob, host_addr);
        join(&eric, host_addr);

        state_update(host_addr);

        print(&utf8(b"Anyone sees we now need to do DKG 0."));
        let room = poker_room::get_room_brief(host_addr);
        assert!(poker_room::is_in_dkg(&room, 0), 999);

        state_update(host_addr);

        print(&utf8(b"Eric contributes to DKG 0."));
        let (dkg_0_eric_secret_share, dkg_0_eric_contribution) =
            dkg_v0::generate_contribution(cur_dkg(&room));
        process_dkg_contribution(
            &eric,
            host_addr,
            0,
            dkg_v0::encode_contribution(&dkg_0_eric_contribution)
        );

        state_update(host_addr);

        print(&utf8(b"Alice contributes to DKG 0."));
        let (dkg_0_alice_secret_share, dkg_0_alice_contribution) =
            dkg_v0::generate_contribution(cur_dkg(&room));
        process_dkg_contribution(
            &alice,
            host_addr,
            0,
            dkg_v0::encode_contribution(&dkg_0_alice_contribution)
        );

        state_update(host_addr);

        print(&utf8(b"Bob contributes to DKG 0."));
        let (dkg_0_bob_secret_share, dkg_0_bob_contribution) =
            dkg_v0::generate_contribution(cur_dkg(&room));
        process_dkg_contribution(
            &bob,
            host_addr,
            0,
            dkg_v0::encode_contribution(&dkg_0_bob_contribution)
        );

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        print(&utf8(b"Anyone sees that DKG 0 finished and shuffle 0 started."));
        assert!(poker_room::is_in_shuffle(&room, 0), 999);
        let cur_shuffle = cur_shuffle(&room);
        assert!(shuffle::is_waiting_for_contribution(cur_shuffle, alice_addr), 999);

        print(&utf8(b"Alice contributes to shuffle 0."));
        let game_0_alice_shuffle_contri =
            shuffle::generate_contribution_locally(&alice, cur_shuffle);
        process_shuffle_contribution(
            &alice,
            host_addr,
            0,
            shuffle::encode_contribution(&game_0_alice_shuffle_contri)
        );

        state_update(host_addr);
        let room = get_room_brief(host_addr);

        print(&utf8(b"Bob contributes to shuffle 0."));
        assert!(poker_room::is_in_shuffle(&room, 0), 999);
        let cur_shuffle = cur_shuffle(&room);
        assert!(shuffle::is_waiting_for_contribution(cur_shuffle, bob_addr), 999);
        let game_0_bob_shuffle_contri =
            shuffle::generate_contribution_locally(&bob, cur_shuffle);
        process_shuffle_contribution(
            &bob,
            host_addr,
            0,
            shuffle::encode_contribution(&game_0_bob_shuffle_contri)
        );

        state_update(host_addr);
        let room = get_room_brief(host_addr);

        print(&utf8(b"Eric contributes to shuffle 0."));
        assert!(poker_room::is_in_shuffle(&room, 0), 999);
        let cur_shuffle = cur_shuffle(&room);
        assert!(shuffle::is_waiting_for_contribution(cur_shuffle, eric_addr), 999);
        let game_0_eric_shuffle_contri =
            shuffle::generate_contribution_locally(&eric, cur_shuffle);
        process_shuffle_contribution(
            &eric,
            host_addr,
            0,
            shuffle::encode_contribution(&game_0_eric_shuffle_contri)
        );

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        print(&utf8(b"Game 0 officially starts. So does shuffle 1."));
        assert!(is_in_game(&room, 0), 999);
        let cur_game = cur_game(&room);
        assert!(game::is_dealing_private_cards(cur_game), 999);

        print(&utf8(b"Initiate 6 private card dealings in parallel."));
        let (game_0_deal_0_alice_secret, game_0_deal_0_alice_reenc) =
            reencryption::reencrypt(
                &alice, game::borrow_private_dealing_session(cur_game, 0)
            );
        let (game_0_deal_1_alice_secret, game_0_deal_1_alice_reenc) =
            reencryption::reencrypt(
                &alice, game::borrow_private_dealing_session(cur_game, 1)
            );
        let (game_0_deal_2_bob_secret, game_0_deal_2_bob_reenc) =
            reencryption::reencrypt(
                &bob, game::borrow_private_dealing_session(cur_game, 2)
            );
        let (game_0_deal_3_bob_secret, game_0_deal_3_bob_reenc) =
            reencryption::reencrypt(
                &bob, game::borrow_private_dealing_session(cur_game, 3)
            );
        let (game_0_deal_4_eric_secret, game_0_deal_4_eric_reenc) =
            reencryption::reencrypt(
                &eric, game::borrow_private_dealing_session(cur_game, 4)
            );
        let (game_0_deal_5_eric_secret, game_0_deal_5_eric_reenc) =
            reencryption::reencrypt(
                &eric, game::borrow_private_dealing_session(cur_game, 5)
            );
        process_private_dealing_reencryption(
            &alice,
            host_addr,
            0,
            0,
            reencryption::encode_reencryption(&game_0_deal_0_alice_reenc)
        );
        process_private_dealing_reencryption(
            &alice,
            host_addr,
            0,
            1,
            reencryption::encode_reencryption(&game_0_deal_1_alice_reenc)
        );
        process_private_dealing_reencryption(
            &bob,
            host_addr,
            0,
            2,
            reencryption::encode_reencryption(&game_0_deal_2_bob_reenc)
        );
        process_private_dealing_reencryption(
            &bob,
            host_addr,
            0,
            3,
            reencryption::encode_reencryption(&game_0_deal_3_bob_reenc)
        );
        process_private_dealing_reencryption(
            &eric,
            host_addr,
            0,
            4,
            reencryption::encode_reencryption(&game_0_deal_4_eric_reenc)
        );
        process_private_dealing_reencryption(
            &eric,
            host_addr,
            0,
            5,
            reencryption::encode_reencryption(&game_0_deal_5_eric_reenc)
        );
        state_update(host_addr);
        let room = get_room_brief(host_addr);

        print(&utf8(b"Everyone does its card dealing duties."));
        assert!(is_in_game(&room, 0), 999);
        let cur_game = cur_game(&room);
        assert!(game::is_dealing_private_cards(cur_game), 999);
        range(0, 6).for_each(|i| {
            let game_0_deal_i_scalar_mul_session =
                reencryption::borrow_scalar_mul_session(
                    game::borrow_private_dealing_session(cur_game, i)
                );
            let game_0_deal_i_player_share =
                threshold_scalar_mul::generate_contribution(
                    &alice,
                    game_0_deal_i_scalar_mul_session,
                    &dkg_0_alice_secret_share
                );
            process_private_dealing_contribution(
                &alice,
                host_addr,
                0,
                i,
                threshold_scalar_mul::encode_contribution(&game_0_deal_i_player_share)
            );
        });
        range(0, 6).for_each(|i| {
            let game_0_deal_i_scalar_mul_session =
                reencryption::borrow_scalar_mul_session(
                    game::borrow_private_dealing_session(cur_game, i)
                );
            let game_0_deal_i_player_share =
                threshold_scalar_mul::generate_contribution(
                    &bob,
                    game_0_deal_i_scalar_mul_session,
                    &dkg_0_bob_secret_share
                );
            process_private_dealing_contribution(
                &bob,
                host_addr,
                0,
                i,
                threshold_scalar_mul::encode_contribution(&game_0_deal_i_player_share)
            );
        });
        range(0, 6).for_each(|i| {
            let game_0_deal_i_scalar_mul_session =
                reencryption::borrow_scalar_mul_session(
                    game::borrow_private_dealing_session(cur_game, i)
                );
            let game_0_deal_i_player_share =
                threshold_scalar_mul::generate_contribution(
                    &eric,
                    game_0_deal_i_scalar_mul_session,
                    &dkg_0_eric_secret_share
                );
            process_private_dealing_contribution(
                &eric,
                host_addr,
                0,
                i,
                threshold_scalar_mul::encode_contribution(&game_0_deal_i_player_share)
            );
        });

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        print(
            &utf8(
                b"Assert: Game 0 is still in progress, in phase 1 betting, Alice's turn."
            )
        );
        assert!(is_in_game(&room, 0), 999);
        assert!(
            vector[false, false, false] == game::get_fold_statuses(cur_game(&room)),
            999
        );
        assert!(game::is_phase_1_betting(cur_game(&room), alice_addr), 999);
        print(&game::get_bets(cur_game(&room)));
        assert!(
            vector[0, 125, 250] == game::get_bets(cur_game(&room)),
            999
        );

        print(&utf8(b"Alice takes a look at her private cards."));
        let game_0_alice_card_0 =
            game::reveal_dealed_card_locally(
                &alice,
                cur_game(&room),
                0,
                game_0_deal_0_alice_secret
            );
        let game_0_alice_card_1 =
            game::reveal_dealed_card_locally(
                &alice,
                cur_game(&room),
                1,
                game_0_deal_1_alice_secret
            );
        print(&utf8(b"game_0_alice_card_0:"));
        print(&utils::get_card_text(game_0_alice_card_0));
        print(&utf8(b"game_0_alice_card_1:"));
        print(&utils::get_card_text(game_0_alice_card_1));

        print(&utf8(b"Bob takes a look at his private cards."));
        let game_0_bob_card_0 =
            game::reveal_dealed_card_locally(
                &bob,
                cur_game(&room),
                2,
                game_0_deal_2_bob_secret
            );
        let game_0_bob_card_1 =
            game::reveal_dealed_card_locally(
                &bob,
                cur_game(&room),
                3,
                game_0_deal_3_bob_secret
            );
        print(&utf8(b"game_0_bob_card_0:"));
        print(&utils::get_card_text(game_0_bob_card_0));
        print(&utf8(b"game_0_bob_card_1:"));
        print(&utils::get_card_text(game_0_bob_card_1));

        print(&utf8(b"Eric takes a look at his private cards."));
        let game_0_eric_card_0 =
            game::reveal_dealed_card_locally(
                &eric,
                cur_game(&room),
                4,
                game_0_deal_4_eric_secret
            );
        let game_0_eric_card_1 =
            game::reveal_dealed_card_locally(
                &eric,
                cur_game(&room),
                5,
                game_0_deal_5_eric_secret
            );
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
        assert!(
            shuffle::is_waiting_for_contribution(cur_shuffle(&room), alice_addr), 999
        );
        let game_1_alice_shuffle_contri =
            shuffle::generate_contribution_locally(&alice, cur_shuffle(&room));
        process_shuffle_contribution(
            &alice,
            host_addr,
            1,
            shuffle::encode_contribution(&game_1_alice_shuffle_contri)
        );

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        print(&utf8(b"Bob contributes to shuffle 1."));
        assert!(shuffle::is_waiting_for_contribution(cur_shuffle(&room), bob_addr), 999);
        let game_1_bob_shuffle_contri =
            shuffle::generate_contribution_locally(&bob, cur_shuffle(&room));
        process_shuffle_contribution(
            &bob,
            host_addr,
            1,
            shuffle::encode_contribution(&game_1_bob_shuffle_contri)
        );

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        print(&utf8(b"Eric contributes to shuffle 1."));
        assert!(
            shuffle::is_waiting_for_contribution(cur_shuffle(&room), eric_addr), 999
        );
        let game_1_eric_shuffle_contri =
            shuffle::generate_contribution_locally(&eric, cur_shuffle(&room));
        process_shuffle_contribution(
            &eric,
            host_addr,
            1,
            shuffle::encode_contribution(&game_1_eric_shuffle_contri)
        );

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(is_in_game(&room, 0), 999);
        print(&utf8(b"Anyone can see shuffle 1 is done."));
        assert!(shuffle::succeeded(cur_shuffle(&room)), 999);
        assert!(
            vector[0, 125, 250] == game::get_bets(cur_game(&room)),
            999
        );
        assert!(
            vector[true, false, false] == game::get_fold_statuses(cur_game(&room)),
            999
        );
        assert!(game::is_phase_1_betting(cur_game(&room), bob_addr), 999);

        print(&utf8(b"Bob raises."));
        process_new_bet(&bob, host_addr, 0, 500);

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(is_in_game(&room, 0), 999);
        assert!(
            vector[0, 500, 250] == game::get_bets(cur_game(&room)),
            999
        );
        assert!(
            vector[true, false, false] == game::get_fold_statuses(cur_game(&room)),
            999
        );
        assert!(game::is_phase_1_betting(cur_game(&room), eric_addr), 999);

        print(&utf8(b"Eric calls."));
        process_new_bet(&eric, host_addr, 0, 500);

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(is_in_game(&room, 0), 999);
        assert!(
            vector[0, 500, 500] == game::get_bets(cur_game(&room)),
            999
        );
        assert!(
            vector[true, false, false] == game::get_fold_statuses(cur_game(&room)),
            999
        );

        print(&utf8(b"Time to open 3 community cards."));
        assert!(game::is_dealing_community_cards(cur_game(&room)), 999);

        print(&utf8(b"Everyone does his card opening duty."));
        vector[0, 1, 2].for_each(|opening_idx| {
            let scalar_mul_session =
                game::borrow_public_opening_session(cur_game(&room), opening_idx);
            let share =
                threshold_scalar_mul::generate_contribution(
                    &bob, scalar_mul_session, &dkg_0_bob_secret_share
                );
            process_public_opening_contribution(
                &bob,
                host_addr,
                0,
                opening_idx,
                threshold_scalar_mul::encode_contribution(&share)
            );
        });
        vector[0, 1, 2].for_each(|opening_idx| {
            let scalar_mul_session =
                game::borrow_public_opening_session(cur_game(&room), opening_idx);
            let share =
                threshold_scalar_mul::generate_contribution(
                    &eric, scalar_mul_session, &dkg_0_eric_secret_share
                );
            process_public_opening_contribution(
                &eric,
                host_addr,
                0,
                opening_idx,
                threshold_scalar_mul::encode_contribution(&share)
            );
        });
        vector[0, 1, 2].for_each(|opening_idx| {
            let scalar_mul_session =
                game::borrow_public_opening_session(cur_game(&room), opening_idx);
            let share =
                threshold_scalar_mul::generate_contribution(
                    &alice, scalar_mul_session, &dkg_0_alice_secret_share
                );
            process_public_opening_contribution(
                &alice,
                host_addr,
                0,
                opening_idx,
                threshold_scalar_mul::encode_contribution(&share)
            );
        });

        state_update(host_addr);

        let room = get_room_brief(host_addr);
        assert!(is_in_game(&room, 0), 999);
        assert!(game::is_phase_2_betting(cur_game(&room), bob_addr), 999);
        print(&utf8(b"Everyone can see the 3 public cards."));
        let public_card_0 = game::get_public_card(cur_game(&room), 0);
        let public_card_1 = game::get_public_card(cur_game(&room), 1);
        let public_card_2 = game::get_public_card(cur_game(&room), 2);
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
        assert!(is_in_game(&room, 0), 999);
        assert!(game::is_phase_2_betting(cur_game(&room), eric_addr), 999);

        print(&utf8(b"Eric bet 300 more chips."));
        process_new_bet(&eric, host_addr, 0, 800);

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(is_in_game(&room, 0), 999);
        let cur_game = cur_game(&room);
        assert!(game::is_phase_2_betting(cur_game, bob_addr), 999);

        print(&utf8(b"Bob calls."));
        process_new_bet(&bob, host_addr, 0, 800);

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(is_in_game(&room, 0), 999);
        let cur_game = cur_game(&room);
        assert!(game::is_opening_4th_community_card(cur_game), 999);

        print(&utf8(b"Opening the 4th public card."));
        let game_0_opening_3 = game::borrow_public_opening_session(cur_game, 3);

        let game_0_opening_3_alice_share =
            threshold_scalar_mul::generate_contribution(
                &alice, game_0_opening_3, &dkg_0_alice_secret_share
            );
        process_public_opening_contribution(
            &alice,
            host_addr,
            0,
            3,
            threshold_scalar_mul::encode_contribution(&game_0_opening_3_alice_share)
        );
        let game_0_opening_3_bob_share =
            threshold_scalar_mul::generate_contribution(
                &bob, game_0_opening_3, &dkg_0_bob_secret_share
            );
        process_public_opening_contribution(
            &bob,
            host_addr,
            0,
            3,
            threshold_scalar_mul::encode_contribution(&game_0_opening_3_bob_share)
        );
        let game_0_opening_3_eric_share =
            threshold_scalar_mul::generate_contribution(
                &eric, game_0_opening_3, &dkg_0_eric_secret_share
            );
        process_public_opening_contribution(
            &eric,
            host_addr,
            0,
            3,
            threshold_scalar_mul::encode_contribution(&game_0_opening_3_eric_share)
        );

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        let cur_game = cur_game(&room);
        assert!(is_in_game(&room, 0), 999);
        assert!(game::is_phase_3_betting(cur_game, bob_addr), 999);

        print(&utf8(b"Anyone can see the 4th public card."));
        let public_card_3 = game::get_public_card(cur_game, 3);
        print(&utf8(b"game_0_public_card_3:"));
        print(&utils::get_card_text(public_card_3));

        print(&utf8(b"Game 0 post-turn betting starts."));
        print(&utf8(b"Bob raises."));
        process_new_bet(&bob, host_addr, 0, 20000);

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        let cur_game = cur_game(&room);
        assert!(is_in_game(&room, 0), 999);
        assert!(game::is_phase_3_betting(cur_game, eric_addr), 999);

        print(&utf8(b"Eric calls."));
        process_new_bet(&eric, host_addr, 0, 20000);

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        let cur_game = cur_game(&room);
        assert!(is_in_game(&room, 0), 999);
        assert!(game::is_opening_5th_community_card(cur_game), 999);

        print(&utf8(b"Opening the 5th public card."));
        let game_0_opening_4 = game::borrow_public_opening_session(cur_game, 4);

        let game_0_opening_4_eric_share =
            threshold_scalar_mul::generate_contribution(
                &eric, game_0_opening_4, &dkg_0_eric_secret_share
            );
        process_public_opening_contribution(
            &eric,
            host_addr,
            0,
            4,
            threshold_scalar_mul::encode_contribution(&game_0_opening_4_eric_share)
        );
        let game_0_opening_4_alice_share =
            threshold_scalar_mul::generate_contribution(
                &alice, game_0_opening_4, &dkg_0_alice_secret_share
            );
        process_public_opening_contribution(
            &alice,
            host_addr,
            0,
            4,
            threshold_scalar_mul::encode_contribution(&game_0_opening_4_alice_share)
        );
        let game_0_opening_4_bob_share =
            threshold_scalar_mul::generate_contribution(
                &bob, game_0_opening_4, &dkg_0_bob_secret_share
            );
        process_public_opening_contribution(
            &bob,
            host_addr,
            0,
            4,
            threshold_scalar_mul::encode_contribution(&game_0_opening_4_bob_share)
        );

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        let cur_game = cur_game(&room);
        assert!(is_in_game(&room, 0), 999);
        assert!(game::is_phase_4_betting(cur_game, bob_addr), 999);

        print(&utf8(b"Anyone can see the 5th public card."));
        let public_card_4 = game::get_public_card(cur_game, 4);

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
        let cur_game = cur_game(&room);
        print(&utf8(b"Game 0 showdown."));
        assert!(game::is_at_showdown(cur_game), 999);

        print(&utf8(b"Bob and Eric reveal their private cards"));
        process_showdown_reveal(
            &eric,
            host_addr,
            0,
            4,
            reencryption::encode_private_state(&game_0_deal_4_eric_secret)
        );
        process_showdown_reveal(
            &eric,
            host_addr,
            0,
            5,
            reencryption::encode_private_state(&game_0_deal_5_eric_secret)
        );
        process_showdown_reveal(
            &bob,
            host_addr,
            0,
            3,
            reencryption::encode_private_state(&game_0_deal_3_bob_secret)
        );
        process_showdown_reveal(
            &bob,
            host_addr,
            0,
            2,
            reencryption::encode_private_state(&game_0_deal_2_bob_secret)
        );

        state_update(host_addr);
        let room = get_room_brief(host_addr);
        assert!(is_in_game(&room, 1), 999);

        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }
}
