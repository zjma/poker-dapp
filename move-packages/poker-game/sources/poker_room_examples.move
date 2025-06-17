#[test_only]
module poker_game::poker_room_examples {
    use std::bcs;
    use poker_game::poker_room::{cur_dkg_addr, cur_deckgen_addr, cur_hand_addr};
    use poker_game::deck_gen;
    #[test_only]
    use poker_game::poker_room::{
        brief,
        state_update,
        join,
        create,
        is_in_dkg,
        is_in_deckgen,
        is_in_the_middle_of_a_hand,
    };

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
    use aptos_framework::object;
    #[test_only]
    use aptos_framework::randomness;
    #[test_only]
    use aptos_framework::timestamp;
    #[test_only]
    use crypto_core::dkg_v0;
    #[test_only]
    use crypto_core::shuffle;
    #[test_only]
    use crypto_core::reencryption;
    #[test_only]
    use crypto_core::threshold_scalar_mul;
    #[test_only]
    use poker_game::hand;
    #[test_only]
    use crypto_core::utils;

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
        coin::deposit(alice_addr, coin::mint(25000, &mint_cap));
        coin::deposit(bob_addr, coin::mint(25000, &mint_cap));
        coin::deposit(eric_addr, coin::mint(25000, &mint_cap));
        let room_seed = b"SOME_ROOM_SEED";
        let room_addr = object::create_object_address(&address_of(&host), room_seed);
        create(&host, room_seed, vector[alice_addr, bob_addr, eric_addr]);

        print(&utf8(b"Alice, Bob, Eric join the room."));
        join(&alice, room_addr);
        join(&bob, room_addr);
        join(&eric, room_addr);

        state_update(room_addr);

        print(&utf8(b"Anyone sees we now need to do DKG 0."));
        let room = brief(room_addr);
        assert!(is_in_dkg(&room, 0), 999);

        state_update(room_addr);
        let dkg_0_addr = cur_dkg_addr(room_addr);
        print(&utf8(b"Eric contributes to DKG 0."));
        let (dkg_0_eric_secret_share, dkg_0_eric_contribution) =
            dkg_v0::generate_contribution(dkg_0_addr);
        dkg_v0::process_contribution(
            &eric,
            dkg_0_addr,
            bcs::to_bytes(&dkg_0_eric_contribution)
        );

        state_update(room_addr);

        print(&utf8(b"Alice contributes to DKG 0."));
        let (dkg_0_alice_secret_share, dkg_0_alice_contribution) =
            dkg_v0::generate_contribution(dkg_0_addr);
        dkg_v0::process_contribution(
            &alice,
            dkg_0_addr,
            bcs::to_bytes(&dkg_0_alice_contribution)
        );

        state_update(room_addr);

        print(&utf8(b"Bob contributes to DKG 0."));
        let (dkg_0_bob_secret_share, dkg_0_bob_contribution) =
            dkg_v0::generate_contribution(dkg_0_addr);
        dkg_v0::process_contribution(
            &bob,
            dkg_0_addr,
            bcs::to_bytes(&dkg_0_bob_contribution)
        );

        state_update(room_addr);
        state_update(room_addr);
        state_update(room_addr);
        state_update(room_addr);
        state_update(room_addr);
        let room = brief(room_addr);
        print(&utf8(b"Anyone sees that DKG 0 finished and deckgen 0 started."));
        assert!(is_in_deckgen(&room, 0), 999);
        let deckgen_0_addr = cur_deckgen_addr(room_addr);
        let deckgen_0_shuffle_0_addr = deck_gen::cur_shuffle_addr(deckgen_0_addr);
        assert!(shuffle::is_waiting_for_contribution(deckgen_0_shuffle_0_addr, alice_addr), 999);

        print(&utf8(b"Alice contributes to shuffle 0."));
        let hand_0_alice_shuffle_contri =
            shuffle::generate_contribution_locally(&alice, deckgen_0_shuffle_0_addr);
        shuffle::process_contribution(
            &alice,
            deckgen_0_shuffle_0_addr,
            bcs::to_bytes(&hand_0_alice_shuffle_contri)
        );

        state_update(room_addr);
        let room = brief(room_addr);

        print(&utf8(b"Bob contributes to shuffle 0."));
        assert!(is_in_deckgen(&room, 0), 999);
        assert!(shuffle::is_waiting_for_contribution(deckgen_0_shuffle_0_addr, bob_addr), 999);
        let hand_0_bob_shuffle_contri =
            shuffle::generate_contribution_locally(&bob, deckgen_0_shuffle_0_addr);
        shuffle::process_contribution(
            &bob,
            deckgen_0_shuffle_0_addr,
            bcs::to_bytes(&hand_0_bob_shuffle_contri)
        );

        state_update(room_addr);
        let room = brief(room_addr);

        print(&utf8(b"Eric contributes to shuffle 0."));
        assert!(is_in_deckgen(&room, 0), 999);
        assert!(shuffle::is_waiting_for_contribution(deckgen_0_shuffle_0_addr, eric_addr), 999);
        let hand_0_eric_shuffle_contri =
            shuffle::generate_contribution_locally(&eric, deckgen_0_shuffle_0_addr);
        shuffle::process_contribution(
            &eric,
            deckgen_0_shuffle_0_addr,
            bcs::to_bytes(&hand_0_eric_shuffle_contri)
        );

        state_update(room_addr);
        let room = brief(room_addr);
        print(&utf8(b"Game 0 officially starts. So does shuffle 1."));
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        let hand_0_addr = cur_hand_addr(room_addr);
        assert!(hand::is_dealing_private_cards(hand_0_addr), 999);
        let hand_0_dealing_addrs = range(0, 6).map(|i| hand::private_dealing_session_addr(hand_0_addr, i));
        print(&utf8(b"Initiate 6 private card dealings in parallel."));
        let (hand_0_deal_0_alice_secret, hand_0_deal_0_alice_reenc) = reencryption::reencrypt(&alice, hand_0_dealing_addrs[0]);
        let (hand_0_deal_1_alice_secret, hand_0_deal_1_alice_reenc) = reencryption::reencrypt(&alice, hand_0_dealing_addrs[1]);
        let (hand_0_deal_2_bob_secret, hand_0_deal_2_bob_reenc) = reencryption::reencrypt(&bob, hand_0_dealing_addrs[2]);
        let (hand_0_deal_3_bob_secret, hand_0_deal_3_bob_reenc) = reencryption::reencrypt(&bob, hand_0_dealing_addrs[3]);
        let (hand_0_deal_4_eric_secret, hand_0_deal_4_eric_reenc) = reencryption::reencrypt(&eric, hand_0_dealing_addrs[4]);
        let (hand_0_deal_5_eric_secret, hand_0_deal_5_eric_reenc) = reencryption::reencrypt(&eric, hand_0_dealing_addrs[5]);
        reencryption::process_reencryption(
            &alice,
            hand_0_dealing_addrs[0],
            bcs::to_bytes(&hand_0_deal_0_alice_reenc)
        );
        reencryption::process_reencryption(
            &alice,
            hand_0_dealing_addrs[1],
            bcs::to_bytes(&hand_0_deal_1_alice_reenc)
        );
        reencryption::process_reencryption(
            &bob,
            hand_0_dealing_addrs[2],
            bcs::to_bytes(&hand_0_deal_2_bob_reenc)
        );
        reencryption::process_reencryption(
            &bob,
            hand_0_dealing_addrs[3],
            bcs::to_bytes(&hand_0_deal_3_bob_reenc)
        );
        reencryption::process_reencryption(
            &eric,
            hand_0_dealing_addrs[4],
            bcs::to_bytes(&hand_0_deal_4_eric_reenc)
        );
        reencryption::process_reencryption(
            &eric,
            hand_0_dealing_addrs[5],
            bcs::to_bytes(&hand_0_deal_5_eric_reenc)
        );
        state_update(room_addr);
        let room = brief(room_addr);

        print(&utf8(b"Everyone does its card dealing duties."));
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        assert!(hand::is_dealing_private_cards(hand_0_addr), 999);
        let hand_0_deal_x_scalar_mul_session_addrs = range(0, 6).map(|x| reencryption::scalar_mul_session_addr(hand::private_dealing_session_addr(hand_0_addr, x)));
        range(0, 6).for_each(|i| {
            let hand_0_deal_x_player_share =
                threshold_scalar_mul::generate_contribution(
                    &alice,
                    hand_0_deal_x_scalar_mul_session_addrs[i],
                    &dkg_0_alice_secret_share
                );
            threshold_scalar_mul::process_contribution(
                &alice,
                hand_0_deal_x_scalar_mul_session_addrs[i],
                bcs::to_bytes(&hand_0_deal_x_player_share)
            );
        });
        range(0, 6).for_each(|i| {
            let hand_0_deal_x_player_share =
                threshold_scalar_mul::generate_contribution(
                    &bob,
                    hand_0_deal_x_scalar_mul_session_addrs[i],
                    &dkg_0_bob_secret_share
                );
            threshold_scalar_mul::process_contribution(
                &bob,
                hand_0_deal_x_scalar_mul_session_addrs[i],
                bcs::to_bytes(&hand_0_deal_x_player_share)
            );
        });
        range(0, 6).for_each(|i| {
            let hand_0_deal_x_player_share =
                threshold_scalar_mul::generate_contribution(
                    &eric,
                    hand_0_deal_x_scalar_mul_session_addrs[i],
                    &dkg_0_eric_secret_share
                );
            threshold_scalar_mul::process_contribution(
                &eric,
                hand_0_deal_x_scalar_mul_session_addrs[i],
                bcs::to_bytes(&hand_0_deal_x_player_share)
            );
        });

        state_update(room_addr);

        let room = brief(room_addr);
        print(
            &utf8(
                b"Assert: Hand 0 is still in progress, in phase 1 betting, Alice's turn."
            )
        );
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        assert!(
            vector[false, false, false] == hand::get_fold_statuses(hand_0_addr),
            999
        );
        assert!(hand::is_phase_1_betting(hand_0_addr, alice_addr), 999);
        print(&hand::get_bets(hand_0_addr));
        assert!(
            vector[0, 125, 250] == hand::get_bets(hand_0_addr),
            999
        );

        print(&utf8(b"Alice takes a look at her private cards."));
        let hand_0_alice_card_0 =
            hand::reveal_dealed_card_locally(
                &alice,
                hand_0_addr,
                0,
                hand_0_deal_0_alice_secret
            );
        let hand_0_alice_card_1 =
            hand::reveal_dealed_card_locally(
                &alice,
                hand_0_addr,
                1,
                hand_0_deal_1_alice_secret
            );
        print(&utf8(b"hand_0_alice_card_0:"));
        print(&utils::get_card_text(hand_0_alice_card_0));
        print(&utf8(b"hand_0_alice_card_1:"));
        print(&utils::get_card_text(hand_0_alice_card_1));

        print(&utf8(b"Bob takes a look at his private cards."));
        let hand_0_bob_card_0 =
            hand::reveal_dealed_card_locally(
                &bob,
                hand_0_addr,
                2,
                hand_0_deal_2_bob_secret
            );
        let hand_0_bob_card_1 =
            hand::reveal_dealed_card_locally(
                &bob,
                hand_0_addr,
                3,
                hand_0_deal_3_bob_secret
            );
        print(&utf8(b"hand_0_bob_card_0:"));
        print(&utils::get_card_text(hand_0_bob_card_0));
        print(&utf8(b"hand_0_bob_card_1:"));
        print(&utils::get_card_text(hand_0_bob_card_1));

        print(&utf8(b"Eric takes a look at his private cards."));
        let hand_0_eric_card_0 =
            hand::reveal_dealed_card_locally(
                &eric,
                hand_0_addr,
                4,
                hand_0_deal_4_eric_secret
            );
        let hand_0_eric_card_1 =
            hand::reveal_dealed_card_locally(
                &eric,
                hand_0_addr,
                5,
                hand_0_deal_5_eric_secret
            );
        print(&utf8(b"hand_0_eric_card_0:"));
        print(&utils::get_card_text(hand_0_eric_card_0));
        print(&utf8(b"hand_0_eric_card_1:"));
        print(&utils::get_card_text(hand_0_eric_card_1));

        print(&utf8(b"Alice folds."));
        hand::process_bet_action(&alice, hand_0_addr, 0);

        state_update(room_addr);
        state_update(room_addr);
        state_update(room_addr);
        state_update(room_addr);
        state_update(room_addr);
        print(&utf8(b"They also find some cycles to do shuffle 1."));
        print(&utf8(b"Alice contributes to shuffle 1."));
        let deckgen_1_addr = cur_deckgen_addr(room_addr);
        let deckgen_1_shuffle_0_addr = deck_gen::cur_shuffle_addr(deckgen_1_addr);
        assert!(
            shuffle::is_waiting_for_contribution(deckgen_1_shuffle_0_addr, alice_addr), 999
        );
        let deckgen_1_alice_shuffle_contri =
            shuffle::generate_contribution_locally(&alice, deckgen_1_shuffle_0_addr);
        shuffle::process_contribution(
            &alice,
            deckgen_1_shuffle_0_addr,
            bcs::to_bytes(&deckgen_1_alice_shuffle_contri)
        );

        state_update(room_addr);
        print(&utf8(b"Bob contributes to shuffle 1."));
        assert!(shuffle::is_waiting_for_contribution(deckgen_1_shuffle_0_addr, bob_addr), 999);
        let deckgen_1_bob_shuffle_contri =
            shuffle::generate_contribution_locally(&bob, deckgen_1_shuffle_0_addr);
        shuffle::process_contribution(
            &bob,
            deckgen_1_shuffle_0_addr,
            bcs::to_bytes(&deckgen_1_bob_shuffle_contri)
        );

        state_update(room_addr);
        print(&utf8(b"Eric contributes to shuffle 1."));
        assert!(
            shuffle::is_waiting_for_contribution(deckgen_1_shuffle_0_addr, eric_addr), 999
        );
        let game_1_eric_shuffle_contri =
            shuffle::generate_contribution_locally(&eric, deckgen_1_shuffle_0_addr);
        shuffle::process_contribution(
            &eric,
            deckgen_1_shuffle_0_addr,
            bcs::to_bytes(&game_1_eric_shuffle_contri)
        );

        state_update(room_addr);
        let room = brief(room_addr);
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        print(&utf8(b"Anyone can see deckgen 1 is done."));
        assert!(deck_gen::succeeded(deckgen_1_addr), 999);
        assert!(
            vector[0, 125, 250] == hand::get_bets(hand_0_addr),
            999
        );
        assert!(
            vector[true, false, false] == hand::get_fold_statuses(hand_0_addr),
            999
        );
        assert!(hand::is_phase_1_betting(hand_0_addr, bob_addr), 999);

        print(&utf8(b"Bob raises."));
        hand::process_bet_action(&bob, hand_0_addr, 500);

        state_update(room_addr);
        let room = brief(room_addr);
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        assert!(
            vector[0, 500, 250] == hand::get_bets(hand_0_addr),
            999
        );
        assert!(
            vector[true, false, false] == hand::get_fold_statuses(hand_0_addr),
            999
        );
        assert!(hand::is_phase_1_betting(hand_0_addr, eric_addr), 999);

        print(&utf8(b"Eric calls."));
        hand::process_bet_action(&eric, hand_0_addr, 500);

        state_update(room_addr);

        let room = brief(room_addr);
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        assert!(
            vector[0, 500, 500] == hand::get_bets(hand_0_addr),
            999
        );
        assert!(
            vector[true, false, false] == hand::get_fold_statuses(hand_0_addr),
            999
        );

        print(&utf8(b"Time to open 3 community cards."));
        assert!(hand::is_dealing_community_cards(hand_0_addr), 999);

        print(&utf8(b"Everyone does his card opening duty."));
        let hand_0_open_x_addrs = range(0, 3).map(|x|hand::borrow_public_opening_session(hand_0_addr, x));
        vector[0, 1, 2].for_each(|opening_idx| {
            let share = threshold_scalar_mul::generate_contribution(&bob, hand_0_open_x_addrs[opening_idx], &dkg_0_bob_secret_share);
            threshold_scalar_mul::process_contribution(&bob, hand_0_open_x_addrs[opening_idx], bcs::to_bytes(&share));
        });
        vector[0, 1, 2].for_each(|opening_idx| {
            let share = threshold_scalar_mul::generate_contribution(&eric, hand_0_open_x_addrs[opening_idx], &dkg_0_eric_secret_share);
            threshold_scalar_mul::process_contribution(&eric, hand_0_open_x_addrs[opening_idx], bcs::to_bytes(&share));
        });
        vector[0, 1, 2].for_each(|opening_idx| {
            let share = threshold_scalar_mul::generate_contribution(&alice, hand_0_open_x_addrs[opening_idx], &dkg_0_alice_secret_share);
            threshold_scalar_mul::process_contribution(&alice, hand_0_open_x_addrs[opening_idx], bcs::to_bytes(&share));
        });

        state_update(room_addr);

        let room = brief(room_addr);
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        assert!(hand::is_phase_2_betting(hand_0_addr, bob_addr), 999);
        print(&utf8(b"Everyone can see the 3 public cards."));
        let public_card_0 = hand::get_public_card(hand_0_addr, 0);
        let public_card_1 = hand::get_public_card(hand_0_addr, 1);
        let public_card_2 = hand::get_public_card(hand_0_addr, 2);
        print(&utf8(b"hand_0_public_card_0:"));
        print(&utils::get_card_text(public_card_0));
        print(&utf8(b"hand_0_public_card_1:"));
        print(&utils::get_card_text(public_card_1));
        print(&utf8(b"hand_0_public_card_2:"));
        print(&utils::get_card_text(public_card_2));

        print(&utf8(b"Game 0 post-flop betting starts."));
        print(&utf8(b"Bob checks."));
        hand::process_bet_action(&bob, hand_0_addr, 500);

        state_update(room_addr);
        let room = brief(room_addr);
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        assert!(hand::is_phase_2_betting(hand_0_addr, eric_addr), 999);

        print(&utf8(b"Eric bet 300 more chips."));
        hand::process_bet_action(&eric, hand_0_addr, 800);

        state_update(room_addr);
        let room = brief(room_addr);
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        assert!(hand::is_phase_2_betting(hand_0_addr, bob_addr), 999);

        print(&utf8(b"Bob calls."));
        hand::process_bet_action(&bob, hand_0_addr, 800);

        state_update(room_addr);
        let room = brief(room_addr);
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        let cur_game = hand_0_addr;
        assert!(hand::is_opening_4th_community_card(cur_game), 999);

        print(&utf8(b"Opening the 4th public card."));
        let hand_0_open_3_addr = hand::borrow_public_opening_session(cur_game, 3);

        let hand_0_open_3_alice_share =
            threshold_scalar_mul::generate_contribution(
                &alice, hand_0_open_3_addr, &dkg_0_alice_secret_share
            );
        threshold_scalar_mul::process_contribution(
            &alice,
            hand_0_open_3_addr,
            bcs::to_bytes(&hand_0_open_3_alice_share)
        );
        let hand_0_open_3_bob_share =
            threshold_scalar_mul::generate_contribution(
                &bob, hand_0_open_3_addr, &dkg_0_bob_secret_share
            );
        threshold_scalar_mul::process_contribution(
            &bob,
            hand_0_open_3_addr,
            bcs::to_bytes(&hand_0_open_3_bob_share)
        );
        let hand_0_open_3_eric_share =
            threshold_scalar_mul::generate_contribution(
                &eric, hand_0_open_3_addr, &dkg_0_eric_secret_share
            );
        threshold_scalar_mul::process_contribution(
            &eric,
            hand_0_open_3_addr,
            bcs::to_bytes(&hand_0_open_3_eric_share)
        );

        state_update(room_addr);
        let room = brief(room_addr);
        let cur_game = hand_0_addr;
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        assert!(hand::is_phase_3_betting(cur_game, bob_addr), 999);

        print(&utf8(b"Anyone can see the 4th public card."));
        let public_card_3 = hand::get_public_card(cur_game, 3);
        print(&utf8(b"hand_0_public_card_3:"));
        print(&utils::get_card_text(public_card_3));

        print(&utf8(b"Game 0 post-turn betting starts."));
        print(&utf8(b"Bob raises."));
        hand::process_bet_action(&bob, hand_0_addr, 20000);

        state_update(room_addr);
        let room = brief(room_addr);
        let cur_game = hand_0_addr;
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        assert!(hand::is_phase_3_betting(cur_game, eric_addr), 999);

        print(&utf8(b"Eric calls."));
        hand::process_bet_action(&eric, hand_0_addr, 20000);

        state_update(room_addr);
        let room = brief(room_addr);
        let cur_game = hand_0_addr;
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        assert!(hand::is_opening_5th_community_card(cur_game), 999);

        print(&utf8(b"Opening the 5th public card."));
        let hand_0_open_4_addr = hand::borrow_public_opening_session(cur_game, 4);

        let hand_0_open_4_eric_share =
            threshold_scalar_mul::generate_contribution(
                &eric, hand_0_open_4_addr, &dkg_0_eric_secret_share
            );
        threshold_scalar_mul::process_contribution(
            &eric,
            hand_0_open_4_addr,
            bcs::to_bytes(&hand_0_open_4_eric_share)
        );
        let hand_0_open_4_alice_share =
            threshold_scalar_mul::generate_contribution(
                &alice, hand_0_open_4_addr, &dkg_0_alice_secret_share
            );
        threshold_scalar_mul::process_contribution(
            &alice,
            hand_0_open_4_addr,
            bcs::to_bytes(&hand_0_open_4_alice_share)
        );
        let hand_0_open_4_bob_share =
            threshold_scalar_mul::generate_contribution(
                &bob, hand_0_open_4_addr, &dkg_0_bob_secret_share
            );
        threshold_scalar_mul::process_contribution(
            &bob,
            hand_0_open_4_addr,
            bcs::to_bytes(&hand_0_open_4_bob_share)
        );

        state_update(room_addr);
        let room = brief(room_addr);
        let cur_game = hand_0_addr;
        assert!(is_in_the_middle_of_a_hand(&room, 0), 999);
        assert!(hand::is_phase_4_betting(cur_game, bob_addr), 999);

        print(&utf8(b"Anyone can see the 5th public card."));
        let public_card_4 = hand::get_public_card(cur_game, 4);

        print(&utf8(b"hand_0_public_card_4:"));
        print(&utils::get_card_text(public_card_4));

        print(&utf8(b"Game 0 post-river betting starts."));
        print(&utf8(b"Bob checks."));
        hand::process_bet_action(&bob, hand_0_addr, 20000);
        state_update(room_addr);
        print(&utf8(b"Eric checks."));
        hand::process_bet_action(&eric, hand_0_addr, 20000);

        state_update(room_addr);
        print(&utf8(b"Hand 0 showdown."));
        assert!(hand::is_at_showdown(hand_0_addr), 999);

        print(&utf8(b"Bob and Eric reveal their private cards"));
        hand::process_showdown_reveal(
            &eric,
            hand_0_addr,
            4,
            bcs::to_bytes(&hand_0_deal_4_eric_secret)
        );
        hand::process_showdown_reveal(
            &eric,
            hand_0_addr,
            5,
            bcs::to_bytes(&hand_0_deal_5_eric_secret)
        );
        hand::process_showdown_reveal(
            &bob,
            hand_0_addr,
            3,
            bcs::to_bytes(&hand_0_deal_3_bob_secret)
        );
        hand::process_showdown_reveal(
            &bob,
            hand_0_addr,
            2,
            bcs::to_bytes(&hand_0_deal_2_bob_secret)
        );

        state_update(room_addr);
        let room = brief(room_addr);
        assert!(is_in_the_middle_of_a_hand(&room, 1), 999);

        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }
}
