module contract_owner::round {
    use std::signer::address_of;
    use std::string::utf8;
    use std::vector;
    use aptos_std::debug;
    use aptos_framework::timestamp;
    use contract_owner::encryption;
    use contract_owner::deck;
    use contract_owner::deck::Deck;
    friend contract_owner::poker;

    const ROUND_STATE__WAITING_SHUFFLE_CONTRIBUTION_FROM_PLAYER_X_BEFORE_Y: u64 = 140333;
    const ROUND_STATE__DEALING_HOLE_CARDS_BEFORE_Y: u64 = 140658;
    const ROUND_STATE__PHASE_1_BET_BY_PLAYER_X_BEFORE_Y: u64 = 140855;
    const ROUND_STATE__OPENING_3_COMMUNITY_CARDS_BEFORE_Y: u64 = 141022;
    const ROUND_STATE__PHASE_2_BET_BY_PLAYER_X_BEFORE_Y: u64 = 141103;
    const ROUND_STATE__OPENING_4TH_COMMUNITY_CARD_BEFORE_Y: u64 = 141131;
    const ROUND_STATE__PHASE_3_BET_BY_PLAYER_X_BEFORE_Y: u64 = 141245;
    const ROUND_STATE__OPENING_5TH_COMMUNITY_CARD_BEFORE_Y: u64 = 141256;
    const ROUND_STATE__PHASE_4_BET_BY_PLAYER_X_BEFORE_Y: u64 = 141414;
    const ROUND_STATE__SHOWDOWN_BEFORE_Y: u64 = 141414;
    const ROUND_STATE__FINISHED: u64 = 141628;
    const ROUND_STATE__ABORTED: u64 = 141629;


    struct RoundStateCode has copy, drop, store {
        main: u64,
        x: u64,
        y: u64,
    }

    struct PokerRoundSession has copy, drop, store {
        num_players: u64,
        player_addrs: vector<address>, // [btn, sb, bb, ...]
        player_chips: vector<u64>,
        state: RoundStateCode,
        deck: Deck,
    }

    public fun dummy_session(): PokerRoundSession {
        PokerRoundSession {
            num_players: 0,
            player_addrs: vector[],
            player_chips: vector[],
            state: RoundStateCode { main: 0, x: 0, y: 0 },
            deck: deck::dummy_deck(),
        }
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(players: vector<address>, chips: vector<u64>, card_ek: encryption::EncKey, player_ek_shares: vector<encryption::EncKey>): (vector<u64>, PokerRoundSession) {
        let (errors, deck) = deck::new(card_ek, player_ek_shares);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 160248);
            return (errors, dummy_session());
        };
        let num_players = vector::length(&players);
        let session = PokerRoundSession {
            num_players,
            player_addrs: players,
            player_chips: chips,
            state: RoundStateCode {
                main: ROUND_STATE__WAITING_SHUFFLE_CONTRIBUTION_FROM_PLAYER_X_BEFORE_Y,
                x: 0,
                y: timestamp::now_seconds() + 5,
            },
            deck,
        };
        (vector[], session)
    }

    public fun borrow_deck(round: &PokerRoundSession): &deck::Deck {
        &round.deck
    }

    public fun is_waiting_for_shuffle_contribution_from(round: &PokerRoundSession, addr: address): bool {
        if (round.state.main != ROUND_STATE__WAITING_SHUFFLE_CONTRIBUTION_FROM_PLAYER_X_BEFORE_Y) return false;
        if (addr != *vector::borrow(&round.player_addrs, round.state.x)) return false;
        true
    }

    public fun process_shuffle_contribution(player: &signer, round: &mut PokerRoundSession, new_draw_pile: vector<encryption::Ciphertext>, proof: deck::ShuffleProof): (vector<u64>, u64) {
        debug::print(&utf8(b"round::process_shuffle_contribution: BEGIN"));
        if (round.state.main != ROUND_STATE__WAITING_SHUFFLE_CONTRIBUTION_FROM_PLAYER_X_BEFORE_Y) return (vector[171018], ROUND_STILL_IN_PROGRESS);
        let now = timestamp::now_seconds();
        if (now >= round.state.y) {
            round.state = RoundStateCode {
                main: ROUND_STATE__ABORTED,
                x: 0,
                y: 0,
            };
            return (vector[171020], ROUND_ABORTED);
        };
        let player_addr = address_of(player);
        let (found, player_idx) = vector::index_of(&round.player_addrs, &player_addr);
        if (!found || round.state.x != player_idx) return (vector[171019], ROUND_STILL_IN_PROGRESS);
        let errors = deck::apply_shuffle(&mut round.deck, new_draw_pile, proof);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 171756);
            return (errors, ROUND_STILL_IN_PROGRESS);
        };
        debug::print(&utf8(b"round::process_shuffle_contribution: END"));
        if (round.state.x < round.num_players - 1) {
            // Wait for the next shuffle contribution.
            round.state.x = round.state.x + 1;
            round.state.y = now + 5;
            (vector[], ROUND_STILL_IN_PROGRESS)
        } else {
            round.state = RoundStateCode {
                main: ROUND_STATE__DEALING_HOLE_CARDS_BEFORE_Y,
                x: 0,
                y: now + 5,
            };
            (vector[], ROUND_STILL_IN_PROGRESS)
        }
    }

    const ROUND_STILL_IN_PROGRESS: u64 = 0;
    const ROUND_ABORTED: u64 = 2;
}
