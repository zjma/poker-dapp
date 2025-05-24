module poker_game::deck_gen {

    use std::signer::address_of;
    use std::vector::range;
    use aptos_framework::object;
    use aptos_framework::timestamp::now_seconds;
    use crypto_core::elgamal;
    use crypto_core::shuffle;
    use crypto_core::group;

    friend poker_game::poker_room;

    const INF: u64 = 999999999;

    struct Session has copy, drop, key, store {
        shuffle_addr: address,
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(owner: address, agg_ek: elgamal::EncKey, allowed_contributors: vector<address>): address {
        let deckgen_holder = object::generate_signer(&object::create_sticky_object(owner));
        let session_addr = address_of(&deckgen_holder);
        let now_secs = now_seconds();
        let zero = group::scalar_from_u64(0);
        let card_reprs = range(0, 52).map(|_| group::rand_element());
        let initial_ciphertexts = card_reprs.map_ref(|repr| elgamal::enc(&agg_ek, &zero, repr));
        let deadlines = range(0, allowed_contributors.length()).map(|i| now_secs + INF * (i + 1));
        let shuffle = shuffle::new_session(
            session_addr,
            agg_ek,
            initial_ciphertexts,
            allowed_contributors,
            deadlines,
        );
        let new_session = Session { shuffle_addr: shuffle };
        move_to(&deckgen_holder, new_session);
        session_addr
    }

    public entry fun state_update(session_addr: address) acquires Session {
        let session = borrow_global_mut<Session>(session_addr);
        shuffle::state_update(session.shuffle_addr);
    }

    public fun cur_shuffle_addr(session_addr: address): address acquires Session {
        let session = borrow_global<Session>(session_addr);
        session.shuffle_addr
    }

    /// Return the card representations and the shuffled deck.
    public fun result(session_addr: address): (vector<group::Element>, vector<elgamal::Ciphertext>) acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(shuffle::succeeded(session.shuffle_addr), 192012);
        let reprs = shuffle::input_cloned(session.shuffle_addr).map(|ciph|{
            let (_, _, c1) = elgamal::unpack_ciphertext(ciph);
            c1
        });
        (reprs, shuffle::result_cloned(session.shuffle_addr))
    }

    public fun succeeded(session_addr: address): bool acquires Session {
        let session = borrow_global<Session>(session_addr);
        shuffle::succeeded(session.shuffle_addr)
    }

    public fun failed(session_addr: address): bool acquires Session {
        let session = borrow_global<Session>(session_addr);
        shuffle::failed(session.shuffle_addr)
    }

    public fun culprit(session_addr: address): address acquires Session {
        let session = borrow_global<Session>(session_addr);
        shuffle::get_culprit(session.shuffle_addr)
    }

    struct SessionBrief has drop, store {
        addr: address,
        shuffle: shuffle::SessionBrief,
    }

    #[view]
    public fun brief(session_addr: address): SessionBrief acquires Session {
        let session = borrow_global<Session>(session_addr);
        SessionBrief {
            addr: session_addr,
            shuffle: shuffle::brief(session.shuffle_addr),
        }
    }
}
