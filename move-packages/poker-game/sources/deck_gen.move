module poker_game::deck_gen {

    use std::vector::range;
    use aptos_framework::timestamp::now_seconds;
    use crypto_core::elgamal;
    use crypto_core::shuffle;
    use crypto_core::group;

    friend poker_game::poker_room;

    const INF: u64 = 999999999;

    struct Session has copy, drop, store {
        shuffle: shuffle::Session,
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(agg_ek: elgamal::EncKey, allowed_contributors: vector<address>): Session {
        let now_secs = now_seconds();
        let zero = group::scalar_from_u64(0);
        let card_reprs = range(0, 52).map(|_| group::rand_element());
        let initial_ciphertexts = card_reprs.map_ref(|repr| elgamal::enc(&agg_ek, &zero, repr));
        let deadlines = range(0, allowed_contributors.length()).map(|i| now_secs + INF * (i + 1));
        let shuffle = shuffle::new_session(
            agg_ek,
            initial_ciphertexts,
            allowed_contributors,
            deadlines,
        );
        Session { shuffle }
    }

    public(friend) fun state_update(session: &mut Session) {
        shuffle::state_update(&mut session.shuffle);
    }

    public fun process_contribution(contributor: &signer, session: &mut Session, contribution: shuffle::VerifiableContribution) {
        shuffle::process_contribution(contributor, &mut session.shuffle, contribution);
    }

    public fun borrow_shuffle_session(session: &Session): &shuffle::Session {
        &session.shuffle
    }

    /// Return the card representations and the shuffled deck.
    public fun result(session: &Session): (vector<group::Element>, vector<elgamal::Ciphertext>) {
        assert!(shuffle::succeeded(&session.shuffle), 192012);
        let reprs = shuffle::input_cloned(&session.shuffle).map(|ciph|{
            let (_, _, c1) = elgamal::unpack_ciphertext(ciph);
            c1
        });
        (reprs, shuffle::result_cloned(&session.shuffle))
    }

    public fun succeeded(session: &Session): bool {
        shuffle::succeeded(&session.shuffle)
    }

    public fun failed(session: &Session): bool {
        shuffle::failed(&session.shuffle)
    }

    public fun culprit(session: &Session): address {
        shuffle::get_culprit(&session.shuffle)
    }
}