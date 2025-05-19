module poker_game::deck_gen {

    use std::option;
    use std::option::Option;
    use std::vector::range;
    use aptos_framework::timestamp::now_seconds;
    use crypto_core::elgamal;
    use crypto_core::shuffle;
    use crypto_core::group;

    friend poker_game::poker_room;

    const INF: u64 = 999999999;

    struct Session has copy, drop, store {
        agg_ek: elgamal::EncKey,
        allowed_contributors: vector<address>,
        card_reprs: vector<group::Element>,
        initial_ciphertexts: vector<elgamal::Ciphertext>,
        shuffle: Option<shuffle::Session>,
    }

    public fun new_session(agg_ek: elgamal::EncKey, allowed_contributors: vector<address>): Session {
        Session {
            agg_ek,
            allowed_contributors,
            card_reprs: vector[],
            initial_ciphertexts: vector[],
            shuffle: option::none(),
        }
    }

    public(friend) fun state_update(session: &mut Session) {
        if (session.shuffle.is_none()) {
            let new_reprs = range(0, 13).map(|_| group::rand_element());
            let zero = group::scalar_from_u64(0);
            let new_ciphs = new_reprs.map_ref(|repr| elgamal::enc(&session.agg_ek, &zero, repr));
            session.card_reprs.append(new_reprs);
            session.initial_ciphertexts.append(new_ciphs);
            if (session.card_reprs.length() >= 52) {
                let now_secs = now_seconds();
                let deadlines = range(0, session.allowed_contributors.length()).map(|i| now_secs + INF * (i + 1));
                let shuffle = shuffle::new_session(
                    session.agg_ek,
                    session.initial_ciphertexts,
                    session.allowed_contributors,
                    deadlines,
                );
                session.shuffle = option::some(shuffle);
            }
        } else {
            shuffle::state_update(session.shuffle.borrow_mut());
        }
    }

    public fun process_contribution(contributor: &signer, session: &mut Session, contribution: shuffle::VerifiableContribution) {
        assert!(session.shuffle.is_some(), 185219);
        shuffle::process_contribution(contributor, session.shuffle.borrow_mut(), contribution);
    }

    public fun borrow_shuffle_session(session: &Session): &shuffle::Session {
        session.shuffle.borrow()
    }

    /// Return the card representations and the shuffled deck.
    public fun result(session: &Session): (vector<group::Element>, vector<elgamal::Ciphertext>) {
        assert!(session.shuffle.is_some(), 192011);
        assert!(shuffle::succeeded(session.shuffle.borrow()), 192012);
        (session.card_reprs, shuffle::result_cloned(session.shuffle.borrow()))
    }

    public fun succeeded(session: &Session): bool {
        session.shuffle.is_some() && shuffle::succeeded(session.shuffle.borrow())
    }

    public fun failed(session: &Session): bool {
        session.shuffle.is_some() && shuffle::failed(session.shuffle.borrow())
    }

    public fun culprit(session: &Session): address {
        shuffle::get_culprit(session.shuffle.borrow())
    }
}