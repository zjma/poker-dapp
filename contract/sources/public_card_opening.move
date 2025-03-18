module contract_owner::public_card_opening {
    use std::option;
    use std::option::Option;
    use std::vector;
    use contract_owner::group;
    use contract_owner::dkg_v0;
    use contract_owner::threshold_scalar_mul;
    use contract_owner::encryption;

    const STATE__THRESHOLD_SCALAR_MUL_IN_PROGRESS: u64 = 1;
    const STATE__SUCCEEDED: u64 = 2;
    const STATE__FAILED: u64 = 3;

    struct Session has copy, drop, store {
        card_reprs: vector<group::Element>,
        blinded_card: group::Element,
        allowed_contributors: vector<address>,
        tsm_session: threshold_scalar_mul::Session,

        state: u64,
        /// When `state == STATE__SUCCEEDED`, the card value is saved here.
        result: Option<u64>,
        /// When `state == STATE__FAILED`, those who misbehaved are saved here.
        culprits: vector<address>,
    }

    public fun new_session(card_reprs: vector<group::Element>, encrypted_card: encryption::Ciphertext, allowed_contributors: vector<address>, secret_info: dkg_v0::SharedSecretPublicInfo, deadline: u64): Session {
        let (_, c0, blinded_card) = encryption::unpack_ciphertext(encrypted_card);
        let tsm_session = threshold_scalar_mul::new_session(c0, secret_info, allowed_contributors, deadline);
        Session {
            card_reprs,
            blinded_card,
            allowed_contributors,
            tsm_session,
            state: STATE__THRESHOLD_SCALAR_MUL_IN_PROGRESS,
            result: option::none(),
            culprits: vector[],
        }
    }

    public fun process_contribution(player: &signer, session: &mut Session, contribution: threshold_scalar_mul::VerifiableContribution) {
        assert!(session.state == STATE__THRESHOLD_SCALAR_MUL_IN_PROGRESS, 263211);
        threshold_scalar_mul::process_contribution(player, &mut session.tsm_session, contribution);
    }

    public fun state_update(session: &mut Session) {
        if (session.state == STATE__THRESHOLD_SCALAR_MUL_IN_PROGRESS) {
            threshold_scalar_mul::state_update(&mut session.tsm_session);
            if (threshold_scalar_mul::succeeded(&session.tsm_session)) {
                let blinder = threshold_scalar_mul::get_result(&session.tsm_session);
                session.state = STATE__SUCCEEDED;
                let revealed_repr = group::element_sub(&session.blinded_card, &blinder);
                let (card_found, card) = vector::index_of(&session.card_reprs, &revealed_repr);
                assert!(card_found, 264133);
                session.result = option::some(card);
            } else if (threshold_scalar_mul::failed(&session.tsm_session)) {
                session.state = STATE__FAILED;
                session.culprits = threshold_scalar_mul::get_culprits(&session.tsm_session);
            }
        }
    }

    public fun succeeded(session: &Session): bool {
        session.state == STATE__SUCCEEDED
    }

    public fun failed(session: &Session): bool {
        session.state == STATE__FAILED
    }

    public fun get_culprits(session: &Session): vector<address> {
        session.culprits
    }

    public fun get_result(session: &Session): u64 {
        assert!(session.state == STATE__SUCCEEDED, 173809);
        *option::borrow(&session.result)
    }

    public fun borrow_scalar_mul_session(session: &Session): &threshold_scalar_mul::Session {
        &session.tsm_session
    }
}