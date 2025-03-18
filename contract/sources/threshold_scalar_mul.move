module contract_owner::threshold_scalar_mul {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::string;
    use std::vector;
    use std::vector::{length, range, for_each, push_back};
    use aptos_std::type_info;
    use aptos_framework::timestamp;
    use contract_owner::sigma_dlog_eq;
    use contract_owner::dkg_v0;
    use contract_owner::group;
    #[test_only]
    use aptos_framework::randomness;
    #[test_only]
    use contract_owner::encryption;
    #[test_only]
    use contract_owner::fiat_shamir_transform;

    const STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE: u64 = 1;
    const STATE__SUCCEEDED: u64 = 3;
    const STATE__FAILED: u64 = 4;

    struct VerifiableContribution has copy, drop, store {
        payload: group::Element,
        proof: sigma_dlog_eq::Proof,
    }

    struct State has copy, drop, store {
        /// Can be one of the following values.
        /// - `STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE`
        /// - `STATE__SUCCEEDED`
        /// - `STATE__FAILED`
        /// TODO: decide whether the result is aggregated on chain (cons: txn too expensive OR new native required) or off chain (cons: 1 extra RTT AND potential need of pairing needed by verifiability).
        main: u64,
        /// If `main == STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE`, this field describes the deadline (in unix seconds).
        deadline: u64,
        /// When `main == STATE__FAILED`, this keeps track of who misbehaved.
        culprits: vector<address>,
    }

    struct Session has copy, drop, store {
        to_be_scaled: group::Element,
        secret_info: dkg_v0::SharedSecretPublicInfo,
        allowed_contributors: vector<address>,
        state: State,
        contributions: vector<Option<VerifiableContribution>>,
        /// Filled once `state` is changed to `STATE__SUCCEEDED`.
        result: Option<group::Element>,
    }

    public fun dummy_contribution(): VerifiableContribution {
        VerifiableContribution {
            payload: group::dummy_element(),
            proof: sigma_dlog_eq::dummy_proof(),
        }
    }

    public fun new_session(
        to_be_scaled: group::Element,
        secret_info: dkg_v0::SharedSecretPublicInfo,
        allowed_contributors: vector<address>,
        deadline: u64,
    ): Session {
        let n = length(&allowed_contributors);
        Session {
            to_be_scaled,
            secret_info,
            allowed_contributors,
            state: State { main: STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE, deadline, culprits: vector[]},
            contributions: vector::map(range(0, n), |_|option::none()),
            result: option::none(),
        }
    }

    public fun state_update(session: &mut Session) {
        if (session.state.main == STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE) {
            let now_sec = timestamp::now_seconds();
            let n = vector::length(&session.allowed_contributors);
            let num_shares = 0;
            let missing_contributors = vector[];
            for_each(vector::range(0, n), |i|{
                let contribution_holder = vector::borrow(&session.contributions, i);
                if (option::is_some(contribution_holder)) {
                    num_shares = num_shares + 1;
                } else {
                    let player = *vector::borrow(&session.allowed_contributors, i);
                    push_back(&mut missing_contributors, player);
                }
            });
            let threshold = dkg_v0::get_threshold(&session.secret_info);
            if (num_shares >= threshold) {
                let scalar_mul_shares = vector::map_ref(&session.contributions, |contri|{
                    if (option::is_some(contri)) {
                        option::some(option::borrow(contri).payload)
                    } else {
                        option::none()
                    }
                });
                session.result = option::some(dkg_v0::aggregate_scalar_mul(&session.secret_info, scalar_mul_shares));
                session.state.main = STATE__SUCCEEDED;
            } else if (now_sec >= session.state.deadline && num_shares < threshold) {
                session.state.main = STATE__FAILED;
                session.state.culprits = missing_contributors;
            }
        }
    }

    public fun process_contribution(contributor: &signer, session: &mut Session, contribution: VerifiableContribution) {
        assert!(session.state.main == STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE, 164507);
        let addr = address_of(contributor);
        let (found, idx) = vector::index_of(&session.allowed_contributors, &addr);
        assert!(found, 164508);
        //TODO: verify contribution
        let contribution_holder = vector::borrow_mut(&mut session.contributions, idx);
        option::fill(contribution_holder, contribution);
    }

    public fun succeeded(session: &Session): bool {
        session.state.main == STATE__SUCCEEDED
    }

    public fun failed(session: &Session): bool {
        session.state.main == STATE__FAILED
    }

    public fun get_culprits(session: &Session): vector<address> {
        assert!(session.state.main == STATE__FAILED, 180858);
        session.state.culprits
    }

    public fun get_result(session: &Session): group::Element {
        assert!(session.state.main == STATE__SUCCEEDED, 165045);
        *option::borrow(&session.result)
    }

    public fun decode_contribution(buf: vector<u8>): (vector<u64>, VerifiableContribution, vector<u8>) {
        let buf_len = vector::length(&buf);
        let header = *string::bytes(&type_info::type_name<VerifiableContribution>());
        let header_len = vector::length(&header);
        if (buf_len < header_len) return (vector[270423], dummy_contribution(), buf);
        let buf = vector::slice(&buf, header_len, buf_len);
        let (errors, payload, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 270424);
            return (errors, dummy_contribution(), buf);
        };
        let (errors, proof, buf) = sigma_dlog_eq::decode_proof(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 270425);
            return (errors, dummy_contribution(), buf);
        };
        let ret = VerifiableContribution {
            payload,
            proof,
        };
        (vector[], ret, buf)
    }

    public fun encode_contribution(obj: &VerifiableContribution): vector<u8> {
        let buf = *string::bytes(&type_info::type_name<VerifiableContribution>());
        vector::append(&mut buf, group::encode_element(&obj.payload));
        vector::append(&mut buf, sigma_dlog_eq::encode_proof(&obj.proof));
        buf
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    public fun generate_contribution(contributor: &signer, session: &Session, secret_share: &dkg_v0::SecretShare): VerifiableContribution {
        let contributor_addr = address_of(contributor);
        let (found, contributor_idx) = vector::index_of(&session.allowed_contributors, &contributor_addr);
        assert!(found, 310240);
        let (_agg_ek, ek_shares) = dkg_v0::unpack_shared_secret_public_info(session.secret_info);
        let ek_share = *vector::borrow(&ek_shares, contributor_idx);
        let (enc_base, public_point) = encryption::unpack_enc_key(ek_share);
        let private_scalar = dkg_v0::unpack_secret_share(*secret_share);
        let payload = group::scale_element(&session.to_be_scaled, &private_scalar);
        let proof = sigma_dlog_eq::prove(&mut fiat_shamir_transform::new_transcript(), &enc_base, &public_point, &session.to_be_scaled, &payload, &private_scalar);
        VerifiableContribution {
            payload,
            proof,
        }
    }

    #[test(framework = @0x1, alice = @0xaaaa, bob = @0xbbbb, eric = @0xeeee)]
    fun example(framework: signer, alice: signer, bob: signer, eric: signer) {
        randomness::initialize_for_testing(&framework);
        timestamp::set_time_has_started_for_testing(&framework);

        let alice_addr = address_of(&alice);
        let bob_addr = address_of(&bob);
        let eric_addr = address_of(&eric);
        let (secret_public_info, alice_secret_share, bob_secret_share, eric_secret_share) = dkg_v0::run_example_session(&alice, &bob, &eric);
        let now_secs = timestamp::now_seconds();
        let target = group::rand_element();
        let session = new_session(target, secret_public_info, vector[alice_addr, bob_addr, eric_addr], now_secs + 5);
        let alice_contribution = generate_contribution(&alice, &session, &alice_secret_share);
        let bob_contribution = generate_contribution(&bob, &session, &bob_secret_share);
        let eric_contribution = generate_contribution(&eric, &session, &eric_secret_share);
        process_contribution(&alice, &mut session, alice_contribution);
        process_contribution(&bob, &mut session, bob_contribution);
        process_contribution(&eric, &mut session, eric_contribution);
        state_update(&mut session);
        assert!(succeeded(&session), 161938);
        let actual_result = get_result(&session);
        let reconstructed_secret = dkg_v0::reconstruct_secret(&secret_public_info, vector[option::some(alice_secret_share), option::some(bob_secret_share), option::some(eric_secret_share)]);
        let expected_result = group::scale_element(&target, &reconstructed_secret);
        assert!(expected_result == actual_result, 161939);
    }
}
