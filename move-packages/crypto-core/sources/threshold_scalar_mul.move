/// The on-chain states & util functions of threshold scalar multiplication, where:
/// a group of users collaborate to scale a publicly on-chain group element `E` with a secret scalar shared between them.
module crypto_core::threshold_scalar_mul {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::vector;
    use std::vector::range;
    use aptos_std::bcs_stream;
    use aptos_std::bcs_stream::BCSStream;
    use aptos_framework::timestamp;
    use crypto_core::elgamal;
    use crypto_core::fiat_shamir_transform;
    use crypto_core::sigma_dlog_eq;
    use crypto_core::dkg_v0;
    use crypto_core::group;
    #[test_only]
    use aptos_framework::randomness;

    const STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE: u64 = 1;
    const STATE__SUCCEEDED: u64 = 3;
    const STATE__FAILED: u64 = 4;

    struct VerifiableContribution has copy, drop, store {
        payload: group::Element,
        proof: Option<sigma_dlog_eq::Proof>,
    }

    struct Session has copy, drop, store {
        to_be_scaled: group::Element,
        secret_info: dkg_v0::SharedSecretPublicInfo,
        allowed_contributors: vector<address>,
        /// Can be one of the following values.
        /// - `STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE`
        /// - `STATE__SUCCEEDED`
        /// - `STATE__FAILED`
        state: u64,
        /// If `state == STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE`, this field describes the deadline (in unix seconds).
        deadline: u64,
        /// When `state == STATE__FAILED`, this keeps track of who misbehaved.
        culprits: vector<address>,
        contributions: vector<Option<VerifiableContribution>>,
        /// Filled once `state` is changed to `STATE__SUCCEEDED`.
        result: Option<group::Element>
    }

    public fun dummy_contribution(): VerifiableContribution {
        VerifiableContribution {
            payload: group::dummy_element(),
            proof: option::none(),
        }
    }

    public fun new_session(
        to_be_scaled: group::Element,
        secret_info: dkg_v0::SharedSecretPublicInfo,
        allowed_contributors: vector<address>,
        deadline: u64
    ): Session {
        let n = allowed_contributors.length();
        Session {
            to_be_scaled,
            secret_info,
            allowed_contributors,
            state: STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE,
            deadline,
            culprits: vector[],
            contributions: range(0, n).map(|_| option::none()),
            result: option::none()
        }
    }

    public fun state_update(session: &mut Session) {
        if (session.state == STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE) {
            let now_sec = timestamp::now_seconds();
            let n = session.allowed_contributors.length();
            let num_shares = 0;
            let missing_contributors = vector[];
            vector::range(0, n).for_each(|i| {
                if (session.contributions[i].is_some()) {
                    num_shares += 1;
                } else {
                    missing_contributors.push_back(session.allowed_contributors[i]);
                }
            });
            let threshold = dkg_v0::get_threshold(&session.secret_info);
            if (num_shares >= threshold) {
                let scalar_mul_shares = session.contributions.map_ref(|maybe_contri| {
                    let maybe_contri: &Option<VerifiableContribution> = maybe_contri;
                    if (maybe_contri.is_some()) {
                        let contri = maybe_contri.borrow();
                        option::some(contri.payload)
                    } else {
                        option::none()
                    }
                });
                session.result = option::some(
                    dkg_v0::aggregate_scalar_mul(
                        &session.secret_info, scalar_mul_shares
                    )
                );
                session.state = STATE__SUCCEEDED;
            } else if (now_sec >= session.deadline && num_shares < threshold) {
                session.state = STATE__FAILED;
                session.culprits = missing_contributors;
            }
        }
    }

    /// Gas cost: 10.88
    public fun process_contribution(
        contributor: &signer, session: &mut Session, contribution: VerifiableContribution
    ) {
        assert!(session.state == STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE, 164507);
        let addr = address_of(contributor);
        let (found, idx) = session.allowed_contributors.index_of(&addr);
        assert!(found, 164508);
        if (contribution.proof.is_some()) {
            let proof = contribution.proof.borrow();
            let trx = fiat_shamir_transform::new_transcript();
            let (_, ek_shares) = dkg_v0::unpack_shared_secret_public_info(session.secret_info);
            let (enc_base, public_point) = elgamal::unpack_enc_key(ek_shares[idx]);
            assert!(sigma_dlog_eq::verify(&mut trx, &enc_base, &public_point, &session.to_be_scaled, &contribution.payload, proof), 164509);
        } else {
            //TODO: enforce proof after debugging
        };
        session.contributions[idx].fill(contribution);
    }

    public fun succeeded(session: &Session): bool {
        session.state == STATE__SUCCEEDED
    }

    public fun failed(session: &Session): bool {
        session.state == STATE__FAILED
    }

    public fun get_culprits(session: &Session): vector<address> {
        assert!(session.state == STATE__FAILED, 180858);
        session.culprits
    }

    public fun get_result(session: &Session): group::Element {
        assert!(session.state == STATE__SUCCEEDED, 165045);
        *session.result.borrow()
    }

    public fun decode_contribution(stream: &mut BCSStream): VerifiableContribution {
        let payload = group::decode_element(stream);
        let proof = bcs_stream::deserialize_option(stream, |s|sigma_dlog_eq::decode_proof(s));
        VerifiableContribution { payload, proof }
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// NOTE: client needs to implement this.
    public fun generate_contribution(
        contributor: &signer, session: &Session, secret_share: &dkg_v0::SecretShare
    ): VerifiableContribution {
        let contributor_addr = address_of(contributor);
        let (found, contributor_idx) = session.allowed_contributors.index_of(&contributor_addr);
        assert!(found, 310240);
        let (_agg_ek, ek_shares) =
            dkg_v0::unpack_shared_secret_public_info(session.secret_info);
        let (enc_base, public_point) =
            elgamal::unpack_enc_key(ek_shares[contributor_idx]);
        let private_scalar = dkg_v0::unpack_secret_share(*secret_share);
        let payload = group::scale_element(&session.to_be_scaled, &private_scalar);
        let proof =
            sigma_dlog_eq::prove(
                &mut fiat_shamir_transform::new_transcript(),
                &enc_base,
                &public_point,
                &session.to_be_scaled,
                &payload,
                &private_scalar
            );
        VerifiableContribution { payload, proof: option::some(proof) }
    }

    #[test(
        framework = @0x1, alice = @0xaaaa, bob = @0xbbbb, eric = @0xeeee
    )]
    fun example(
        framework: signer,
        alice: signer,
        bob: signer,
        eric: signer
    ) {
        randomness::initialize_for_testing(&framework);
        timestamp::set_time_has_started_for_testing(&framework);

        let alice_addr = address_of(&alice);
        let bob_addr = address_of(&bob);
        let eric_addr = address_of(&eric);
        let (secret_public_info, alice_secret_share, bob_secret_share, eric_secret_share) =

            dkg_v0::run_example_session(&alice, &bob, &eric);
        let now_secs = timestamp::now_seconds();
        let target = group::rand_element();
        let session =
            new_session(
                target,
                secret_public_info,
                vector[alice_addr, bob_addr, eric_addr],
                now_secs + 5
            );
        let alice_contribution =
            generate_contribution(&alice, &session, &alice_secret_share);
        let bob_contribution = generate_contribution(&bob, &session, &bob_secret_share);
        let eric_contribution = generate_contribution(
            &eric, &session, &eric_secret_share
        );
        process_contribution(&alice, &mut session, alice_contribution);
        process_contribution(&bob, &mut session, bob_contribution);
        process_contribution(&eric, &mut session, eric_contribution);
        state_update(&mut session);
        assert!(succeeded(&session), 161938);
        let actual_result = get_result(&session);
        let reconstructed_secret =
            dkg_v0::reconstruct_secret(
                &secret_public_info,
                vector[
                    option::some(alice_secret_share),
                    option::some(bob_secret_share),
                    option::some(eric_secret_share)
                ]
            );
        let expected_result = group::scale_element(&target, &reconstructed_secret);
        assert!(expected_result == actual_result, 161939);
    }
}
