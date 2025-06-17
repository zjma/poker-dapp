/// On-chain states and util functions of a re-encryption where:
/// a group of users collaborate to transform a ciphertext without actually decrypting it,
/// so only a targeted user can decrypt privately.
/// The group has to have a shared ElGamal decrpyion key `s`.
/// The ciphertext has to be generated with the ElGamal encryption key corresponding to `s`.
module crypto_core::reencryption {
    use std::bcs;
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use aptos_std::bcs_stream;
    use aptos_std::bcs_stream::BCSStream;
    use aptos_std::debug::print;
    use aptos_framework::object;
    use aptos_framework::timestamp;
    use crypto_core::fiat_shamir_transform;
    use crypto_core::sigma_dlog;
    use crypto_core::sigma_dlog_eq;
    use crypto_core::dkg_v0;
    use crypto_core::threshold_scalar_mul;
    use crypto_core::group;
    use crypto_core::elgamal;
    #[test_only]
    use aptos_framework::randomness;

    const STATE__ACCEPTING_REENC: u64 = 1;
    const STATE__THRESHOLD_SCALAR_MUL_IN_PROGRESS: u64 = 2;
    const STATE__SUCCEEDED: u64 = 3;
    const STATE__FAILED: u64 = 4;

    struct VerifiableReencrpytion has copy, drop, store {
        th: group::Element,
        tsh: group::Element,
        urth: group::Element,
        proof_t: Option<sigma_dlog_eq::Proof>,
        proof_u: Option<sigma_dlog::Proof>,
    }

    public fun dummy_reencryption(): VerifiableReencrpytion {
        VerifiableReencrpytion {
            th: group::dummy_element(),
            tsh: group::dummy_element(),
            urth: group::dummy_element(),
            proof_t: option::none(),
            proof_u: option::none(),
        }
    }

    public fun decode_reencyption(stream: &mut BCSStream): VerifiableReencrpytion {
        let th = group::decode_element(stream);
        let tsh = group::decode_element(stream);
        let urth = group::decode_element(stream);
        let proof_t = bcs_stream::deserialize_option(stream, |s| sigma_dlog_eq::decode_proof(s));
        let proof_u = bcs_stream::deserialize_option(stream, |s| sigma_dlog::decode_proof(s));
        VerifiableReencrpytion { th, tsh, urth, proof_t, proof_u }
    }

    struct Session has copy, drop, key, store {
        card: elgamal::Ciphertext,
        deal_target: address,
        scalar_mul_party: vector<address>,
        secret_info: dkg_v0::SharedSecretPublicInfo,
        scalar_mul_deadline: u64,
        state: u64,
        deadline: u64,
        reenc: Option<elgamal::Ciphertext>,
        thresh_scalar_mul_session: Option<address>,
        culprits: vector<address>
    }

    public fun new_session(
        owner: address,
        card: elgamal::Ciphertext,
        deal_target: address,
        scalar_mul_party: vector<address>,
        secret_info: dkg_v0::SharedSecretPublicInfo,
        reencryption_deadline: u64,
        scalar_mul_deadline: u64
    ): address {
        let session_holder = object::generate_signer(&object::create_sticky_object(owner));
        let session_addr = address_of(&session_holder);

        assert!(reencryption_deadline < scalar_mul_deadline, 304000);
        let new_session = Session {
            card,
            deal_target,
            scalar_mul_party,
            secret_info,
            scalar_mul_deadline,
            state: STATE__ACCEPTING_REENC,
            deadline: reencryption_deadline,
            reenc: option::none(),
            thresh_scalar_mul_session: option::none(),
            culprits: vector[]
        };

        move_to(&session_holder, new_session);
        session_addr
    }

    /// Gas cost: 19.72
    public entry fun process_reencryption(player: &signer, session_addr: address, reenc_bytes: vector<u8>) acquires Session {
        let session = borrow_global_mut<Session>(session_addr);
        assert!(session.state == STATE__ACCEPTING_REENC, 175626);
        let player_addr = address_of(player);
        assert!(session.deal_target == player_addr, 175627);
        let (_, ek, _) = dkg_v0::unpack_shared_secret_public_info(session.secret_info);
        let (enc_base, pub_element) = elgamal::unpack_enc_key(ek);
        let trx = fiat_shamir_transform::new_transcript();
        let reenc = decode_reencyption(&mut bcs_stream::new(reenc_bytes));
        let VerifiableReencrpytion { th, tsh, urth, proof_t, proof_u } = reenc;
        if (proof_t.is_some()) {
            assert!(
                sigma_dlog_eq::verify(
                    &mut trx,
                    &enc_base,
                    &th,
                    &pub_element,
                    &tsh,
                    proof_t.borrow(),
                ),
                104032
            );
        };
        let (_, rh, old_c1) = elgamal::unpack_ciphertext(session.card);
        let rth = group::element_add(&rh, &th);
        if (proof_u.is_some()) {
            assert!(
                sigma_dlog::verify(&mut trx, &rth, &urth, proof_u.borrow()),
                104033
            );
        };
        let new_c0 = group::element_add(&rh, &th);
        let new_c1 = group::element_sum(vector[old_c1, urth, tsh]);
        let new_ciph = elgamal::make_ciphertext(enc_base, new_c0, new_c1);
        session.reenc = option::some(new_ciph);
    }

    public entry fun state_update(session_addr: address) acquires Session {
        let session = borrow_global_mut<Session>(session_addr);
        let now_secs = timestamp::now_seconds();
        if (session.state == STATE__ACCEPTING_REENC) {
            if (session.reenc.is_some()) {
                let new_ciph = session.reenc.borrow();
                let (_, new_c0, _) = elgamal::unpack_ciphertext(*new_ciph);
                let sub_session =
                    threshold_scalar_mul::new_session(
                        session_addr,
                        new_c0,
                        session.secret_info,
                        session.scalar_mul_party,
                        session.scalar_mul_deadline
                    );
                session.state = STATE__THRESHOLD_SCALAR_MUL_IN_PROGRESS;
                session.thresh_scalar_mul_session = option::some(sub_session);
            } else if (now_secs >= session.deadline) {
                session.state = STATE__FAILED;
                session.culprits = vector[session.deal_target];
            }
        } else if (session.state == STATE__THRESHOLD_SCALAR_MUL_IN_PROGRESS) {
            let sub_session = *session.thresh_scalar_mul_session.borrow();
            threshold_scalar_mul::state_update(sub_session);
            if (threshold_scalar_mul::succeeded(sub_session)) {
                session.state = STATE__SUCCEEDED;
            } else if (threshold_scalar_mul::failed(sub_session)) {
                session.state = STATE__FAILED;
                session.culprits = threshold_scalar_mul::culprits(sub_session);
            }
        }
    }

    public fun succeeded(session_addr: address): bool acquires Session {
        let session = borrow_global<Session>(session_addr);
        session.state == STATE__SUCCEEDED
    }

    public fun failed(session_addr: address): bool acquires Session {
        let session = borrow_global<Session>(session_addr);
        session.state == STATE__FAILED
    }

    public fun culprits(session_addr: address): vector<address> acquires Session {
        let session = borrow_global<Session>(session_addr);
        session.culprits
    }

    public fun scalar_mul_session_addr(session_addr: address): address acquires Session {
        let session = borrow_global<Session>(session_addr);
        *session.thresh_scalar_mul_session.borrow()
    }

    struct RecipientPrivateState has copy, drop {
        u: group::Scalar
    }

    public fun dummy_private_state(): RecipientPrivateState {
        RecipientPrivateState { u: group::dummy_scalar() }
    }

    public fun decode_private_state(stream: &mut BCSStream): RecipientPrivateState {
        let u = group::decode_scalar(stream);
        RecipientPrivateState { u }
    }

    struct SessionBrief has copy, drop, store {
        addr: address,
        card: elgamal::Ciphertext,
        deal_target: address,
        scalar_mul_party: vector<address>,
        secret_info: dkg_v0::SharedSecretPublicInfo,
        scalar_mul_deadline: u64,
        state: u64,
        deadline: u64,
        reenc: Option<elgamal::Ciphertext>,
        thresh_scalar_mul_session: Option<threshold_scalar_mul::SessionBrief>,
    }

    #[view]
    public fun brief(session_addr: address): SessionBrief acquires Session {
        let session = borrow_global<Session>(session_addr);
        SessionBrief {
            addr: session_addr,
            card: session.card,
            deal_target: session.deal_target,
            scalar_mul_party: session.scalar_mul_party,
            secret_info: session.secret_info,
            scalar_mul_deadline: session.scalar_mul_deadline,
            state: session.state,
            deadline: session.deadline,
            reenc: session.reenc,
            thresh_scalar_mul_session: session.thresh_scalar_mul_session.map(|addr| threshold_scalar_mul::brief(addr)),
        }
    }

    fun decode_brief(stream: &mut BCSStream): SessionBrief {
        let addr = bcs_stream::deserialize_address(stream);
        let card = elgamal::decode_ciphertext(stream);
        let deal_target = bcs_stream::deserialize_address(stream);
        let scalar_mul_party = bcs_stream::deserialize_vector(stream, |s|bcs_stream::deserialize_address(s));
        let secret_info = dkg_v0::decode_secret_info(stream);
        let scalar_mul_deadline = bcs_stream::deserialize_u64(stream);
        let state = bcs_stream::deserialize_u64(stream);
        let deadline = bcs_stream::deserialize_u64(stream);
        let reenc = bcs_stream::deserialize_option(stream, |s|elgamal::decode_ciphertext(s));
        let thresh_scalar_mul_session = bcs_stream::deserialize_option(stream, |s|threshold_scalar_mul::decode_session_brief(s));
        SessionBrief {
            addr, card, deal_target, scalar_mul_party, secret_info, scalar_mul_deadline, state, deadline, reenc, thresh_scalar_mul_session
        }
    }

    fun session_from_brief(brief: SessionBrief): Session {
        assert!(brief.thresh_scalar_mul_session.is_none(), 999);
        Session {
            card: brief.card,
            deal_target: brief.deal_target,
            scalar_mul_party: brief.scalar_mul_party,
            secret_info: brief.secret_info,
            scalar_mul_deadline: brief.scalar_mul_deadline,
            state: brief.state,
            deadline: brief.deadline,
            reenc: brief.reenc,
            thresh_scalar_mul_session: option::none(),
            culprits: vector[],

        }
    }
    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// NOTE: client needs to implement this.
    public fun reencrypt(
        target: &signer, session_addr: address
    ): (RecipientPrivateState, VerifiableReencrpytion) acquires Session {
        let session = borrow_global<Session>(session_addr);
        let addr = address_of(target);
        assert!(addr == session.deal_target, 285206);

        let (_, ek, _) = dkg_v0::unpack_shared_secret_public_info(session.secret_info);
        let (_, old_ek) = elgamal::unpack_enc_key(ek);
        let t = group::rand_scalar();
        let u = group::rand_scalar();
        let (enc_base, c_0, _) = elgamal::unpack_ciphertext(session.card);
        let th = group::scale_element(&enc_base, &t);
        let tsh = group::scale_element(&old_ek, &t);
        let rth = group::element_add(&c_0, &th);
        let urth = group::scale_element(&rth, &u);
        let trx = fiat_shamir_transform::new_transcript();
        let proof_t = sigma_dlog_eq::prove(&mut trx, &enc_base, &th, &old_ek, &tsh, &t);
        let proof_u = sigma_dlog::prove(&mut trx, &rth, &urth, &u);
        let reenc = VerifiableReencrpytion { th, tsh, urth, proof_t: option::some(proof_t), proof_u: option::some(proof_u) };
        let private_state = RecipientPrivateState { u };
        (private_state, reenc)
    }

    public fun reveal(session_addr: address, private_state: RecipientPrivateState): group::Element acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(session.state == STATE__SUCCEEDED, 285305);
        let RecipientPrivateState { u } = private_state;
        let srth =
            threshold_scalar_mul::result(*session.thresh_scalar_mul_session.borrow());
        let (_, new_c0, new_c1) =
            elgamal::unpack_ciphertext(*session.reenc.borrow());
        let urth = group::scale_element(&new_c0, &u);
        let blinder = group::element_add(&srth, &urth);
        let plaintext = group::element_sub(&new_c1, &blinder);
        plaintext
    }

    #[test(
        framework = @0x1, upper_level_object = @0x0123abcd, alice = @0xaaaa, bob = @0xbbbb, eric = @0xeeee
    )]
    fun example(
        framework: signer,
        upper_level_object: signer,
        alice: signer,
        bob: signer,
        eric: signer
    ) acquires Session {
        randomness::initialize_for_testing(&framework);
        timestamp::set_time_has_started_for_testing(&framework);
        let upper_level_session_addr = address_of(&upper_level_object);
        let alice_addr = address_of(&alice);
        let bob_addr = address_of(&bob);
        let eric_addr = address_of(&eric);
        let (secret_info, alice_share, bob_share, eric_share) =
            dkg_v0::run_example_session(upper_level_session_addr, &alice, &bob, &eric);
        let (_, agg_ek, _ek_shares) = dkg_v0::unpack_shared_secret_public_info(secret_info);
        let target = group::rand_element();
        let r = group::rand_scalar();
        let target_ciph = elgamal::enc(&agg_ek, &r, &target);
        let now_secs = timestamp::now_seconds();
        let session_addr =
            new_session(
                upper_level_session_addr,
                target_ciph,
                eric_addr,
                vector[alice_addr, bob_addr, eric_addr],
                secret_info,
                now_secs + 5,
                now_secs + 10
            );
        let (eric_private_state, eric_reenc) = reencrypt(&eric, session_addr);
        process_reencryption(&eric, session_addr, bcs::to_bytes(&eric_reenc));
        state_update(session_addr);
        let scalar_mul_session_addr = scalar_mul_session_addr(session_addr);
        let alice_contribution = threshold_scalar_mul::generate_contribution(&alice, scalar_mul_session_addr, &alice_share);
        threshold_scalar_mul::process_contribution(&alice, scalar_mul_session_addr, bcs::to_bytes(&alice_contribution));
        let bob_contribution = threshold_scalar_mul::generate_contribution(&bob, scalar_mul_session_addr, &bob_share);
        threshold_scalar_mul::process_contribution(&bob, scalar_mul_session_addr, bcs::to_bytes(&bob_contribution));
        let eric_contribution = threshold_scalar_mul::generate_contribution(&eric, scalar_mul_session_addr, &eric_share);
        threshold_scalar_mul::process_contribution(&eric, scalar_mul_session_addr, bcs::to_bytes(&eric_contribution));
        state_update(session_addr);
        assert!(succeeded(session_addr), 170517);
        let actual_result = reveal(session_addr, eric_private_state);
        assert!(target == actual_result, 170518);
    }
}
