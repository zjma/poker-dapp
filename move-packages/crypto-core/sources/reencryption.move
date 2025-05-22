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

    struct Session has copy, drop, store {
        card: elgamal::Ciphertext,
        deal_target: address,
        scalar_mul_party: vector<address>,
        secret_info: dkg_v0::SharedSecretPublicInfo,
        scalar_mul_deadline: u64,
        state: u64,
        deadline: u64,
        reenc: Option<elgamal::Ciphertext>,
        thresh_scalar_mul_session: Option<threshold_scalar_mul::Session>,
        culprits: vector<address>
    }

    fun decode_session(stream: &mut BCSStream): Session {
        let card = elgamal::decode_ciphertext(stream);
        let deal_target = bcs_stream::deserialize_address(stream);
        let scalar_mul_party = bcs_stream::deserialize_vector(stream, |s|bcs_stream::deserialize_address(s));
        let secret_info = dkg_v0::decode_secret_info(stream);
        let scalar_mul_deadline = bcs_stream::deserialize_u64(stream);
        let state = bcs_stream::deserialize_u64(stream);
        let deadline = bcs_stream::deserialize_u64(stream);
        let reenc = bcs_stream::deserialize_option(stream, |s|elgamal::decode_ciphertext(s));
        let thresh_scalar_mul_session = bcs_stream::deserialize_option(stream, |s|threshold_scalar_mul::decode_session(s));
        let culprits = bcs_stream::deserialize_vector(stream, |s|bcs_stream::deserialize_address(s));
        Session {
            card,
            deal_target,
            scalar_mul_party,
            secret_info,
            scalar_mul_deadline,
            state,
            deadline,
            reenc,
            thresh_scalar_mul_session,
            culprits,
        }
    }

    public fun new_session(
        card: elgamal::Ciphertext,
        deal_target: address,
        scalar_mul_party: vector<address>,
        secret_info: dkg_v0::SharedSecretPublicInfo,
        reencryption_deadline: u64,
        scalar_mul_deadline: u64
    ): Session {
        assert!(reencryption_deadline < scalar_mul_deadline, 304000);
        Session {
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
        }
    }

    /// Gas cost: 19.72
    public fun process_reencryption(
        player: &signer, session: &mut Session, reenc: VerifiableReencrpytion
    ) {
        assert!(session.state == STATE__ACCEPTING_REENC, 175626);
        let player_addr = address_of(player);
        assert!(session.deal_target == player_addr, 175627);
        let (ek, _) = dkg_v0::unpack_shared_secret_public_info(session.secret_info);
        let (enc_base, pub_element) = elgamal::unpack_enc_key(ek);
        let trx = fiat_shamir_transform::new_transcript();
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

    #[test(player = @0x2346a73e0b3a6e1770c1503e28bfc8b7c9d50d25a2e230db5a18d34c442468a3)]
    fun hihi(player: signer) {
        let stream = bcs_stream::new(x"20fea6b4f12bd99e8c7dd07fe1efd47fd6ab5af0875eb2d8ef3c677c1dc527294c2060ac3bf81bb0e724367ef135bef3585e16bb7bf8a8ddce7bc0479bba91f26a49207e07dd4edc8bbb8546d0dc59685561384ffc53e16a0b2792f502d6024295d2712346a73e0b3a6e1770c1503e28bfc8b7c9d50d25a2e230db5a18d34c442468a302cc48876052af45aa711a3597b204fcd22aa132105e5b98643422fcd8902438412346a73e0b3a6e1770c1503e28bfc8b7c9d50d25a2e230db5a18d34c442468a320fea6b4f12bd99e8c7dd07fe1efd47fd6ab5af0875eb2d8ef3c677c1dc527294c2080f9112af99669c114e397ca592929482bfa9e9b451927b3dcf4fee6285ad4590220fea6b4f12bd99e8c7dd07fe1efd47fd6ab5af0875eb2d8ef3c677c1dc527294c20169bc63864d1d68ebe221951b90bbd5b4d16fbffbf2045b5cc00854f2e623b0220fea6b4f12bd99e8c7dd07fe1efd47fd6ab5af0875eb2d8ef3c677c1dc527294c20fcb4a3de60e7b311edf0f14a37629ce84bb93e2906cf5b826ae3a683659a9856e8e463df000000000100000000000000e91ac9a300000000000000");
        let session = decode_session(&mut stream);
        let stream = bcs_stream::new(x"20f274a3545b76f87438de90e9be86d012c1a9b7a562beb4ceb879dc5a22065b44201e13e56a502ac4ec8bcce754fb7816ba693137c80968380bff4d6d35230962432050af82aa5de176844995e1d2b158dcd6631ffd8a66af788424f72d9e7a69dd650120b49ceb1edb55da0e196c787677dfccb45b0dbb568f7e2189114fc3597fc3933a201c52fcbf9729c882133f717ca079edadbbb1c0caba9bb62bba6dc1462c67eb392066f27a3ec4aebb8f6d64fd57f357d5a4365a7eacbc736e6423c5652da6a80d01012054600a362237c82089cc1059af147058aa1a6b0d835d34201ed1435d3a219e1f207b8cb267e0815950595e60dc674654fbc659ad1a55cbfcc0b70ded424793620f");
        let reenc = decode_reencyption(&mut stream);
        process_reencryption(&player, &mut session, reenc);
    }

    /// Gas cost: 10.88
    public fun process_scalar_mul_share(
        player: &signer,
        session: &mut Session,
        share: threshold_scalar_mul::VerifiableContribution
    ) {
        let sub_session = session.thresh_scalar_mul_session.borrow_mut();
        threshold_scalar_mul::process_contribution(player, sub_session, share);
    }

    public fun state_update(session: &mut Session) {
        let now_secs = timestamp::now_seconds();
        if (session.state == STATE__ACCEPTING_REENC) {
            if (session.reenc.is_some()) {
                let new_ciph = session.reenc.borrow();
                let (_, new_c0, _) = elgamal::unpack_ciphertext(*new_ciph);
                let sub_session =
                    threshold_scalar_mul::new_session(
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
            let sub_session = session.thresh_scalar_mul_session.borrow_mut();
            threshold_scalar_mul::state_update(sub_session);
            if (threshold_scalar_mul::succeeded(sub_session)) {
                session.state = STATE__SUCCEEDED;
            } else if (threshold_scalar_mul::failed(sub_session)) {
                session.state = STATE__FAILED;
                session.culprits = threshold_scalar_mul::get_culprits(sub_session);
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

    public fun borrow_scalar_mul_session(session: &Session): &threshold_scalar_mul::Session {
        session.thresh_scalar_mul_session.borrow()
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

    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// NOTE: client needs to implement this.
    public fun reencrypt(
        target: &signer, session: &Session
    ): (RecipientPrivateState, VerifiableReencrpytion) {
        let addr = address_of(target);
        assert!(addr == session.deal_target, 285206);

        let (ek, _) = dkg_v0::unpack_shared_secret_public_info(session.secret_info);
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

    public fun reveal(
        session: &Session, private_state: RecipientPrivateState
    ): group::Element {
        assert!(session.state == STATE__SUCCEEDED, 285305);
        let RecipientPrivateState { u } = private_state;
        let srth =
            threshold_scalar_mul::get_result(
                session.thresh_scalar_mul_session.borrow()
            );
        let (_, new_c0, new_c1) =
            elgamal::unpack_ciphertext(*session.reenc.borrow());
        let urth = group::scale_element(&new_c0, &u);
        let blinder = group::element_add(&srth, &urth);
        let plaintext = group::element_sub(&new_c1, &blinder);
        plaintext
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
        let (secret_info, alice_share, bob_share, eric_share) =
            dkg_v0::run_example_session(&alice, &bob, &eric);
        let (agg_ek, _ek_shares) = dkg_v0::unpack_shared_secret_public_info(secret_info);
        let target = group::rand_element();
        let r = group::rand_scalar();
        let target_ciph = elgamal::enc(&agg_ek, &r, &target);
        let now_secs = timestamp::now_seconds();
        let session =
            new_session(
                target_ciph,
                eric_addr,
                vector[alice_addr, bob_addr, eric_addr],
                secret_info,
                now_secs + 5,
                now_secs + 10
            );
        let (eric_private_state, eric_reenc) = reencrypt(&eric, &session);
        process_reencryption(&eric, &mut session, eric_reenc);
        state_update(&mut session);
        let alice_contribution =
            threshold_scalar_mul::generate_contribution(
                &alice,
                session.thresh_scalar_mul_session.borrow(),
                &alice_share
            );
        process_scalar_mul_share(&alice, &mut session, alice_contribution);
        let bob_contribution =
            threshold_scalar_mul::generate_contribution(
                &bob, session.thresh_scalar_mul_session.borrow(), &bob_share
            );
        process_scalar_mul_share(&bob, &mut session, bob_contribution);
        let eric_contribution =
            threshold_scalar_mul::generate_contribution(
                &eric, session.thresh_scalar_mul_session.borrow(), &eric_share
            );
        process_scalar_mul_share(&eric, &mut session, eric_contribution);
        state_update(&mut session);
        assert!(succeeded(&session), 170517);
        let actual_result = reveal(&session, eric_private_state);
        assert!(target == actual_result, 170518);
    }
}
