/// On-chain states and util functions of a re-encryption where:
/// a group of users collaborate to transform a ciphertext without actually decrypting it,
/// so only a targeted user can decrypt privately.
/// The group has to have a shared ElGamal decrpyion key `s`.
/// The ciphertext has to be generated with the ElGamal encryption key corresponding to `s`.
module crypto_core::reencryption {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
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

    /// NOTE: client needs to implement this.
    public fun encode_reencryption(obj: &VerifiableReencrpytion): vector<u8> {
        let buf = vector[];
        buf.append(group::encode_element(&obj.th));
        buf.append(group::encode_element(&obj.tsh));
        buf.append(group::encode_element(&obj.urth));
        if (obj.proof_t.is_some()) {
            buf.push_back(1);
            buf.append(sigma_dlog_eq::encode_proof(obj.proof_t.borrow()));
        } else {
            buf.push_back(0);
        };
        if (obj.proof_u.is_some()) {
            buf.push_back(1);
            buf.append(sigma_dlog::encode_proof(obj.proof_u.borrow()));
        } else {
            buf.push_back(0);
        };
        buf
    }

    public fun decode_reencyption(
        buf: vector<u8>
    ): (vector<u64>, VerifiableReencrpytion, vector<u8>) {
        let (errors, th, buf) = group::decode_element(buf);
        if (!errors.is_empty()) {
            errors.push_back(302035);
            return (errors, dummy_reencryption(), buf);
        };
        let (errors, tsh, buf) = group::decode_element(buf);
        if (!errors.is_empty()) {
            errors.push_back(302036);
            return (errors, dummy_reencryption(), buf);
        };
        let (errors, urth, buf) = group::decode_element(buf);
        if (!errors.is_empty()) {
            errors.push_back(302037);
            return (errors, dummy_reencryption(), buf);
        };
        let buflen = buf.length();
        if (buflen == 0) return (vector[302038], dummy_reencryption(), buf);
        let has_proof_t = buf[0] > 0;
        let buf = buf.slice(1, buflen);
        let proof_t = if (has_proof_t) {
            let (errors, proof_t, remainder) = sigma_dlog_eq::decode_proof(buf);
            buf = remainder;
            if (!errors.is_empty()) {
                errors.push_back(302039);
                return (errors, dummy_reencryption(), buf);
            };
            option::some(proof_t)
        } else {
            option::none()
        };
        let buflen = buf.length();
        if (buflen == 0) return (vector[302040], dummy_reencryption(), buf);
        let has_proof_u = buf[0] > 0;
        let buf = buf.slice(1, buflen);
        let proof_u = if (has_proof_u) {
            let (errors, proof_u, remainder) = sigma_dlog::decode_proof(buf);
            buf = remainder;
            if (!errors.is_empty()) {
                errors.push_back(302041);
                return (errors, dummy_reencryption(), buf);
            };
            option::some(proof_u)
        } else {
            option::none()
        };
        let ret = VerifiableReencrpytion { th, tsh, urth, proof_t, proof_u };
        (vector[], ret, buf)
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
                104032
            );
        };
        let new_c0 = group::element_add(&rh, &th);
        let new_c1 = group::element_sum(vector[old_c1, urth, tsh]);
        let new_ciph = elgamal::make_ciphertext(enc_base, new_c0, new_c1);
        session.reenc = option::some(new_ciph);
    }

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

    public fun decode_private_state(
        buf: vector<u8>
    ): (vector<u64>, RecipientPrivateState, vector<u8>) {
        let (errors, u, buf) = group::decode_scalar(buf);
        if (!errors.is_empty()) {
            errors.push_back(124147);
            return (errors, dummy_private_state(), buf);
        };
        let ret = RecipientPrivateState { u };
        (vector[], ret, buf)
    }

    /// NOTE: client needs to implement this.
    public fun encode_private_state(obj: &RecipientPrivateState): vector<u8> {
        group::encode_scalar(&obj.u)
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
