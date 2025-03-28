/// On-chain states and util functions of a re-encryption where:
/// a group of users collaborate to transform a ciphertext without actually decrypting it,
/// so only a targeted user can decrypt privately.
/// The group has to have a shared ElGamal decrpyion key `s`.
/// The ciphertext has to be generated with the ElGamal encryption key corresponding to `s`.
module contract_owner::reencryption {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::string;
    use std::vector;
    use aptos_std::type_info;
    use aptos_framework::timestamp;
    use contract_owner::dkg_v0;
    use contract_owner::threshold_scalar_mul;
    use contract_owner::group;
    use contract_owner::elgamal;
    #[test_only]
    use aptos_framework::randomness;

    const STATE__ACCEPTING_REENC: u64 = 1;
    const STATE__THRESHOLD_SCALAR_MUL_IN_PROGRESS: u64 = 2;
    const STATE__SUCCEEDED: u64 = 3;
    const STATE__FAILED: u64 = 4;

    struct VerifiableReencrpytion has copy, drop, store {
        new_ciph: elgamal::Ciphertext,
        new_ek: group::Element,
        // TODO: proof
    }

    public fun dummy_reencryption(): VerifiableReencrpytion {
        VerifiableReencrpytion {
            new_ciph: elgamal::dummy_ciphertext(),
            new_ek: group::dummy_element(),
        }
    }

    public fun encode_reencryption(obj: &VerifiableReencrpytion): vector<u8> {
        let buf = *string::bytes(&type_info::type_name<VerifiableReencrpytion>());
        vector::append(&mut buf, elgamal::encode_ciphertext(&obj.new_ciph));
        vector::append(&mut buf, group::encode_element(&obj.new_ek));
        buf
    }

    public fun decode_reencyption(buf: vector<u8>): (vector<u64>, VerifiableReencrpytion, vector<u8>) {
        let buf_len = vector::length(&buf);
        let header = *string::bytes(&type_info::type_name<VerifiableReencrpytion>());
        let header_len = vector::length(&header);
        if (buf_len < header_len) return (vector[302034], dummy_reencryption(), buf);
        let buf = vector::slice(&buf, header_len, buf_len);
        let (errors, new_ciph, buf) = elgamal::decode_ciphertext(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 302035);
            return (errors, dummy_reencryption(), buf);
        };
        let (errors, new_ek, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 302036);
            return (errors, dummy_reencryption(), buf);
        };
        let ret = VerifiableReencrpytion {
            new_ciph, new_ek,
        };
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
        reenc: Option<VerifiableReencrpytion>,
        thresh_scalar_mul_session: Option<threshold_scalar_mul::Session>,
        culprits: vector<address>,
    }

    public fun new_session(
        card: elgamal::Ciphertext, deal_target: address, scalar_mul_party: vector<address>, secret_info: dkg_v0::SharedSecretPublicInfo,
        reencryption_deadline: u64, scalar_mul_deadline: u64,
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
            culprits: vector[],
        }
    }

    public fun process_reencryption(player: &signer, session: &mut Session, reenc: VerifiableReencrpytion) {
        assert!(session.state == STATE__ACCEPTING_REENC, 175626);
        let player_addr = address_of(player);
        assert!(session.deal_target == player_addr, 175627);
        //TODO: verify reenc
        session.reenc = option::some(reenc);

    }

    public fun process_scalar_mul_share(player: &signer, session: &mut Session, share: threshold_scalar_mul::VerifiableContribution) {
        let sub_session = option::borrow_mut(&mut session.thresh_scalar_mul_session);
        threshold_scalar_mul::process_contribution(player, sub_session, share);
    }

    public fun state_update(session: &mut Session) {
        let now_secs = timestamp::now_seconds();
        if (session.state == STATE__ACCEPTING_REENC) {
            if (option::is_some(&session.reenc)) {
                let new_ciph = option::borrow(&session.reenc).new_ciph;
                let (_, new_c0, _) = elgamal::unpack_ciphertext(new_ciph);
                let sub_session = threshold_scalar_mul::new_session(new_c0, session.secret_info, session.scalar_mul_party, session.scalar_mul_deadline);
                session.state = STATE__THRESHOLD_SCALAR_MUL_IN_PROGRESS;
                session.thresh_scalar_mul_session = option::some(sub_session);
            } else if (now_secs >= session.deadline) {
                session.state = STATE__FAILED;
                session.culprits = vector[session.deal_target];
            }
        } else if (session.state == STATE__THRESHOLD_SCALAR_MUL_IN_PROGRESS) {
            let sub_session = option::borrow_mut(&mut session.thresh_scalar_mul_session);
            threshold_scalar_mul::state_update(sub_session);
            if (threshold_scalar_mul::succeeded(sub_session)) {
                session.state = STATE__SUCCEEDED;
            } else if (threshold_scalar_mul::failed(sub_session)) {
                session.state = STATE__FAILED;
                session.culprits = threshold_scalar_mul::get_culprits(sub_session);
            }
        }
    }

    public fun borrow_reenc(session: &Session): &VerifiableReencrpytion {
        option::borrow(&session.reenc)
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
        option::borrow(&session.thresh_scalar_mul_session)
    }

    struct RecipientPrivateState has copy, drop {
        u: group::Scalar,
    }

    public fun dummy_private_state(): RecipientPrivateState {
        RecipientPrivateState { u: group::dummy_scalar() }
    }

    public fun decode_private_state(buf: vector<u8>): (vector<u64>, RecipientPrivateState, vector<u8>) {
        let (errors, u, buf) = group::decode_scalar(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 124147);
            return (errors, dummy_private_state(), buf);
        };
        let ret = RecipientPrivateState { u };
        (vector[], ret, buf)
    }

    public fun encode_private_state(obj: &RecipientPrivateState): vector<u8> {
        group::encode_scalar(&obj.u)
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    public fun reencrypt(target: &signer, session: &Session): (RecipientPrivateState, VerifiableReencrpytion) {
        let addr = address_of(target);
        assert!(addr == session.deal_target, 285206);

        let (ek, _) = dkg_v0::unpack_shared_secret_public_info(session.secret_info);
        let (_, old_ek) = elgamal::unpack_enc_key(ek);
        let t = group::rand_scalar();
        let u = group::rand_scalar();
        let (enc_base, c_0, c_1) = elgamal::unpack_ciphertext(session.card);
        let new_c0 = group::element_add(&c_0, &group::scale_element(&enc_base, &t));
        let new_c1 = group::element_sum(vector[c_1, group::scale_element(&c_0, &u), group::scale_element(&old_ek, &t), group::scale_element(&enc_base, &group::scalar_mul(&t, &u))]);
        let new_ciph = elgamal::make_ciphertext(enc_base, new_c0, new_c1);
        let new_ek = group::element_add(&old_ek, &group::scale_element(&enc_base, &u));
        let reenc = VerifiableReencrpytion { new_ciph, new_ek };
        let private_state = RecipientPrivateState { u };
        (private_state, reenc)
    }

    public fun reveal(session: &Session, private_state: RecipientPrivateState): group::Element {
        assert!(session.state == STATE__SUCCEEDED, 285305);
        let RecipientPrivateState { u } = private_state;
        let (enc_base, _, _) = elgamal::unpack_ciphertext(session.card);
        let (old_ek, _) = dkg_v0::unpack_shared_secret_public_info(session.secret_info);
        let (_, old_ek_element) = elgamal::unpack_enc_key(old_ek);
        let rhs = group::element_add(&old_ek_element, &group::scale_element(&enc_base, &u));
        let lhs = option::borrow(&session.reenc).new_ek;
        assert!(lhs == rhs, 285307);
        let srtH = threshold_scalar_mul::get_result(option::borrow(&session.thresh_scalar_mul_session));
        let (_, new_c0, new_c1) = elgamal::unpack_ciphertext(option::borrow(&session.reenc).new_ciph);
        let plaintext = group::element_sub(&new_c1, &group::element_add(&srtH, &group::scale_element(&new_c0, &u)));
        plaintext
    }

    #[test(framework = @0x1, alice = @0xaaaa, bob = @0xbbbb, eric = @0xeeee)]
    fun example(framework: signer, alice: signer, bob: signer, eric: signer) {
        randomness::initialize_for_testing(&framework);
        timestamp::set_time_has_started_for_testing(&framework);
        let alice_addr = address_of(&alice);
        let bob_addr = address_of(&bob);
        let eric_addr = address_of(&eric);
        let (secret_info, alice_share, bob_share, eric_share) = dkg_v0::run_example_session(&alice, &bob, &eric);
        let (agg_ek, ek_shares) = dkg_v0::unpack_shared_secret_public_info(secret_info);
        let target = group::rand_element();
        let r = group::rand_scalar();
        let target_ciph = elgamal::enc(&agg_ek, &r, &target);
        let now_secs = timestamp::now_seconds();
        let session = new_session(target_ciph, eric_addr, vector[alice_addr, bob_addr, eric_addr], secret_info, now_secs + 5, now_secs + 10);
        let (eric_private_state, eric_reenc) = reencrypt(&eric, &session);
        process_reencryption(&eric, &mut session, eric_reenc);
        state_update(&mut session);
        let alice_contribution = threshold_scalar_mul::generate_contribution(&alice, option::borrow(&session.thresh_scalar_mul_session), &alice_share);
        process_scalar_mul_share(&alice, &mut session, alice_contribution);
        let bob_contribution = threshold_scalar_mul::generate_contribution(&bob, option::borrow(&session.thresh_scalar_mul_session), &bob_share);
        process_scalar_mul_share(&bob, &mut session, bob_contribution);
        let eric_contribution = threshold_scalar_mul::generate_contribution(&eric, option::borrow(&session.thresh_scalar_mul_session), &eric_share);
        process_scalar_mul_share(&eric, &mut session, eric_contribution);
        state_update(&mut session);
        assert!(succeeded(&session), 170517);
        let actual_result = reveal(&session, eric_private_state);
        assert!(target == actual_result, 170518);
    }
}
