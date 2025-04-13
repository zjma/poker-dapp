/// The on-chain states/util functions of a shuffle process where:
/// a list of users take turns to verifiably shuffle a list of ElGamal ciphertexts.
module contract_owner::shuffle {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::vector;
    use aptos_framework::timestamp;
    use contract_owner::fiat_shamir_transform;
    use contract_owner::pederson_commitment;
    use contract_owner::bg12;
    use contract_owner::utils;
    use contract_owner::elgamal;
    #[test_only]
    use aptos_std::debug::print;
    #[test_only]
    use aptos_framework::randomness;
    #[test_only]
    use contract_owner::group;

    const STATE__ACCEPTING_CONTRIBUTION: u64 = 1;
    const STATE__SUCCEEDED: u64 = 2;
    const STATE__FAILED: u64 = 3;

    struct VerifiableContribution has copy, drop, store {
        new_ciphertexts: vector<elgamal::Ciphertext>,
        proof: bg12::Proof
    }

    public fun dummy_contribution(): VerifiableContribution {
        VerifiableContribution {
            new_ciphertexts: vector[],
            proof: bg12::dummy_proof()
        }
    }

    public fun decode_contribution(
        buf: vector<u8>
    ): (vector<u64>, VerifiableContribution, vector<u8>) {
        let (errors, num_items, buf) = utils::decode_u64(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 182920);
            return (errors, dummy_contribution(), buf);
        };
        let new_ciphertexts = vector[];
        let i = 0;
        while (i < num_items) {
            let (errors, ciphertext, remainder) = elgamal::decode_ciphertext(buf);
            if (!vector::is_empty(&errors)) {
                vector::push_back(&mut errors, i);
                vector::push_back(&mut errors, 182921);
                return (errors, dummy_contribution(), buf);
            };
            buf = remainder;
            vector::push_back(&mut new_ciphertexts, ciphertext);
            i = i + 1;
        };
        let (errors, proof, buf) = bg12::decode_proof(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 182922);
            return (errors, dummy_contribution(), buf);
        };
        let ret = VerifiableContribution { new_ciphertexts, proof };
        (vector[], ret, buf)
    }

    public fun encode_contribution(obj: &VerifiableContribution): vector<u8> {
        let buf = vector[];
        let num_ciphs = vector::length(&obj.new_ciphertexts);
        vector::append(&mut buf, utils::encode_u64(num_ciphs));
        vector::for_each_ref(
            &obj.new_ciphertexts,
            |ciph| {
                vector::append(&mut buf, elgamal::encode_ciphertext(ciph));
            }
        );
        vector::append(&mut buf, bg12::encode_proof(&obj.proof));
        buf
    }

    struct Session has copy, drop, store {
        enc_key: elgamal::EncKey,
        pedersen_ctxt: pederson_commitment::Context,
        initial_ciphertexts: vector<elgamal::Ciphertext>,
        allowed_contributors: vector<address>,
        num_contributions_expected: u64,
        deadlines: vector<u64>,
        status: u64,
        /// If `status == STATE__ACCEPTING_CONTRIBUTION`, this indicates who should contribute now.
        expected_contributor_idx: u64,
        contributions: vector<VerifiableContribution>,
        culprit: Option<address>
    }

    public fun dummy_session(): Session {
        Session {
            enc_key: elgamal::dummy_enc_key(),
            pedersen_ctxt: pederson_commitment::dummy_context(),
            initial_ciphertexts: vector[],
            allowed_contributors: vector[],
            num_contributions_expected: 0,
            deadlines: vector[],
            status: 0,
            expected_contributor_idx: 0,
            contributions: vector[],
            culprit: option::none()
        }
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(
        enc_key: elgamal::EncKey,
        initial_ciphertexts: vector<elgamal::Ciphertext>,
        allowed_contributors: vector<address>,
        deadlines: vector<u64>
    ): Session {
        let num_contributions_expected = vector::length(&allowed_contributors);
        assert!(num_contributions_expected >= 2, 180007);
        assert!(num_contributions_expected == vector::length(&deadlines), 180008);

        // Ensure deadlines are valid.
        assert!(timestamp::now_seconds() < deadlines[0], 180009);
        let i = 1;
        while (i < num_contributions_expected) {
            assert!(deadlines[i - 1] < deadlines[i], 180010);
            i = i + 1;
        };

        let num_items = vector::length(&initial_ciphertexts);
        Session {
            enc_key,
            pedersen_ctxt: pederson_commitment::rand_context(num_items),
            initial_ciphertexts,
            allowed_contributors,
            num_contributions_expected,
            deadlines,
            status: STATE__ACCEPTING_CONTRIBUTION,
            expected_contributor_idx: 0,
            contributions: vector[],
            culprit: option::none()
        }
    }

    public fun state_update(session: &mut Session) {
        let now_secs = timestamp::now_seconds();
        if (session.status == STATE__ACCEPTING_CONTRIBUTION) {
            if (vector::length(&session.contributions)
                > session.expected_contributor_idx) {
                session.expected_contributor_idx = session.expected_contributor_idx + 1;
                if (session.expected_contributor_idx
                    == session.num_contributions_expected) {
                    session.status = STATE__SUCCEEDED;
                }
            } else if (now_secs >= session.deadlines[session.expected_contributor_idx]) {
                session.status = STATE__FAILED;
                session.culprit = option::some(
                    session.allowed_contributors[session.expected_contributor_idx]
                );
            }
        }
    }

    public fun process_contribution(
        contributor: &signer, session: &mut Session, contribution: VerifiableContribution
    ) {
        let addr = address_of(contributor);
        let (found, idx) = vector::index_of(&session.allowed_contributors, &addr);
        assert!(found, 180100);
        let num_contri_committed = vector::length(&session.contributions);
        assert!(idx == num_contri_committed, 180101);
        let trx = fiat_shamir_transform::new_transcript();
        let original =
            if (idx == 0) {
                &session.initial_ciphertexts
            } else {
                &session.contributions[idx - 1].new_ciphertexts
            };
        assert!(
            bg12::verify(
                &session.enc_key,
                &session.pedersen_ctxt,
                &mut trx,
                original,
                &contribution.new_ciphertexts,
                &contribution.proof
            ),
            180102
        );
        vector::push_back(&mut session.contributions, contribution);
    }

    public fun succeeded(session: &Session): bool {
        session.status == STATE__SUCCEEDED
    }

    public fun failed(session: &Session): bool {
        session.status == STATE__FAILED
    }

    public fun get_culprit(session: &Session): address {
        assert!(session.status == STATE__FAILED, 175225);
        *option::borrow(&session.culprit)
    }

    public fun input_cloned(session: &Session): vector<elgamal::Ciphertext> {
        session.initial_ciphertexts
    }

    public fun result_cloned(session: &Session): vector<elgamal::Ciphertext> {
        assert!(session.status == STATE__SUCCEEDED, 175158);
        session.contributions[session.num_contributions_expected - 1].new_ciphertexts
    }

    public fun is_waiting_for_contribution(
        session: &Session, who: address
    ): bool {
        if (session.status != STATE__ACCEPTING_CONTRIBUTION)
            return false;
        who == session.allowed_contributors[session.expected_contributor_idx]
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    public fun generate_contribution_locally(
        contributor: &signer, session: &Session
    ): VerifiableContribution {
        assert!(session.status == STATE__ACCEPTING_CONTRIBUTION, 183535);
        let contributor_addr = address_of(contributor);
        let (contributor_found, contributor_idx) = vector::index_of(
            &session.allowed_contributors, &contributor_addr
        );
        assert!(contributor_found, 183536);
        assert!(session.expected_contributor_idx == contributor_idx, 183537);

        let num_items = vector::length(&session.initial_ciphertexts);

        let current_deck =
            if (session.expected_contributor_idx == 0) {
                session.initial_ciphertexts
            } else {
                session.contributions[session.expected_contributor_idx - 1].new_ciphertexts
            };
        let permutation = randomness::permutation(num_items);
        let rerandomizers = vector::map(
            vector::range(0, num_items),
            |_| group::rand_scalar()
        );

        let new_ciphertexts = vector::map(
            vector::range(0, num_items),
            |i| {
                let blinder =
                    elgamal::enc(
                        &session.enc_key, &rerandomizers[i], &group::group_identity()
                    );
                let new_ciph =
                    elgamal::ciphertext_add(&current_deck[permutation[i]], &blinder);
                new_ciph
            }
        );
        let trx = fiat_shamir_transform::new_transcript();
        let proof =
            bg12::prove(
                &session.enc_key,
                &session.pedersen_ctxt,
                &mut trx,
                &current_deck,
                &new_ciphertexts,
                permutation,
                &rerandomizers
            );
        VerifiableContribution { new_ciphertexts, proof }
    }

    #[test(
        framework = @0x1, alice = @0xaaaa, bob = @0xbbbb, eric = @0xeeee
    )]
    fun example(
        framework: signer, alice: signer, bob: signer, eric: signer
    ) {
        randomness::initialize_for_testing(&framework);
        timestamp::set_time_has_started_for_testing(&framework);
        let alice_addr = address_of(&alice);
        let bob_addr = address_of(&bob);
        let eric_addr = address_of(&eric);

        let enc_base = group::rand_element();
        let (dk, ek) = elgamal::key_gen(enc_base);
        let plaintexts = vector::map(
            vector::range(0, 52),
            |_| group::rand_element()
        );
        let ciphertexts = vector::map_ref(
            &plaintexts,
            |plain| elgamal::enc(&ek, &group::rand_scalar(), plain)
        );
        let now_secs = timestamp::now_seconds();
        let session =
            new_session(
                ek,
                ciphertexts,
                vector[alice_addr, bob_addr, eric_addr],
                vector[now_secs + 5, now_secs + 10, now_secs + 15]
            );
        assert!(is_waiting_for_contribution(&session, alice_addr), 185955);
        let alice_contribution = generate_contribution_locally(&alice, &session);
        process_contribution(&alice, &mut session, alice_contribution);
        state_update(&mut session);
        assert!(is_waiting_for_contribution(&session, bob_addr), 185956);
        let bob_contribution = generate_contribution_locally(&bob, &session);
        process_contribution(&bob, &mut session, bob_contribution);
        state_update(&mut session);
        assert!(is_waiting_for_contribution(&session, eric_addr), 185957);
        let eric_contribution = generate_contribution_locally(&eric, &session);
        process_contribution(&eric, &mut session, eric_contribution);
        state_update(&mut session);
        assert!(succeeded(&session), 185958);
        let shuffled_ciphs = result_cloned(&session);
        let shuffled_plains = vector::map(
            shuffled_ciphs, |ciph| elgamal::dec(&dk, &ciph)
        );
        let permutation = vector::map(
            plaintexts,
            |plain| {
                let (found, new_pos) = vector::index_of(&shuffled_plains, &plain);
                assert!(found, 185959);
                new_pos
            }
        );
        print(&permutation);
    }
}
