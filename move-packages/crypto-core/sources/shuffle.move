/// The on-chain states/util functions of a shuffle process where:
/// a list of users take turns to verifiably shuffle a list of ElGamal ciphertexts.
module crypto_core::shuffle {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use aptos_framework::timestamp;
    use crypto_core::fiat_shamir_transform;
    use crypto_core::pederson_commitment;
    use crypto_core::bg12;
    use crypto_core::utils;
    use crypto_core::elgamal;
    #[test_only]
    use std::vector;
    #[test_only]
    use std::vector::range;
    #[test_only]
    use aptos_std::debug::print;
    #[test_only]
    use aptos_framework::randomness;
    #[test_only]
    use crypto_core::group;

    const STATE__ACCEPTING_CONTRIBUTION: u64 = 1;
    const STATE__SUCCEEDED: u64 = 2;
    const STATE__FAILED: u64 = 3;

    struct VerifiableContribution has copy, drop, store {
        new_ciphertexts: vector<elgamal::Ciphertext>,
        proof: Option<bg12::Proof>,
    }

    public fun dummy_contribution(): VerifiableContribution {
        VerifiableContribution {
            new_ciphertexts: vector[],
            proof: option::none(),
        }
    }

    public fun decode_contribution(
        buf: vector<u8>
    ): (vector<u64>, VerifiableContribution, vector<u8>) {
        let (errors, num_items, buf) = utils::decode_u64(buf);
        if (!errors.is_empty()) {
            errors.push_back(182920);
            return (errors, dummy_contribution(), buf);
        };
        let new_ciphertexts = vector[];
        let i = 0;
        while (i < num_items) {
            let (errors, ciphertext, remainder) = elgamal::decode_ciphertext(buf);
            if (!errors.is_empty()) {
                errors.push_back(i);
                errors.push_back(182921);
                return (errors, dummy_contribution(), buf);
            };
            buf = remainder;
            new_ciphertexts.push_back(ciphertext);
            i += 1;
        };
        let buflen = buf.length();
        if (buflen == 0) return (vector[182922], dummy_contribution(), buf);
        let has_proof = buf[0] > 0;
        let buf = buf.slice(1, buflen);
        let proof = if (has_proof) {
            let (errors, proof, remainder) = bg12::decode_proof(buf);
            buf = remainder;
            if (!errors.is_empty()) {
                errors.push_back(182923);
                return (errors, dummy_contribution(), buf);
            };
            option::some(proof)
        } else {
            option::none()
        };
        let ret = VerifiableContribution { new_ciphertexts, proof };
        (vector[], ret, buf)
    }

    public fun encode_contribution(obj: &VerifiableContribution): vector<u8> {
        let buf = vector[];
        let num_ciphs = obj.new_ciphertexts.length();
        buf.append(utils::encode_u64(num_ciphs));
        obj.new_ciphertexts.for_each_ref(|ciph| {
            buf.append(elgamal::encode_ciphertext(ciph));
        });
        if (obj.proof.is_some()) {
            buf.push_back(1);
            buf.append(bg12::encode_proof(obj.proof.borrow()));
        } else {
            buf.push_back(0);
        };
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
        let num_contributions_expected = allowed_contributors.length();
        assert!(num_contributions_expected >= 2, 180007);
        assert!(num_contributions_expected == deadlines.length(), 180008);

        // Ensure deadlines are valid.
        assert!(timestamp::now_seconds() < deadlines[0], 180009);
        let i = 1;
        while (i < num_contributions_expected) {
            assert!(deadlines[i - 1] < deadlines[i], 180010);
            i += 1;
        };

        let num_items = initial_ciphertexts.length();
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
            if (session.contributions.length()
                > session.expected_contributor_idx) {
                session.expected_contributor_idx += 1;
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
        let (found, idx) = session.allowed_contributors.index_of(&addr);
        assert!(found, 180100);
        let num_contri_committed = session.contributions.length();
        assert!(idx == num_contri_committed, 180101);
        let trx = fiat_shamir_transform::new_transcript();
        let original =
            if (idx == 0) {
                &session.initial_ciphertexts
            } else {
                &session.contributions[idx - 1].new_ciphertexts
            };
        if (contribution.proof.is_some()) {
            assert!(
                bg12::verify(
                    &session.enc_key,
                    &session.pedersen_ctxt,
                    &mut trx,
                    original,
                    &contribution.new_ciphertexts,
                    contribution.proof.borrow(),
                ),
                180102
            );
        };
        session.contributions.push_back(contribution);
    }

    public fun succeeded(session: &Session): bool {
        session.status == STATE__SUCCEEDED
    }

    public fun failed(session: &Session): bool {
        session.status == STATE__FAILED
    }

    public fun get_culprit(session: &Session): address {
        assert!(session.status == STATE__FAILED, 175225);
        *session.culprit.borrow()
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
    /// NOTE: client needs to implement this.
    public fun generate_contribution_locally(
        contributor: &signer, session: &Session
    ): VerifiableContribution {
        assert!(session.status == STATE__ACCEPTING_CONTRIBUTION, 183535);
        let contributor_addr = address_of(contributor);
        let (contributor_found, contributor_idx) = session.allowed_contributors.index_of(&contributor_addr);
        assert!(contributor_found, 183536);
        assert!(session.expected_contributor_idx == contributor_idx, 183537);

        let num_items = session.initial_ciphertexts.length();

        let current_deck =
            if (session.expected_contributor_idx == 0) {
                session.initial_ciphertexts
            } else {
                session.contributions[session.expected_contributor_idx - 1].new_ciphertexts
            };
        let permutation = randomness::permutation(num_items);
        let rerandomizers = range(0, num_items).map(|_| group::rand_scalar());

        let new_ciphertexts = range(0, num_items).map(|i| {
            let blinder =
                elgamal::enc(
                    &session.enc_key, &rerandomizers[i], &group::group_identity()
                );
            let new_ciph =
                elgamal::ciphertext_add(&current_deck[permutation[i]], &blinder);
            new_ciph
        });
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
        VerifiableContribution { new_ciphertexts, proof: option::some(proof) }
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

        let enc_base = group::rand_element();
        let (dk, ek) = elgamal::key_gen(enc_base);
        let plaintexts = vector::range(0, 52).map(|_| group::rand_element());
        let ciphertexts = plaintexts.map_ref(|plain| elgamal::enc(&ek, &group::rand_scalar(), plain));
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
        let shuffled_plains = shuffled_ciphs.map(|ciph| elgamal::dec(&dk, &ciph));
        let permutation = plaintexts.map(|plain| {
            let (found, new_pos) = shuffled_plains.index_of(&plain);
            assert!(found, 185959);
            new_pos
        });
        print(&permutation);
    }
}
