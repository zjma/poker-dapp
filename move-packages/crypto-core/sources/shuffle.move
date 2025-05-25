/// The on-chain states/util functions of a shuffle process where:
/// a list of users take turns to verifiably shuffle a list of ElGamal ciphertexts.
module crypto_core::shuffle {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::vector::range;
    use aptos_std::bcs_stream;
    use aptos_std::bcs_stream::BCSStream;
    use aptos_framework::object;
    use aptos_framework::randomness;
    use aptos_framework::timestamp;
    use crypto_core::group;
    use crypto_core::fiat_shamir_transform;
    use crypto_core::pedersen_commitment;
    use crypto_core::bg12;
    use crypto_core::elgamal;
    #[test_only]
    use std::bcs;
    #[test_only]
    use std::vector;
    #[test_only]
    use aptos_std::debug::print;

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

    /// Gas cost: 205 (proof is none), 413 (proof is some)
    public fun decode_contribution(stream: &mut BCSStream): VerifiableContribution {
        let new_ciphertexts = bcs_stream::deserialize_vector(stream, |s|elgamal::decode_ciphertext(s));
        let proof = bcs_stream::deserialize_option(stream, |s|bg12::decode_proof(s));
        VerifiableContribution { new_ciphertexts, proof }
    }

    struct Session has copy, drop, key, store {
        enc_key: elgamal::EncKey,
        pedersen_ctxt: pedersen_commitment::Context,
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
            pedersen_ctxt: pedersen_commitment::dummy_context(),
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
        owner: address,
        enc_key: elgamal::EncKey,
        initial_ciphertexts: vector<elgamal::Ciphertext>,
        allowed_contributors: vector<address>,
        deadlines: vector<u64>
    ): address {
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
        let new_session = Session {
            enc_key,
            pedersen_ctxt: pedersen_commitment::rand_context(num_items),
            initial_ciphertexts,
            allowed_contributors,
            num_contributions_expected,
            deadlines,
            status: STATE__ACCEPTING_CONTRIBUTION,
            expected_contributor_idx: 0,
            contributions: vector[],
            culprit: option::none()
        };
        let session_holder = object::generate_signer(&object::create_sticky_object(owner));
        move_to(&session_holder, new_session);
        address_of(&session_holder)
    }

    public entry fun state_update(session_addr: address) acquires Session {
        let session = borrow_global_mut<Session>(session_addr);
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

    public entry fun process_contribution(contributor: &signer, session_addr: address, contribution_bytes: vector<u8>) acquires Session {
        let session = borrow_global_mut<Session>(session_addr);
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
        let contribution = decode_contribution(&mut bcs_stream::new(contribution_bytes));
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

    public fun succeeded(session_addr: address): bool acquires Session {
        let session = borrow_global<Session>(session_addr);
        session.status == STATE__SUCCEEDED
    }

    public fun failed(session_addr: address): bool acquires Session {
        let session = borrow_global<Session>(session_addr);
        session.status == STATE__FAILED
    }

    public fun in_progress(session_addr: address): bool acquires Session {
        let session = borrow_global<Session>(session_addr);
        session.status == STATE__ACCEPTING_CONTRIBUTION
    }

    public fun get_culprit(session_addr: address): address acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(session.status == STATE__FAILED, 175225);
        *session.culprit.borrow()
    }

    public fun input_cloned(session_addr: address): vector<elgamal::Ciphertext> acquires Session {
        let session = borrow_global<Session>(session_addr);
        session.initial_ciphertexts
    }

    public fun result_cloned(session_addr: address): vector<elgamal::Ciphertext> acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(session.status == STATE__SUCCEEDED, 175158);
        session.contributions[session.num_contributions_expected - 1].new_ciphertexts
    }

    public fun is_waiting_for_contribution(session_addr: address, who: address): bool acquires Session {
        let session = borrow_global<Session>(session_addr);
        if (session.status != STATE__ACCEPTING_CONTRIBUTION)
            return false;
        who == session.allowed_contributors[session.expected_contributor_idx]
    }

    #[lint::allow_unsafe_randomness]
    /// NOTE: client needs to implement this.
    public fun generate_contribution_locally(contributor: &signer, session_addr: address): VerifiableContribution acquires Session {
        let session = borrow_global<Session>(session_addr);
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

    struct SessionBrief has drop, store {
        addr: address,
        enc_key: elgamal::EncKey,
        pedersen_ctxt: pedersen_commitment::Context,
        allowed_contributors: vector<address>,
        deadlines: vector<u64>,
        status: u64,
        expected_contributor_idx: u64,
        last_ciphertexts: vector<elgamal::Ciphertext>,
    }

    #[view]
    public fun brief(session_addr: address): SessionBrief acquires Session {
        let session = borrow_global<Session>(session_addr);
        let last_ciphertexts = if (session.expected_contributor_idx == 0) {
            session.initial_ciphertexts
        } else {
            session.contributions[session.expected_contributor_idx - 1].new_ciphertexts
        };
        SessionBrief {
            addr: session_addr,
            enc_key: session.enc_key,
            pedersen_ctxt: session.pedersen_ctxt,
            allowed_contributors: session.allowed_contributors,
            deadlines: session.deadlines,
            status: session.status,
            expected_contributor_idx: session.expected_contributor_idx,
            last_ciphertexts,
        }
    }

    #[test(
        framework = @0x1, upper_level_session_holder = @0x0123abcd, alice = @0xaaaa, bob = @0xbbbb
    )]
    fun example(
        framework: signer,
        upper_level_session_holder: signer,
        alice: signer,
        bob: signer,
    ) acquires Session {
        randomness::initialize_for_testing(&framework);
        timestamp::set_time_has_started_for_testing(&framework);
        let upper_level_session_addr = address_of(&upper_level_session_holder);
        let alice_addr = address_of(&alice);
        let bob_addr = address_of(&bob);

        let enc_base = group::rand_element();
        let (dk, ek) = elgamal::key_gen(enc_base);
        let plaintexts = vector::range(0, 52).map(|_| group::rand_element());
        let ciphertexts = plaintexts.map_ref(|plain| elgamal::enc(&ek, &group::rand_scalar(), plain));
        let now_secs = timestamp::now_seconds();
        let session_addr =
            new_session(
                upper_level_session_addr,
                ek,
                ciphertexts,
                vector[alice_addr, bob_addr],
                vector[now_secs + 5, now_secs + 10]
            );
        assert!(is_waiting_for_contribution(session_addr, alice_addr), 185955);
        let alice_contribution = generate_contribution_locally(&alice, session_addr);
        process_contribution(&alice, session_addr, bcs::to_bytes(&alice_contribution));
        state_update(session_addr);
        assert!(is_waiting_for_contribution(session_addr, bob_addr), 185956);
        let bob_contribution = generate_contribution_locally(&bob, session_addr);
        process_contribution(&bob, session_addr, bcs::to_bytes(&bob_contribution));
        state_update(session_addr);
        assert!(succeeded(session_addr), 185958);
        let shuffled_ciphs = result_cloned(session_addr);
        let shuffled_plains = shuffled_ciphs.map(|ciph| elgamal::dec(&dk, &ciph));
        let permutation = plaintexts.map(|plain| {
            let (found, new_pos) = shuffled_plains.index_of(&plain);
            assert!(found, 185959);
            new_pos
        });
        print(&permutation);
    }
}
