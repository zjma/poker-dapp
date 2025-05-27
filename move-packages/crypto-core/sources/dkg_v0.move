/// A naive DKG.
/// - A group of participants use the blockchain as the broadcast channel and collborate to generate a secret `s`.
/// - No one knows `s`.
/// - Every participant gets a secret share which they need to keep private.
/// - If someone sees all the secret shares, they can reconstruct `s`.
/// - For any group element `P`, the group can collaborate to reveal `s*P` without leaking any information about `s`.
///   - See more details in `threshold_scalar_mul.move`.
module crypto_core::dkg_v0 {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::vector;
    use aptos_std::bcs_stream;
    use aptos_std::bcs_stream::BCSStream;
    use aptos_framework::object;
    use aptos_framework::timestamp;
    use crypto_core::fiat_shamir_transform;
    use crypto_core::sigma_dlog;
    use crypto_core::elgamal::EncKey;
    use crypto_core::elgamal;
    use crypto_core::group;
    #[test_only]
    use std::bcs;

    const STATE__IN_PROGRESS: u64 = 0;
    const STATE__SUCCEEDED: u64 = 1;
    const STATE__TIMED_OUT: u64 = 2;

    struct Session has copy, drop, key, store {
        base_point: group::Element,
        expected_contributors: vector<address>,
        deadline: u64,
        state: u64,
        contributions: vector<Option<VerifiableContribution>>,
        contribution_still_needed: u64,
        agg_public_point: group::Element,
        culprits: vector<address>,
    }

    struct SessionBrief has drop, store {
        addr: address,
        base_point: group::Element,
        expected_contributors: vector<address>,
        deadline: u64,
        state: u64,
        contributed_flags: vector<bool>,
        agg_public_point: group::Element,
    }

    struct VerifiableContribution has copy, drop, store {
        public_point: group::Element,
        proof: Option<sigma_dlog::Proof>,
    }

    struct SecretShare has copy, drop, store {
        private_scalar: group::Scalar
    }

    struct SharedSecretPublicInfo has copy, drop, store {
        session_addr: address,
        agg_ek: elgamal::EncKey,
        ek_shares: vector<elgamal::EncKey>
    }

    public fun dummy_session(): Session {
        Session {
            base_point: group::group_identity(),
            expected_contributors: vector[],
            deadline: 0,
            state: STATE__IN_PROGRESS,
            contributions: vector[],
            contribution_still_needed: 0,
            agg_public_point: group::group_identity(),
            culprits: vector[]
        }
    }

    public fun dummy_contribution(): VerifiableContribution {
        VerifiableContribution {
            public_point: group::dummy_element(),
            proof: option::none(),
        }
    }

    public fun dummy_secret_info(): SharedSecretPublicInfo {
        SharedSecretPublicInfo {
            session_addr: @0x0,
            agg_ek: elgamal::dummy_enc_key(),
            ek_shares: vector[]
        }
    }

    public fun decode_contribution(stream: &mut BCSStream): VerifiableContribution {
        let public_point = group::decode_element(stream);
        let proof = bcs_stream::deserialize_option(stream, |s|sigma_dlog::decode_proof(s));
        VerifiableContribution { public_point, proof }
    }

    public fun decode_secret_info(stream: &mut BCSStream): SharedSecretPublicInfo {
        let session_addr = bcs_stream::deserialize_address(stream);
        let agg_ek = elgamal::decode_enc_key(stream);
        let ek_shares = bcs_stream::deserialize_vector(stream, |s|elgamal::decode_enc_key(s));
        SharedSecretPublicInfo {
            session_addr,
            agg_ek,
            ek_shares,
        }
    }

    const INF: u64 = 999999999;

    #[lint::allow_unsafe_randomness]
    public fun new_session(owner: address, expected_contributors: vector<address>): address {
        let num_players = expected_contributors.length();
        let new_session = Session {
            base_point: group::rand_element(),
            expected_contributors,
            deadline: timestamp::now_seconds() + INF,
            state: STATE__IN_PROGRESS,
            contributions: vector::range(0, num_players).map(|_| option::none()),
            contribution_still_needed: expected_contributors.length(),
            agg_public_point: group::group_identity(),
            culprits: vector[]
        };
        let session_holder = object::generate_signer(&object::create_sticky_object(owner));
        move_to(&session_holder, new_session);
        address_of(&session_holder)
    }

    public fun succeeded(session_addr: address): bool acquires Session {
        let dkg_session = borrow_global<Session>(session_addr);
        dkg_session.state == STATE__SUCCEEDED
    }

    public fun failed(session_addr: address): bool acquires Session {
        let dkg_session = borrow_global<Session>(session_addr);
        dkg_session.state == STATE__TIMED_OUT
    }

    public fun get_culprits(session_addr: address): vector<address> acquires Session {
        let dkg_session = borrow_global<Session>(session_addr);
        dkg_session.culprits
    }

    public fun get_contributors(session_addr: address): vector<address> acquires Session {
        let dkg_session = borrow_global<Session>(session_addr);
        assert!(dkg_session.state == STATE__SUCCEEDED, 191253);
        dkg_session.expected_contributors
    }

    /// Anyone can call this to trigger state transitions for the given DKG.
    public entry fun state_update(session_addr: address) acquires Session {
        let dkg_session = borrow_global_mut<Session>(session_addr);
        if (dkg_session.state == STATE__IN_PROGRESS) {
            if (dkg_session.contribution_still_needed == 0) {
                dkg_session.contributions.for_each_ref(|contri| {
                    let contri: &Option<VerifiableContribution> = contri;
                    let contribution = *contri.borrow();
                    group::element_add_assign(
                        &mut dkg_session.agg_public_point,
                        &contribution.public_point
                    );
                });
                dkg_session.state = STATE__SUCCEEDED;
            } else if (timestamp::now_seconds() >= dkg_session.deadline) {
                let n = dkg_session.expected_contributors.length();
                let culprit_idxs = vector::range(0, n).filter(|idx| {
                    dkg_session.contributions[*idx].is_none()
                });
                let culprits = culprit_idxs.map(|idx| dkg_session.expected_contributors[idx]);
                dkg_session.state = STATE__TIMED_OUT;
                dkg_session.culprits = culprits;
            }
        }
    }

    /// Gas cost: 5.44
    public entry fun process_contribution(
        contributor: &signer,
        session_addr: address,
        contribution_bytes: vector<u8>,
    ) acquires Session {
        let session = borrow_global_mut<Session>(session_addr);
        let contributor_addr = address_of(contributor);
        let (found, contributor_idx) = session.expected_contributors.index_of(&contributor_addr);
        assert!(found, 124130);
        let contribution = decode_contribution(&mut bcs_stream::new(contribution_bytes));
        if (contribution.proof.is_some()) {
            let proof = contribution.proof.borrow();
            let trx = fiat_shamir_transform::new_transcript();
            assert!(sigma_dlog::verify(&mut trx, &session.base_point, &contribution.public_point, proof), 124131);
        } else {
            //TODO: enforce proof after debugging
        };

        session.contribution_still_needed -= 1;
        session.contributions[contributor_idx].fill(contribution);
    }

    #[view]
    public fun brief(session_addr: address): SessionBrief acquires Session {
        let session = borrow_global<Session>(session_addr);
        SessionBrief {
            addr: session_addr,
            base_point: session.base_point,
            expected_contributors: session.expected_contributors,
            deadline: session.deadline,
            state: session.state,
            contributed_flags: session.contributions.map_ref(|c|c.is_some()),
            agg_public_point: session.agg_public_point,

        }
    }

    public fun get_shared_secret_public_info(session_addr: address): SharedSecretPublicInfo acquires Session {
        let session = borrow_global<Session>(session_addr);
        assert!(session.state == STATE__SUCCEEDED, 193709);
        let agg_ek = elgamal::make_enc_key(session.base_point, session.agg_public_point);
        let ek_shares = session.contributions.map_ref(|contri| {
            let contri: &Option<VerifiableContribution> = contri;
            let contribution = *contri.borrow();
            elgamal::make_enc_key(session.base_point, contribution.public_point)
        });
        SharedSecretPublicInfo { session_addr, agg_ek, ek_shares }
    }

    public fun unpack_shared_secret_public_info(
        info: SharedSecretPublicInfo
    ): (address, EncKey, vector<EncKey>) {
        let SharedSecretPublicInfo { session_addr, agg_ek, ek_shares } = info;
        (session_addr, agg_ek, ek_shares)
    }

    public fun unpack_secret_share(secret_share: SecretShare): group::Scalar {
        let SecretShare { private_scalar } = secret_share;
        private_scalar
    }

    public fun get_threshold(secret_info: &SharedSecretPublicInfo): u64 {
        secret_info.ek_shares.length()
    }

    /// Given the shares of a threshold scalar multiplication,compute the scalar-mul result.
    /// Assume that any given share is valid and the number of shares given is greater than or equal to the threshold.
    ///
    /// Gas cost: 0.68*n
    public fun aggregate_scalar_mul(
        _secret_info: &SharedSecretPublicInfo, shares: vector<Option<group::Element>>
    ): group::Element {
        let ret = group::group_identity();
        shares.for_each(|share| {
            group::element_add_assign(&mut ret, &share.extract());
        });
        ret
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// NOTE: client needs to implement this.
    public fun generate_contribution(session_addr: address): (SecretShare, VerifiableContribution) acquires Session {
        let session = borrow_global<Session>(session_addr);
        let private_scalar = group::rand_scalar();
        let secret_share = SecretShare { private_scalar };
        let public_point = group::scale_element(&session.base_point, &private_scalar);
        let proof =
            sigma_dlog::prove(
                &mut fiat_shamir_transform::new_transcript(),
                &session.base_point,
                &public_point,
                &private_scalar
            );
        let contribution = VerifiableContribution { public_point, proof: option::some(proof) };
        (secret_share, contribution)
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// An example DKG done by Alice, Bob, Eric.
    public fun run_example_session(
        upper_level_session_addr: address, alice: &signer, bob: &signer, eric: &signer
    ): (SharedSecretPublicInfo, SecretShare, SecretShare, SecretShare) acquires Session {
        let alice_addr = address_of(alice);
        let bob_addr = address_of(bob);
        let eric_addr = address_of(eric);
        let dkg_session_addr = new_session(upper_level_session_addr, vector[alice_addr, bob_addr, eric_addr]);
        let (alice_secret_share, alice_contribution) = generate_contribution(dkg_session_addr);
        let (bob_secret_share, bob_contribution) = generate_contribution(dkg_session_addr);
        let (eric_secret_share, eric_contribution) = generate_contribution(dkg_session_addr);
        process_contribution(alice, dkg_session_addr, bcs::to_bytes(&alice_contribution));
        process_contribution(bob, dkg_session_addr, bcs::to_bytes(&bob_contribution));
        process_contribution(eric, dkg_session_addr, bcs::to_bytes(&eric_contribution));
        state_update(dkg_session_addr);
        assert!(succeeded(dkg_session_addr), 999);
        let public_info = get_shared_secret_public_info(dkg_session_addr);
        (public_info, alice_secret_share, bob_secret_share, eric_secret_share)
    }

    #[test_only]
    /// Given enough secret shares, reconstruct the secret.
    public fun reconstruct_secret(
        public_info: &SharedSecretPublicInfo, shares: vector<Option<SecretShare>>
    ): group::Scalar {
        let n = public_info.ek_shares.length();
        assert!(n == shares.length(), 162205);
        let agg = group::scalar_from_u64(0);
        shares.for_each(|share| {
            let share = share.extract();
            let s = unpack_secret_share(share);
            agg = group::scalar_add(&agg, &s);
        });
        agg
    }
}
