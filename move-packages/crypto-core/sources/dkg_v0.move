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
    use aptos_framework::timestamp;
    use crypto_core::fiat_shamir_transform;
    use crypto_core::sigma_dlog;
    use crypto_core::elgamal::EncKey;
    use crypto_core::elgamal;
    use crypto_core::group;

    const STATE__IN_PROGRESS: u64 = 0;
    const STATE__SUCCEEDED: u64 = 1;
    const STATE__TIMED_OUT: u64 = 2;

    struct DKGSession has copy, drop, store {
        base_point: group::Element,
        expected_contributors: vector<address>,
        deadline: u64,
        state: u64,
        contributions: vector<Option<VerifiableContribution>>,
        contribution_still_needed: u64,
        agg_public_point: group::Element,
        culprits: vector<address>,
    }

    struct VerifiableContribution has copy, drop, store {
        public_point: group::Element,
        proof: Option<sigma_dlog::Proof>,
    }

    struct SecretShare has copy, drop, store {
        private_scalar: group::Scalar
    }

    struct SharedSecretPublicInfo has copy, drop, store {
        agg_ek: elgamal::EncKey,
        ek_shares: vector<elgamal::EncKey>
    }

    public fun dummy_session(): DKGSession {
        DKGSession {
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
        let agg_ek = elgamal::decode_enc_key(stream);
        let ek_shares = bcs_stream::deserialize_vector(stream, |s|elgamal::decode_enc_key(s));
        SharedSecretPublicInfo {
            agg_ek,
            ek_shares,
        }
    }

    const INF: u64 = 999999999;

    #[lint::allow_unsafe_randomness]
    public fun new_session(expected_contributors: vector<address>): DKGSession {
        let num_players = expected_contributors.length();
        DKGSession {
            base_point: group::rand_element(),
            expected_contributors,
            deadline: timestamp::now_seconds() + INF,
            state: STATE__IN_PROGRESS,
            contributions: vector::range(0, num_players).map(|_| option::none()),
            contribution_still_needed: expected_contributors.length(),
            agg_public_point: group::group_identity(),
            culprits: vector[]
        }
    }

    public fun succeeded(dkg_session: &DKGSession): bool {
        dkg_session.state == STATE__SUCCEEDED
    }

    public fun failed(dkg_session: &DKGSession): bool {
        dkg_session.state == STATE__TIMED_OUT
    }

    public fun get_culprits(dkg_session: &DKGSession): vector<address> {
        dkg_session.culprits
    }

    public fun get_contributors(dkg_session: &DKGSession): vector<address> {
        assert!(dkg_session.state == STATE__SUCCEEDED, 191253);
        dkg_session.expected_contributors
    }

    /// Anyone can call this to trigger state transitions for the given DKG.
    public fun state_update(dkg_session: &mut DKGSession) {
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
    public fun process_contribution(
        contributor: &signer,
        session: &mut DKGSession,
        contribution: VerifiableContribution,
    ) {
        let contributor_addr = address_of(contributor);
        let (found, contributor_idx) = session.expected_contributors.index_of(&contributor_addr);
        assert!(found, 124130);

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

    public fun get_shared_secret_public_info(session: &DKGSession): SharedSecretPublicInfo {
        assert!(session.state == STATE__SUCCEEDED, 193709);
        let agg_ek = elgamal::make_enc_key(session.base_point, session.agg_public_point);
        let ek_shares = session.contributions.map_ref(|contri| {
            let contri: &Option<VerifiableContribution> = contri;
            let contribution = *contri.borrow();
            elgamal::make_enc_key(session.base_point, contribution.public_point)
        });
        SharedSecretPublicInfo { agg_ek, ek_shares }
    }

    public fun unpack_shared_secret_public_info(
        info: SharedSecretPublicInfo
    ): (EncKey, vector<EncKey>) {
        let SharedSecretPublicInfo { agg_ek, ek_shares } = info;
        (agg_ek, ek_shares)
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
    public fun generate_contribution(session: &DKGSession):
        (SecretShare, VerifiableContribution) {
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
        alice: &signer, bob: &signer, eric: &signer
    ): (SharedSecretPublicInfo, SecretShare, SecretShare, SecretShare) {
        let alice_addr = address_of(alice);
        let bob_addr = address_of(bob);
        let eric_addr = address_of(eric);
        let session = new_session(vector[alice_addr, bob_addr, eric_addr]);
        let (alice_secret_share, alice_contribution) = generate_contribution(&session);
        let (bob_secret_share, bob_contribution) = generate_contribution(&session);
        let (eric_secret_share, eric_contribution) = generate_contribution(&session);
        process_contribution(alice, &mut session, alice_contribution);
        process_contribution(bob, &mut session, bob_contribution);
        process_contribution(eric, &mut session, eric_contribution);
        state_update(&mut session);
        assert!(succeeded(&session), 999);
        let public_info = get_shared_secret_public_info(&session);
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
