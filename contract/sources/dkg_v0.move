/// A naive DKG.
/// - A group of participants use the blockchain as the broadcast channel and collborate to generate a secret `s`.
/// - No one knows `s`.
/// - Every participant gets a secret share which they need to keep private.
/// - If someone sees all the secret shares, they can reconstruct `s`.
/// - For any group element `P`, the group can collaborate to reveal `s*P` without leaking any information about `s`.
///   - See more details in `threshold_scalar_mul.move`.
module contract_owner::dkg_v0 {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::vector;
    use aptos_framework::timestamp;
    use contract_owner::sigma_dlog;
    use contract_owner::elgamal::EncKey;
    use contract_owner::elgamal;
    use contract_owner::group;
    #[test_only]
    use contract_owner::fiat_shamir_transform;

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
        culprits: vector<address>
    }

    struct VerifiableContribution has copy, drop, store {
        public_point: group::Element,
        proof: sigma_dlog::Proof
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
            proof: sigma_dlog::dummy_proof()
        }
    }

    public fun dummy_secret_info(): SharedSecretPublicInfo {
        SharedSecretPublicInfo {
            agg_ek: elgamal::dummy_enc_key(),
            ek_shares: vector[]
        }
    }

    public fun decode_contribution(
        buf: vector<u8>
    ): (vector<u64>, VerifiableContribution, vector<u8>) {
        let (errors, public_point, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 132607);
            return (errors, dummy_contribution(), buf);
        };
        let (errors, proof, buf) = sigma_dlog::decode_proof(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 132608);
            return (errors, dummy_contribution(), buf);
        };
        let ret = VerifiableContribution { public_point, proof };
        (vector[], ret, buf)
    }

    public fun encode_contribution(obj: &VerifiableContribution): vector<u8> {
        let buf = vector[];
        vector::append(&mut buf, group::encode_element(&obj.public_point));
        vector::append(&mut buf, sigma_dlog::encode_proof(&obj.proof));
        buf
    }

    #[lint::allow_unsafe_randomness]
    public fun new_session(expected_contributors: vector<address>): DKGSession {
        let num_players = vector::length(&expected_contributors);
        DKGSession {
            base_point: group::rand_element(),
            expected_contributors,
            deadline: timestamp::now_seconds() + 10,
            state: STATE__IN_PROGRESS,
            contributions: vector::map(
                vector::range(0, num_players),
                |_| option::none()
            ),
            contribution_still_needed: vector::length(&expected_contributors),
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
                vector::for_each_ref(
                    &dkg_session.contributions,
                    |contri| {
                        let contribution = *option::borrow(contri);
                        group::element_add_assign(
                            &mut dkg_session.agg_public_point,
                            &contribution.public_point
                        );
                    }
                );
                dkg_session.state = STATE__SUCCEEDED;
            } else if (timestamp::now_seconds() >= dkg_session.deadline) {
                let n = vector::length(&dkg_session.expected_contributors);
                let culprit_idxs = vector::filter(
                    vector::range(0, n),
                    |idx| {
                        option::is_none(&dkg_session.contributions[*idx])
                    }
                );
                let culprits = vector::map(
                    culprit_idxs, |idx| dkg_session.expected_contributors[idx]
                );
                dkg_session.state = STATE__TIMED_OUT;
                dkg_session.culprits = culprits;
            }
        }
    }

    public fun process_contribution(
        contributor: &signer,
        session: &mut DKGSession,
        contribution: VerifiableContribution
    ) {
        //TODO: verify contribution
        let contributor_addr = address_of(contributor);
        let (found, contributor_idx) = vector::index_of(
            &session.expected_contributors, &contributor_addr
        );
        assert!(found, 124130);
        session.contribution_still_needed = session.contribution_still_needed - 1;
        option::fill(&mut session.contributions[contributor_idx], contribution);
    }

    public fun get_shared_secret_public_info(session: &DKGSession): SharedSecretPublicInfo {
        assert!(session.state == STATE__SUCCEEDED, 193709);
        let agg_ek = elgamal::make_enc_key(session.base_point, session.agg_public_point);
        let ek_shares = vector::map_ref(
            &session.contributions,
            |contri| {
                let contribution = *option::borrow(contri);
                elgamal::make_enc_key(session.base_point, contribution.public_point)
            }
        );
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
        vector::length(&secret_info.ek_shares)
    }

    /// Given the shares of a threshold scalar multiplication,compute the scalar-mul result.
    /// Assume that any given share is valid and the number of shares given is greater than or equal to the threshold.
    public fun aggregate_scalar_mul(
        _secret_info: &SharedSecretPublicInfo, shares: vector<Option<group::Element>>
    ): group::Element {
        let ret = group::group_identity();
        vector::for_each(
            shares,
            |share| {
                group::element_add_assign(&mut ret, &option::extract(&mut share));
            }
        );
        ret
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// Client needs to implement this.
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
        let contribution = VerifiableContribution { public_point, proof };
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
        let n = vector::length(&public_info.ek_shares);
        assert!(n == vector::length(&shares), 162205);
        let agg = group::scalar_from_u64(0);
        vector::for_each(
            shares,
            |share| {
                let share = option::extract(&mut share);
                let s = unpack_secret_share(share);
                agg = group::scalar_add(&agg, &s);
            }
        );
        agg
    }
}
