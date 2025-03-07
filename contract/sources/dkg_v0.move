module contract_owner::dkg_v0 {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::string;
    use std::vector;
    use aptos_std::type_info;
    use aptos_framework::timestamp;
    use contract_owner::encryption::EncKey;
    use contract_owner::encryption;
    use contract_owner::group;

    const STATE__IN_PROGRESS: u64 = 0;
    const STATE__SUCCEEDED: u64 = 1;
    const STATE__TIMED_OUT: u64 = 2;

    struct DKGSession has copy, drop, store {
        base_point: group::Element,
        expected_contributors: vector<address>,
        deadline: u64,
        state: u64,
        contributions: vector<Option<Contribution>>,
        contribution_still_needed: u64,
        agg_public_point: group::Element,
        culprits: vector<address>,
    }

    struct Contribution has copy, drop, store {
        public_point: group::Element,
    }

    struct SharedSecretPublicInfo has drop {
        agg_ek: encryption::EncKey,
        ek_shares: vector<encryption::EncKey>,
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
            culprits: vector[],
        }
    }

    public fun default_contribution(): Contribution {
        Contribution {
            public_point: group::dummy_element(),
        }
    }

    public fun decode_contribution(buf: vector<u8>): (vector<u64>, Contribution, vector<u8>) {
        let buf_len = vector::length(&buf);
        let header = *string::bytes(&type_info::type_name<Contribution>());
        let header_len = vector::length(&header);
        if (buf_len < header_len) {
            return (vector[134540], default_contribution(), buf);
        };
        if (header != vector::slice(&buf, 0, header_len)) {
            return (vector[134716], default_contribution(), buf);
        };
        let buf = vector::slice(&buf, header_len, buf_len);
        let (errors, element, remainder) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 132607);
            (errors, Contribution { public_point: group::group_identity()}, remainder)
        } else {
            (vector[], Contribution{ public_point: element }, remainder)
        }
    }

    public fun encode_contribution(obj: &Contribution): vector<u8> {
        let buf = *string::bytes(&type_info::type_name<Contribution>());
        vector::append(&mut buf, group::encode_element(&obj.public_point));
        buf
    }
    struct ContributionProof has drop {
        //TODO
    }

    public fun dummy_proof(): ContributionProof {
        ContributionProof {}
    }

    public fun decode_proof(buf: vector<u8>): (vector<u64>, ContributionProof, vector<u8>) {
        let buf_len = vector::length(&buf);
        let header = *string::bytes(&type_info::type_name<ContributionProof>());
        let header_len = vector::length(&header);
        if (buf_len < header_len) return (vector[121413], dummy_proof(), buf);
        if (header != vector::slice(&buf, 0, header_len)) return (vector[121414], dummy_proof(), buf);
        let buf = vector::slice(&buf, header_len, buf_len);
        (vector[], ContributionProof {}, buf)
    }

    public fun encode_proof(_obj: &ContributionProof): vector<u8> {
        let buf = *string::bytes(&type_info::type_name<ContributionProof>());
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
            contributions: vector::map(vector::range(0, num_players), |_|option::none()),
            contribution_still_needed: vector::length(&expected_contributors),
            agg_public_point: group::group_identity(),
            culprits: vector[],
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
                vector::for_each_ref(&dkg_session.contributions, |contri|{
                    let contribution = *option::borrow(contri);
                    group::element_add_assign(&mut dkg_session.agg_public_point, &contribution.public_point);
                });
                dkg_session.state = STATE__SUCCEEDED;
            } else if (timestamp::now_seconds() >= dkg_session.deadline) {
                let n = vector::length(&dkg_session.expected_contributors);
                let culprit_idxs = vector::filter(vector::range(0, n), |idx|{
                    let contribution_slot = vector::borrow(&dkg_session.contributions, *idx);
                    option::is_none(contribution_slot)
                });
                let culprits = vector::map(culprit_idxs, |idx| *vector::borrow(&dkg_session.expected_contributors, idx));
                dkg_session.state = STATE__TIMED_OUT;
                dkg_session.culprits = culprits;
            }
        }
    }

    public fun apply_contribution(contributor: &signer, session: &mut DKGSession, contribution: Contribution, proof: ContributionProof) {
        //TODO: verify contribution
        let contributor_addr = address_of(contributor);
        let (found, contributor_idx) = vector::index_of(&session.expected_contributors, &contributor_addr);
        assert!(found, 124130);
        session.contribution_still_needed = session.contribution_still_needed - 1;
        let contribution_slot = vector::borrow_mut(&mut session.contributions, contributor_idx);
        option::fill(contribution_slot, contribution);
    }

    public fun get_shared_secret_public_info(session: &DKGSession): SharedSecretPublicInfo {
        assert!(session.state == STATE__SUCCEEDED, 193709);
        let agg_ek = encryption::make_enc_key(session.base_point, session.agg_public_point);
        let ek_shares = vector::map_ref(&session.contributions, |contri|{
            let contribution = *option::borrow(contri);
            encryption::make_enc_key(session.base_point, contribution.public_point)
        });
        SharedSecretPublicInfo {
            agg_ek,
            ek_shares,
        }
    }

    public fun unpack_shared_secret_public_info(info: SharedSecretPublicInfo): (EncKey, vector<EncKey>) {
        let SharedSecretPublicInfo { agg_ek, ek_shares } = info;
        (agg_ek, ek_shares)
    }
    #[lint::allow_unsafe_randomness]
    #[test_only]
    public fun generate_contribution(session: &DKGSession): (Contribution, ContributionProof) {
        let private_scalar = group::rand_scalar();
        let public_point = group::scalar_mul(&session.base_point, &private_scalar);
        let contribution = Contribution { public_point };
        let proof = ContributionProof {};
        (contribution, proof)
    }
}
