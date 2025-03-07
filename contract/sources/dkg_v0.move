module contract_owner::dkg_v0 {
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::string;
    use std::vector;
    use aptos_std::type_info;
    use contract_owner::encryption;
    use contract_owner::group;

    struct DKGSession has copy, drop, store {
        base_point: group::Element,
        expected_contributors: vector<address>,
        contributions: vector<Option<Contribution>>,
        contribution_still_needed: u64,
        agg_public_point: group::Element,
    }

    struct Contribution has copy, drop, store {
        public_point: group::Element,
    }

    public fun dummy_session(): DKGSession {
        DKGSession {
            base_point: group::group_identity(),
            expected_contributors: vector[],
            contributions: vector[],
            contribution_still_needed: 0,
            agg_public_point: group::group_identity(),
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
            contributions: vector::map(vector::range(0, num_players), |_|option::none()),
            contribution_still_needed: vector::length(&expected_contributors),
            agg_public_point: group::group_identity(),
        }
    }

    const DKG_STILL_IN_PROGRESS: u64 = 0;
    const DKG_FINISHED: u64 = 1;
    const DKG_ABORTED: u64 = 2;

    public fun apply_contribution(contributor: &signer, session: &mut DKGSession, contribution: Contribution, proof: ContributionProof): (vector<u64>, u64) {
        //TODO: verify contribution
        let contributor_addr = address_of(contributor);
        let (found, contributor_idx) = vector::index_of(&session.expected_contributors, &contributor_addr);
        if (!found) return (vector[124130], DKG_STILL_IN_PROGRESS);
        {
            let contribution_slot = vector::borrow_mut(&mut session.contributions, contributor_idx);
            if (option::is_some(contribution_slot)) return (vector[124134], DKG_STILL_IN_PROGRESS);
            option::fill(contribution_slot, contribution);
        };
        session.contribution_still_needed = session.contribution_still_needed - 1;
        if (session.contribution_still_needed == 0) {
            vector::for_each_ref(&session.contributions, |contri|{
                let contribution = *option::borrow(contri);
                group::element_add_assign(&mut session.agg_public_point, &contribution.public_point);
            });
            (vector[], 1)
        } else {
            (vector[], 0)
        }

    }

    public fun get_ek_and_shares(session: &DKGSession): (encryption::EncKey, vector<encryption::EncKey>) {
        let ek = encryption::make_enc_key(session.base_point, session.agg_public_point);
        let ek_shares = vector::map_ref(&session.contributions, |contri|{
            let contribution = *option::borrow(contri);
            encryption::make_enc_key(session.base_point, contribution.public_point)
        });
        (ek, ek_shares)
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