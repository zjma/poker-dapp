/// Protocol to prove knowledge of scalar `s` such that `s*B0==P0, s*B1==P1` for public elements `B0, B1, P0, P1`.
module contract_owner::sigma_dlog_eq {
    use std::string;
    use std::vector;
    use aptos_std::type_info;
    use contract_owner::fiat_shamir_transform;
    use contract_owner::group;
    #[test_only]
    use aptos_framework::randomness;

    struct Proof has copy, drop, store {
        t0: group::Element,
        t1: group::Element,
        s: group::Scalar,
    }

    public fun dummy_proof(): Proof {
        Proof {
            t0: group::dummy_element(),
            t1: group::dummy_element(),
            s: group::dummy_scalar(),
        }
    }

    public fun encode_proof(proof: &Proof): vector<u8> {
        let buf = *string::bytes(&type_info::type_name<Proof>());
        vector::append(&mut buf, group::encode_element(&proof.t0));
        vector::append(&mut buf, group::encode_element(&proof.t1));
        vector::append(&mut buf, group::encode_scalar(&proof.s));
        buf
    }

    public fun decode_proof(buf: vector<u8>): (vector<u64>, Proof, vector<u8>) {
        let buf_len = vector::length(&buf);
        let header = *string::bytes(&type_info::type_name<Proof>());
        let header_len = vector::length(&header);
        if (buf_len < header_len) return (vector[125703], dummy_proof(), buf);
        if (header != vector::slice(&buf, 0, header_len)) return (vector[125704], dummy_proof(), buf);
        let buf = vector::slice(&buf, header_len, buf_len);
        let (errors, t0, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 125705);
            return (errors, dummy_proof(), buf);
        };
        let (errors, t1, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 125706);
            return (errors, dummy_proof(), buf);
        };
        let (errors, s, buf) = group::decode_scalar(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 125707);
            return (errors, dummy_proof(), buf);
        };
        let ret = Proof { t0, t1, s};
        (vector[], ret, buf)
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    public fun prove(
        trx: &mut fiat_shamir_transform::Transcript,
        b0: &group::Element, p0: &group::Element, b1: &group::Element, p1: &group::Element, // statement
        s: &group::Scalar // witness
    ): Proof {
        fiat_shamir_transform::append_group_element(trx, b0);
        fiat_shamir_transform::append_group_element(trx, p0);
        fiat_shamir_transform::append_group_element(trx, b1);
        fiat_shamir_transform::append_group_element(trx, p1);
        let r = group::rand_scalar();
        let t0 = group::scale_element(b0, &r);
        let t1 = group::scale_element(b1, &r);
        fiat_shamir_transform::append_group_element(trx, &t0);
        fiat_shamir_transform::append_group_element(trx, &t1);
        let c = fiat_shamir_transform::hash_to_scalar(trx);
        let s = group::scalar_add(&r, &group::scalar_mul(&c, s));
        Proof { t0, t1, s }
    }

    public fun verify(
        trx: &mut fiat_shamir_transform::Transcript,
        b0: &group::Element, p0: &group::Element, b1: &group::Element, p1: &group::Element, // statement
        proof: &Proof
    ): bool {
        fiat_shamir_transform::append_group_element(trx, b0);
        fiat_shamir_transform::append_group_element(trx, p0);
        fiat_shamir_transform::append_group_element(trx, b1);
        fiat_shamir_transform::append_group_element(trx, p1);
        fiat_shamir_transform::append_group_element(trx, &proof.t0);
        fiat_shamir_transform::append_group_element(trx, &proof.t1);
        let c = fiat_shamir_transform::hash_to_scalar(trx);
        let ret = true;
        ret = ret && group::scale_element(b0, &proof.s) == group::element_add(&proof.t0, &group::scale_element(p0, &c));
        ret = ret && group::scale_element(b1, &proof.s) == group::element_add(&proof.t1, &group::scale_element(p1, &c));
        ret
    }

    #[test(framework = @0x1)]
    fun general(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let s = group::rand_scalar();
        let b0 = group::rand_element();
        let b1 = group::rand_element();
        let p0 = group::scale_element(&b0, &s);
        let p1 = group::scale_element(&b1, &s);
        let prover_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut prover_trx, b"SHARED_PREFIX");
        let proof = prove(&mut prover_trx, &b0, &p0, &b1, &p1, &s);

        let verifier_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut verifier_trx, b"SHARED_PREFIX");
        assert!(verify(&mut verifier_trx, &b0, &p0, &b1, &p1, &proof), 999);
    }
}
