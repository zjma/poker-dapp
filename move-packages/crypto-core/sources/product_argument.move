module crypto_core::product_argument {
    use std::vector;
    use crypto_core::pederson_commitment;
    use crypto_core::fiat_shamir_transform;
    use crypto_core::utils;
    use crypto_core::group;
    #[test_only]
    use aptos_framework::randomness;

    struct Proof has copy, drop, store {
        vec_d_cmt: group::Element,
        cmt_2: group::Element,
        cmt_3: group::Element,
        vec_a_tilde: vector<group::Scalar>,
        vec_b_tilde: vector<group::Scalar>,
        r_tilde: group::Scalar,
        s_tilde: group::Scalar
    }

    public fun dummy_proof(): Proof {
        Proof {
            vec_d_cmt: group::dummy_element(),
            cmt_2: group::dummy_element(),
            cmt_3: group::dummy_element(),
            vec_a_tilde: vector[],
            vec_b_tilde: vector[],
            r_tilde: group::dummy_scalar(),
            s_tilde: group::dummy_scalar()
        }
    }

    public fun decode_proof(buf: vector<u8>): (vector<u64>, Proof, vector<u8>) {
        let (errors, vec_d_cmt, buf) = group::decode_element(buf);
        if (!errors.is_empty()) {
            errors.push_back(211909);
            return (errors, dummy_proof(), buf);
        };
        let (errors, cmt_2, buf) = group::decode_element(buf);
        if (!errors.is_empty()) {
            errors.push_back(211910);
            return (errors, dummy_proof(), buf);
        };
        let (errors, cmt_3, buf) = group::decode_element(buf);
        if (!errors.is_empty()) {
            errors.push_back(211911);
            return (errors, dummy_proof(), buf);
        };
        let (errors, vec_a_tilde_len, buf) = utils::decode_uleb128(buf);
        if (!errors.is_empty()) {
            errors.push_back(211912);
            return (errors, dummy_proof(), buf);
        };

        let vec_a_tilde = vector[];
        let i = 0;
        while (i < vec_a_tilde_len) {
            let (errors, scalar, remainder) = group::decode_scalar(buf);
            if (!errors.is_empty()) {
                errors.push_back(i as u64);
                errors.push_back(211913);
                return (errors, dummy_proof(), buf);
            };
            buf = remainder;
            vec_a_tilde.push_back(scalar);
            i += 1;
        };

        let (errors, vec_b_tilde_len, buf) = utils::decode_uleb128(buf);
        if (!errors.is_empty()) {
            errors.push_back(211914);
            return (errors, dummy_proof(), buf);
        };

        let vec_b_tilde = vector[];
        let i = 0;
        while (i < vec_b_tilde_len) {
            let (errors, scalar, remainder) = group::decode_scalar(buf);
            if (!errors.is_empty()) {
                errors.push_back(i as u64);
                errors.push_back(211915);
                return (errors, dummy_proof(), buf);
            };
            buf = remainder;
            vec_b_tilde.push_back(scalar);
            i += 1;
        };

        let (errors, r_tilde, buf) = group::decode_scalar(buf);
        if (!errors.is_empty()) {
            errors.push_back(211916);
            return (errors, dummy_proof(), buf);
        };

        let (errors, s_tilde, buf) = group::decode_scalar(buf);
        if (!errors.is_empty()) {
            errors.push_back(211917);
            return (errors, dummy_proof(), buf);
        };

        let ret = Proof {
            vec_d_cmt,
            cmt_2,
            cmt_3,
            vec_a_tilde,
            vec_b_tilde,
            r_tilde,
            s_tilde
        };

        (vector[], ret, buf)
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// NOTE: client needs to implement this.
    public fun prove(
        pederson_ctxt: &pederson_commitment::Context,
        trx: &mut fiat_shamir_transform::Transcript,
        n: u64,
        _vec_a_cmt: &group::Element,
        _b: &group::Scalar,
        vec_a: &vector<group::Scalar>,
        r: &group::Scalar
    ): Proof {
        let vec_b = vector[vec_a[0]];
        let i = 1;
        while (i < n) {
            let new_item = group::scalar_mul(&vec_b[i - 1], vec_a.borrow(i));
            vec_b.push_back(new_item);
            i += 1;
        };

        let vec_d = vector::range(0, n).map(|_| group::rand_scalar());
        let r_d = group::rand_scalar();
        let vec_delta = vector[vec_d[0]];
        vec_delta.append(vector::range(1, n - 1).map(|_| group::rand_scalar()));
        vec_delta.push_back(group::scalar_from_u64(0));
        let s_1 = group::rand_scalar();
        let s_x = group::rand_scalar();
        let vec_d_cmt = pederson_commitment::vec_commit(pederson_ctxt, &r_d, &vec_d);
        let vec_2 = vector::range(0, n - 1).map(|i| {
            group::scalar_neg(
                &group::scalar_mul(&vec_d[i + 1], &vec_delta[i])
            )
        });
        let cmt_2 = pederson_commitment::vec_commit(pederson_ctxt, &s_1, &vec_2);
        let vec_3 = vector::range(0, n - 1).map(|i| {
            let tmp =
                group::scalar_add(
                    &group::scalar_mul(vec_a.borrow(i + 1), &vec_delta[i]),
                    &group::scalar_mul(&vec_b[i], &vec_d[i + 1])
                );
            group::scalar_sub(&vec_delta[i + 1], &tmp)
        });
        let cmt_3 = pederson_commitment::vec_commit(pederson_ctxt, &s_x, &vec_3);
        fiat_shamir_transform::append_group_element(trx, &vec_d_cmt);
        fiat_shamir_transform::append_group_element(trx, &cmt_2);
        fiat_shamir_transform::append_group_element(trx, &cmt_3);
        let x = fiat_shamir_transform::hash_to_scalar(trx);
        let vec_a_tilde = vector::range(0, n).map(|i| {
            group::scalar_add(
                &vec_d[i],
                &group::scalar_mul(&x, vec_a.borrow(i))
            )
        });
        let vec_b_tilde = vector::range(0, n).map(|i| {
            group::scalar_add(
                &vec_delta[i],
                &group::scalar_mul(&x, &vec_b[i])
            )
        });
        let r_tilde = group::scalar_add(&group::scalar_mul(&x, r), &r_d);
        let s_tilde = group::scalar_add(&group::scalar_mul(&x, &s_x), &s_1);

        Proof {
            vec_d_cmt,
            cmt_2,
            cmt_3,
            vec_a_tilde,
            vec_b_tilde,
            r_tilde,
            s_tilde
        }
    }

    public fun verify(
        pederson_ctxt: &pederson_commitment::Context,
        trx: &mut fiat_shamir_transform::Transcript,
        n: u64,
        vec_a_cmt: &group::Element,
        b: &group::Scalar,
        proof: &Proof
    ): bool {
        fiat_shamir_transform::append_group_element(trx, &proof.vec_d_cmt);
        fiat_shamir_transform::append_group_element(trx, &proof.cmt_2);
        fiat_shamir_transform::append_group_element(trx, &proof.cmt_3);
        let x = fiat_shamir_transform::hash_to_scalar(trx);

        if (group::element_add(&group::scale_element(vec_a_cmt, &x), &proof.vec_d_cmt)
            != pederson_commitment::vec_commit(
                pederson_ctxt, &proof.r_tilde, &proof.vec_a_tilde
            ))
            return false;

        let tmp_vec = vector::range(0, n - 1).map(|i| {
            group::scalar_sub(
                &group::scalar_mul(&x, &proof.vec_b_tilde[i + 1]),
                &group::scalar_mul(&proof.vec_b_tilde[i], &proof.vec_a_tilde[i + 1])
            )
        });

        if (group::element_add(&group::scale_element(&proof.cmt_3, &x), &proof.cmt_2)
            != pederson_commitment::vec_commit(pederson_ctxt, &proof.s_tilde, &tmp_vec))
            return false;

        if (proof.vec_a_tilde[0] != proof.vec_b_tilde[0])
            return false;
        if (proof.vec_b_tilde[n - 1] != group::scalar_mul(&x, b))
            return false;

        true
    }

    #[test(framework = @0x1)]
    fun completeness(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let n = 52;
        let pedersen_ctxt = pederson_commitment::rand_context(n);
        let r = group::rand_scalar();
        let vec_a = vector::range(0, n).map(|_| group::rand_scalar());

        let b = group::scalar_from_u64(1);
        vec_a.for_each_ref(|val| {
            b = group::scalar_mul(&b, val);
        });

        let vec_a_cmt = pederson_commitment::vec_commit(&pedersen_ctxt, &r, &vec_a);
        let trx_prover = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(
            &mut trx_prover, b"SOME_ARBITRARY_PREFIX"
        );
        let trx_verifier = trx_prover;
        let proof = prove(
            &pedersen_ctxt,
            &mut trx_prover,
            n,
            &vec_a_cmt,
            &b,
            &vec_a,
            &r
        );
        assert!(
            verify(
                &pedersen_ctxt,
                &mut trx_verifier,
                n,
                &vec_a_cmt,
                &b,
                &proof
            ),
            999
        );
    }
}
