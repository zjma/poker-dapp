module contract_owner::product_argument {
    use std::vector;
    use contract_owner::pederson_commitment;
    use contract_owner::fiat_shamir_transform;
    use contract_owner::utils;
    use contract_owner::group;
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
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 211909);
            return (errors, dummy_proof(), buf);
        };
        let (errors, cmt_2, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 211910);
            return (errors, dummy_proof(), buf);
        };
        let (errors, cmt_3, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 211911);
            return (errors, dummy_proof(), buf);
        };
        let (errors, vec_a_tilde_len, buf) = utils::decode_u64(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 211912);
            return (errors, dummy_proof(), buf);
        };

        let vec_a_tilde = vector[];
        let i = 0;
        while (i < vec_a_tilde_len) {
            let (errors, scalar, remainder) = group::decode_scalar(buf);
            if (!vector::is_empty(&errors)) {
                vector::push_back(&mut errors, i);
                vector::push_back(&mut errors, 211913);
                return (errors, dummy_proof(), buf);
            };
            buf = remainder;
            vector::push_back(&mut vec_a_tilde, scalar);
            i = i + 1;
        };

        let (errors, vec_b_tilde_len, buf) = utils::decode_u64(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 211914);
            return (errors, dummy_proof(), buf);
        };

        let vec_b_tilde = vector[];
        let i = 0;
        while (i < vec_b_tilde_len) {
            let (errors, scalar, remainder) = group::decode_scalar(buf);
            if (!vector::is_empty(&errors)) {
                vector::push_back(&mut errors, i);
                vector::push_back(&mut errors, 211915);
                return (errors, dummy_proof(), buf);
            };
            buf = remainder;
            vector::push_back(&mut vec_b_tilde, scalar);
            i = i + 1;
        };

        let (errors, r_tilde, buf) = group::decode_scalar(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 211916);
            return (errors, dummy_proof(), buf);
        };

        let (errors, s_tilde, buf) = group::decode_scalar(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 211917);
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

    public fun encode_proof(proof: &Proof): vector<u8> {
        let buf = group::encode_element(&proof.vec_d_cmt);
        vector::append(&mut buf, group::encode_element(&proof.cmt_2));
        vector::append(&mut buf, group::encode_element(&proof.cmt_3));
        let vec_a_tilde_len = vector::length(&proof.vec_a_tilde);
        vector::append(&mut buf, utils::encode_u64(vec_a_tilde_len));
        vector::for_each_ref(
            &proof.vec_a_tilde,
            |scalar| {
                vector::append(&mut buf, group::encode_scalar(scalar));
            }
        );
        let vec_b_tilde_len = vector::length(&proof.vec_b_tilde);
        vector::append(&mut buf, utils::encode_u64(vec_b_tilde_len));
        vector::for_each_ref(
            &proof.vec_b_tilde,
            |scalar| {
                vector::append(&mut buf, group::encode_scalar(scalar));
            }
        );
        vector::append(&mut buf, group::encode_scalar(&proof.r_tilde));
        vector::append(&mut buf, group::encode_scalar(&proof.s_tilde));
        buf
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    public fun prove(
        pederson_ctxt: &pederson_commitment::Context,
        trx: &mut fiat_shamir_transform::Transcript,
        n: u64,
        _vec_a_cmt: &group::Element,
        _b: &group::Scalar,
        vec_a: &vector<group::Scalar>,
        r: &group::Scalar
    ): Proof {
        let vec_b = vector[*vector::borrow(vec_a, 0)];
        let i = 1;
        while (i < n) {
            let new_item = group::scalar_mul(&vec_b[i - 1], vector::borrow(vec_a, i));
            vector::push_back(&mut vec_b, new_item);
            i = i + 1;
        };

        let vec_d = vector::map(vector::range(0, n), |_| group::rand_scalar());
        let r_d = group::rand_scalar();
        let vec_delta = vector[vec_d[0]];
        vector::append(
            &mut vec_delta,
            vector::map(
                vector::range(1, n - 1),
                |_| group::rand_scalar()
            )
        );
        vector::push_back(&mut vec_delta, group::scalar_from_u64(0));
        let s_1 = group::rand_scalar();
        let s_x = group::rand_scalar();
        let vec_d_cmt = pederson_commitment::vec_commit(pederson_ctxt, &r_d, &vec_d);
        let vec_2 = vector::map(
            vector::range(0, n - 1),
            |i| {
                group::scalar_neg(
                    &group::scalar_mul(&vec_d[i + 1], &vec_delta[i])
                )
            }
        );
        let cmt_2 = pederson_commitment::vec_commit(pederson_ctxt, &s_1, &vec_2);
        let vec_3 = vector::map(
            vector::range(0, n - 1),
            |i| {
                let tmp =
                    group::scalar_add(
                        &group::scalar_mul(vector::borrow(vec_a, i + 1), &vec_delta[i]),
                        &group::scalar_mul(&vec_b[i], &vec_d[i + 1])
                    );
                group::scalar_sub(&vec_delta[i + 1], &tmp)
            }
        );
        let cmt_3 = pederson_commitment::vec_commit(pederson_ctxt, &s_x, &vec_3);
        fiat_shamir_transform::append_group_element(trx, &vec_d_cmt);
        fiat_shamir_transform::append_group_element(trx, &cmt_2);
        fiat_shamir_transform::append_group_element(trx, &cmt_3);
        let x = fiat_shamir_transform::hash_to_scalar(trx);
        let vec_a_tilde = vector::map(
            vector::range(0, n),
            |i| {
                group::scalar_add(
                    &vec_d[i],
                    &group::scalar_mul(&x, vector::borrow(vec_a, i))
                )
            }
        );
        let vec_b_tilde = vector::map(
            vector::range(0, n),
            |i| {
                group::scalar_add(
                    &vec_delta[i],
                    &group::scalar_mul(&x, &vec_b[i])
                )
            }
        );
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

        let tmp_vec = vector::map(
            vector::range(0, n - 1),
            |i| {
                group::scalar_sub(
                    &group::scalar_mul(&x, &proof.vec_b_tilde[i + 1]),
                    &group::scalar_mul(&proof.vec_b_tilde[i], &proof.vec_a_tilde[i + 1])
                )
            }
        );

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
        let vec_a = vector::map(vector::range(0, n), |_| group::rand_scalar());

        let b = group::scalar_from_u64(1);
        vector::for_each_ref(&vec_a, |val| {
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
