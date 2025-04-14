module contract_owner::multiexp_argument {
    use std::vector;
    use contract_owner::fiat_shamir_transform;
    use contract_owner::pederson_commitment;
    use contract_owner::utils;
    use contract_owner::elgamal;
    use contract_owner::group;
    #[test_only]
    use aptos_framework::randomness;

    struct Proof has copy, drop, store {
        cmt_a0: group::Element,
        b_cmt_0: group::Element,
        b_cmt_1: group::Element,
        e_0: elgamal::Ciphertext,
        e_1: elgamal::Ciphertext,
        a_vec: vector<group::Scalar>,
        r: group::Scalar,
        b: group::Scalar,
        s: group::Scalar,
        tau: group::Scalar
    }

    public fun dummy_proof(): Proof {
        Proof {
            cmt_a0: group::dummy_element(),
            b_cmt_0: group::dummy_element(),
            b_cmt_1: group::dummy_element(),
            e_0: elgamal::dummy_ciphertext(),
            e_1: elgamal::dummy_ciphertext(),
            a_vec: vector[],
            r: group::dummy_scalar(),
            b: group::dummy_scalar(),
            s: group::dummy_scalar(),
            tau: group::dummy_scalar()
        }
    }

    public fun decode_proof(buf: vector<u8>): (vector<u64>, Proof, vector<u8>) {
        let (errors, cmt_a0, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 243333);
            return (errors, dummy_proof(), buf);
        };

        let (errors, b_cmt_0, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 243334);
            return (errors, dummy_proof(), buf);
        };

        let (errors, b_cmt_1, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 243335);
            return (errors, dummy_proof(), buf);
        };

        let (errors, e_0, buf) = elgamal::decode_ciphertext(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 243336);
            return (errors, dummy_proof(), buf);
        };

        let (errors, e_1, buf) = elgamal::decode_ciphertext(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 243337);
            return (errors, dummy_proof(), buf);
        };

        let (errors, a_vec_len, buf) = utils::decode_u64(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 243338);
            return (errors, dummy_proof(), buf);
        };

        let a_vec = vector[];
        let i = 0;
        while (i < a_vec_len) {
            let (errors, scalar, remainder) = group::decode_scalar(buf);
            if (!vector::is_empty(&errors)) {
                vector::push_back(&mut errors, i);
                vector::push_back(&mut errors, 243339);
                return (errors, dummy_proof(), buf);
            };
            buf = remainder;
            vector::push_back(&mut a_vec, scalar);
            i = i + 1;
        };

        let (errors, r, buf) = group::decode_scalar(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 243340);
            return (errors, dummy_proof(), buf);
        };

        let (errors, b, buf) = group::decode_scalar(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 243341);
            return (errors, dummy_proof(), buf);
        };

        let (errors, s, buf) = group::decode_scalar(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 243342);
            return (errors, dummy_proof(), buf);
        };

        let (errors, tau, buf) = group::decode_scalar(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 243343);
            return (errors, dummy_proof(), buf);
        };

        let ret = Proof { cmt_a0, b_cmt_0, b_cmt_1, e_0, e_1, a_vec, r, b, s, tau };

        (vector[], ret, buf)
    }

    public fun encode_proof(proof: &Proof): vector<u8> {
        let buf = group::encode_element(&proof.cmt_a0);
        vector::append(&mut buf, group::encode_element(&proof.b_cmt_0));
        vector::append(&mut buf, group::encode_element(&proof.b_cmt_1));
        vector::append(&mut buf, elgamal::encode_ciphertext(&proof.e_0));
        vector::append(&mut buf, elgamal::encode_ciphertext(&proof.e_1));
        let a_vec_len = vector::length(&proof.a_vec);
        vector::append(&mut buf, utils::encode_u64(a_vec_len));
        vector::for_each_ref(
            &proof.a_vec,
            |val| {
                vector::append(&mut buf, group::encode_scalar(val));
            }
        );
        vector::append(&mut buf, group::encode_scalar(&proof.r));
        vector::append(&mut buf, group::encode_scalar(&proof.b));
        vector::append(&mut buf, group::encode_scalar(&proof.s));
        vector::append(&mut buf, group::encode_scalar(&proof.tau));
        buf
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// NOTE: client needs to implement this.
    public fun prove(
        ek: &elgamal::EncKey,
        pedersen_ctxt: &pederson_commitment::Context,
        trx: &mut fiat_shamir_transform::Transcript,
        vec_c: &vector<elgamal::Ciphertext>,
        c: &elgamal::Ciphertext,
        vec_a_cmt: &group::Element,
        vec_a: &vector<group::Scalar>,
        r: &group::Scalar,
        rho: &group::Scalar
    ): Proof {
        let (enc_base, _) = elgamal::unpack_enc_key(*ek);
        let n = vector::length(vec_a);
        let vec_a_0 = vector::map(vector::range(0, n), |_| group::rand_scalar());
        let r_0 = group::rand_scalar();
        let b_vec = vector[group::rand_scalar(), group::scalar_from_u64(0)];
        let s_vec = vector[group::rand_scalar(), group::scalar_from_u64(0)];
        let tau_vec = vector[group::rand_scalar(), *rho];
        let vec_a_0_cmt = pederson_commitment::vec_commit(pedersen_ctxt, &r_0, &vec_a_0);
        let b_cmt_vec = vector::map(
            vector::range(0, 2),
            |k| pederson_commitment::vec_commit(
                pedersen_ctxt, &s_vec[k], &vector[b_vec[k]]
            )
        );
        let e_vec = vector::map(
            vector::range(0, 2),
            |k| {
                let msg = group::scale_element(&enc_base, &b_vec[k]);
                let chunk0 = elgamal::enc(ek, &tau_vec[k], &msg);
                let chunk1 =
                    if (k == 0) {
                        elgamal::weird_multi_exp(vec_c, &vec_a_0)
                    } else {
                        elgamal::weird_multi_exp(vec_c, vec_a)
                    };
                elgamal::ciphertext_add(&chunk0, &chunk1)
            }
        );
        fiat_shamir_transform::append_group_element(trx, &vec_a_0_cmt);
        fiat_shamir_transform::append_group_element(trx, &b_cmt_vec[0]);
        fiat_shamir_transform::append_raw_bytes(
            trx, elgamal::encode_ciphertext(&e_vec[0])
        );
        fiat_shamir_transform::append_group_element(trx, &b_cmt_vec[1]);
        fiat_shamir_transform::append_raw_bytes(
            trx, elgamal::encode_ciphertext(&e_vec[1])
        );

        let x = fiat_shamir_transform::hash_to_scalar(trx);
        let a_out_vec = vector::map(
            vector::range(0, n),
            |i| {
                group::scalar_add(
                    &vec_a_0[i],
                    &group::scalar_mul(vector::borrow(vec_a, i), &x)
                )
            }
        );

        let r_out = group::scalar_add(&r_0, &group::scalar_mul(r, &x));
        let b_out = group::scalar_add(&b_vec[0], &group::scalar_mul(&b_vec[1], &x));
        let s_out = group::scalar_add(&s_vec[0], &group::scalar_mul(&s_vec[1], &x));
        let tau_out = group::scalar_add(
            &tau_vec[0],
            &group::scalar_mul(&tau_vec[1], &x)
        );
        Proof {
            cmt_a0: vec_a_0_cmt,
            b_cmt_0: b_cmt_vec[0],
            b_cmt_1: b_cmt_vec[1],
            e_0: e_vec[0],
            e_1: e_vec[1],
            a_vec: a_out_vec,
            r: r_out,
            b: b_out,
            s: s_out,
            tau: tau_out
        }
    }

    public fun verify(
        ek: &elgamal::EncKey,
        pedersen_ctxt: &pederson_commitment::Context,
        trx: &mut fiat_shamir_transform::Transcript,
        vec_c: &vector<elgamal::Ciphertext>,
        c: &elgamal::Ciphertext,
        vec_a_cmt: &group::Element,
        proof: &Proof
    ): bool {
        let (enc_base, _) = elgamal::unpack_enc_key(*ek);
        let b_0_cmt_expected =
            pederson_commitment::vec_commit(
                pedersen_ctxt, &group::scalar_from_u64(0), &vector[]
            );
        fiat_shamir_transform::append_group_element(trx, &proof.cmt_a0);
        fiat_shamir_transform::append_group_element(trx, &proof.b_cmt_0);
        fiat_shamir_transform::append_raw_bytes(
            trx, elgamal::encode_ciphertext(&proof.e_0)
        );
        fiat_shamir_transform::append_group_element(trx, &proof.b_cmt_1);
        fiat_shamir_transform::append_raw_bytes(
            trx, elgamal::encode_ciphertext(&proof.e_1)
        );
        let x = fiat_shamir_transform::hash_to_scalar(trx);

        if (b_0_cmt_expected != proof.b_cmt_1) return false;

        if (group::element_add(&proof.cmt_a0, &group::scale_element(vec_a_cmt, &x))
            != pederson_commitment::vec_commit(pedersen_ctxt, &proof.r, &proof.a_vec))
            return false;

        if (group::element_add(
            &proof.b_cmt_0, &group::scale_element(&proof.b_cmt_1, &x)
        ) != pederson_commitment::vec_commit(pedersen_ctxt, &proof.s, &vector[proof.b]))
            return false;

        if (elgamal::ciphertext_add(
            &proof.e_0, &elgamal::ciphertext_mul(&proof.e_1, &x)
        ) != elgamal::ciphertext_add(
            &elgamal::enc(
                ek,
                &proof.tau,
                &group::scale_element(&enc_base, &proof.b)
            ),
            &elgamal::weird_multi_exp(vec_c, &proof.a_vec)
        ))
            return false;

        if (*c != proof.e_1) return false;

        true
    }

    #[test(framework = @0x1)]
    fun completeness(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let n = 52;
        let pedersen_ctxt = pederson_commitment::rand_context(n);
        let elgamal_base = group::rand_element();
        let (_dk, ek) = elgamal::key_gen(elgamal_base);
        let r = group::rand_scalar();
        let vec_a = vector::map(vector::range(0, n), |_| group::rand_scalar());
        let vec_a_cmt = pederson_commitment::vec_commit(&pedersen_ctxt, &r, &vec_a);
        let rho = group::rand_scalar();
        let vec_c = vector::map(
            vector::range(0, n),
            |_| {
                let randomizer = group::rand_scalar();
                let rand_msg = group::rand_element();
                elgamal::enc(&ek, &randomizer, &rand_msg)
            }
        );
        let c =
            elgamal::ciphertext_add(
                &elgamal::enc(&ek, &rho, &group::group_identity()),
                &elgamal::weird_multi_exp(&vec_c, &vec_a)
            );
        let trx_prover = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut trx_prover, b"SOME_RANDOM_PREFIX");
        let trx_verifier = trx_prover;
        let proof =
            prove(
                &ek,
                &pedersen_ctxt,
                &mut trx_prover,
                &vec_c,
                &c,
                &vec_a_cmt,
                &vec_a,
                &r,
                &rho
            );
        assert!(
            verify(
                &ek,
                &pedersen_ctxt,
                &mut trx_verifier,
                &vec_c,
                &c,
                &vec_a_cmt,
                &proof
            ),
            999
        );
    }
}
