module crypto_core::bg12 {
    use std::vector;
    use crypto_core::fiat_shamir_transform;
    use crypto_core::pederson_commitment;
    use crypto_core::elgamal;
    use crypto_core::product_argument;
    use crypto_core::multiexp_argument;
    use crypto_core::group;
    #[test_only]
    use aptos_framework::randomness;

    struct Proof has copy, drop, store {
        vec_a_cmt: group::Element,
        vec_b_cmt: group::Element,
        multiexp_proof: multiexp_argument::Proof,
        product_proof: product_argument::Proof
    }

    public fun dummy_proof(): Proof {
        Proof {
            vec_a_cmt: group::dummy_element(),
            vec_b_cmt: group::dummy_element(),
            multiexp_proof: multiexp_argument::dummy_proof(),
            product_proof: product_argument::dummy_proof()
        }
    }

    public fun decode_proof(buf: vector<u8>): (vector<u64>, Proof, vector<u8>) {
        let (errors, vec_a_cmt, buf) = group::decode_element(buf);
        if (!errors.is_empty()) {
            errors.push_back(995237);
            return (errors, dummy_proof(), buf);
        };
        let (errors, vec_b_cmt, buf) = group::decode_element(buf);
        if (!errors.is_empty()) {
            errors.push_back(995238);
            return (errors, dummy_proof(), buf);
        };
        let (errors, multiexp_proof, buf) = multiexp_argument::decode_proof(buf);
        if (!errors.is_empty()) {
            errors.push_back(995239);
            return (errors, dummy_proof(), buf);
        };
        let (errors, product_proof, buf) = product_argument::decode_proof(buf);
        if (!errors.is_empty()) {
            errors.push_back(995240);
            return (errors, dummy_proof(), buf);
        };
        let ret = Proof { vec_a_cmt, vec_b_cmt, multiexp_proof, product_proof };
        (vector[], ret, buf)
    }

    /// NOTE: client needs to implement this.
    public fun encode_proof(proof: &Proof): vector<u8> {
        let buf = vector[];
        buf.append(group::encode_element(&proof.vec_a_cmt));
        buf.append(group::encode_element(&proof.vec_b_cmt));
        buf.append(multiexp_argument::encode_proof(&proof.multiexp_proof));
        buf.append(product_argument::encode_proof(&proof.product_proof));
        buf
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// NOTE: client needs to implement this.
    public fun prove(
        ek: &elgamal::EncKey,
        pedersen_ctxt: &pederson_commitment::Context,
        trx: &mut fiat_shamir_transform::Transcript,
        original: &vector<elgamal::Ciphertext>,
        shuffled: &vector<elgamal::Ciphertext>,
        permutation: vector<u64>,
        vec_rho: &vector<group::Scalar>
    ): Proof {
        let n = original.length();
        let vec_a = permutation.map(|v| group::scalar_from_u64(v + 1));
        let r = group::rand_scalar();
        let vec_a_cmt = pederson_commitment::vec_commit(pedersen_ctxt, &r, &vec_a);
        fiat_shamir_transform::append_group_element(trx, &vec_a_cmt);
        let x = fiat_shamir_transform::hash_to_scalar(trx);
        let x_powers = powers_of_x(&x, n);
        let vec_b = vector::range(0, n).map(|i| x_powers[permutation[i]]);
        let s = group::rand_scalar();
        let vec_b_cmt = pederson_commitment::vec_commit(pedersen_ctxt, &s, &vec_b);
        fiat_shamir_transform::append_group_element(trx, &vec_b_cmt);
        let y = fiat_shamir_transform::hash_to_scalar(trx);
        fiat_shamir_transform::append_raw_bytes(trx, b"NUDGE");
        let z = fiat_shamir_transform::hash_to_scalar(trx);
        let neg_z = group::scalar_neg(&z);
        let vec_neg_z = vector::range(0, n).map(|_| neg_z);
        let vec_neg_z_cmt =
            pederson_commitment::vec_commit(
                pedersen_ctxt, &group::scalar_from_u64(0), &vec_neg_z
            );
        let vec_d_cmt =
            group::element_add(
                &group::scale_element(&vec_a_cmt, &y),
                &vec_b_cmt
            );
        let vec_d = vector::range(0, n).map(|i| {
            group::scalar_add(&group::scalar_mul(&y, &vec_a[i]), &vec_b[i])
        });
        let t = group::scalar_add(&group::scalar_mul(&y, &r), &s);

        let tmp_vec = vector::range(0, n).map(|i| group::scalar_sub(&vec_d[i], &z));
        let tmp_product = group::scalar_from_u64(1);
        tmp_vec.for_each_ref(|v| {
            tmp_product = group::scalar_mul(&tmp_product, v);
        });
        let trx_branch = *trx;
        let product_proof =
            product_argument::prove(
                pedersen_ctxt,
                &mut trx_branch,
                n,
                &group::element_add(&vec_d_cmt, &vec_neg_z_cmt),
                &tmp_product,
                &tmp_vec,
                &t
            );

        let rho = group::scalar_from_u64(0);
        vector::range(0, n).for_each(|i| {
            let new_item = group::scalar_mul(vec_rho.borrow(i), &vec_b[i]);
            rho = group::scalar_add(&rho, &new_item);
        });
        let tmp_ciph = elgamal::weird_multi_exp(original, &x_powers);
        let multiexp_proof =
            multiexp_argument::prove(
                ek,
                pedersen_ctxt,
                trx,
                shuffled,
                &tmp_ciph,
                &vec_b_cmt,
                &vec_b,
                &s,
                &group::scalar_neg(&rho)
            );
        Proof { vec_a_cmt, vec_b_cmt, multiexp_proof, product_proof }
    }

    public fun verify(
        ek: &elgamal::EncKey,
        pedersen_ctxt: &pederson_commitment::Context,
        trx: &mut fiat_shamir_transform::Transcript,
        original: &vector<elgamal::Ciphertext>,
        shuffled: &vector<elgamal::Ciphertext>,
        proof: &Proof
    ): bool {
        let n = original.length();
        fiat_shamir_transform::append_group_element(trx, &proof.vec_a_cmt);
        let x = fiat_shamir_transform::hash_to_scalar(trx);
        fiat_shamir_transform::append_group_element(trx, &proof.vec_b_cmt);
        let y = fiat_shamir_transform::hash_to_scalar(trx);
        fiat_shamir_transform::append_raw_bytes(trx, b"NUDGE");
        let z = fiat_shamir_transform::hash_to_scalar(trx);
        let neg_z = group::scalar_neg(&z);
        let vec_neg_z = vector::range(0, n).map(|_| neg_z);
        let vec_neg_z_cmt =
            pederson_commitment::vec_commit(
                pedersen_ctxt, &group::scalar_from_u64(0), &vec_neg_z
            );
        let vec_d_cmt =
            group::element_add(
                &group::scale_element(&proof.vec_a_cmt, &y),
                &proof.vec_b_cmt
            );
        let tmp_product = group::scalar_from_u64(1);
        let x_powers = powers_of_x(&x, n);
        vector::range(0, n).for_each(|i| {
            let item =
                group::scalar_sub(
                    &group::scalar_add(
                        &group::scalar_mul(&y, &group::scalar_from_u64(i + 1)),
                        &x_powers[i]
                    ),
                    &z
                );
            tmp_product = group::scalar_mul(&tmp_product, &item);
        });
        let trx_branch = *trx;
        let tmp_ciph = elgamal::weird_multi_exp(original, &x_powers);
        product_argument::verify(
            pedersen_ctxt,
            &mut trx_branch,
            n,
            &group::element_add(&vec_d_cmt, &vec_neg_z_cmt),
            &tmp_product,
            &proof.product_proof
        ) && multiexp_argument::verify(
            ek,
            pedersen_ctxt,
            trx,
            shuffled,
            &tmp_ciph,
            &proof.vec_b_cmt,
            &proof.multiexp_proof
        )
    }

    fun powers_of_x(x: &group::Scalar, n: u64): vector<group::Scalar> {
        let ret = vector[*x];
        let i = 1;
        while (i < n) {
            let new_item = group::scalar_mul(&ret[i - 1], x);
            ret.push_back(new_item);
            i += 1;
        };
        ret
    }

    #[test(framework = @0x1)]
    fun completeness(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let n = 52;
        let pedersen_ctxt = pederson_commitment::rand_context(52);
        let enc_base = group::rand_element();
        let (_elgamal_dk, ek) = elgamal::key_gen(enc_base);
        let card_plaintexts = vector::range(0, n).map(|_| group::rand_element());
        let old_deck = vector::range(0, n).map(|i| elgamal::enc(&ek, &group::rand_scalar(), &card_plaintexts[i]));

        let rerandomizers = vector::range(0, n).map(|_| group::rand_scalar());
        let permutation = randomness::permutation(n);
        let new_deck = vector::range(0, n).map(|i| {
            elgamal::ciphertext_add(
                &old_deck[permutation[i]],
                &elgamal::enc(&ek, &rerandomizers[i], &group::group_identity())
            )
        });

        let trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut trx, b"SOME_TESTING_PREFIX");
        let trx_verifier = trx;
        let proof =
            prove(
                &ek,
                &pedersen_ctxt,
                &mut trx,
                &old_deck,
                &new_deck,
                permutation,
                &rerandomizers
            );
        assert!(
            verify(
                &ek,
                &pedersen_ctxt,
                &mut trx_verifier,
                &old_deck,
                &new_deck,
                &proof
            ),
            999
        );
    }
}
