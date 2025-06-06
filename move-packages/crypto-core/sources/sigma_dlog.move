/// Protocol to prove knowledge of scalar `s` such that `s*B == P` for public group element `B` and `P`.
module crypto_core::sigma_dlog {
    use aptos_std::bcs_stream::BCSStream;
    use crypto_core::fiat_shamir_transform;
    use crypto_core::group;
    #[test_only]
    use aptos_framework::randomness;

    struct Proof has copy, drop, store {
        t: group::Element,
        s: group::Scalar,
    }

    public fun dummy_proof(): Proof {
        Proof {
            t: group::dummy_element(),
            s: group::dummy_scalar()
        }
    }

    public fun decode_proof(stream: &mut BCSStream): Proof {
        let t = group::decode_element(stream);
        let s = group::decode_scalar(stream);
        Proof { t, s }
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// NOTE: client needs to implement this.
    public fun prove(
        trx: &mut fiat_shamir_transform::Transcript,
        b: &group::Element,
        p: &group::Element, // statement
        s: &group::Scalar // witness
    ): Proof {
        fiat_shamir_transform::append_group_element(trx, b);
        fiat_shamir_transform::append_group_element(trx, p);
        let r = group::rand_scalar();
        let t = group::scale_element(b, &r);
        fiat_shamir_transform::append_group_element(trx, &t);
        let c = fiat_shamir_transform::hash_to_scalar(trx);
        let s = group::scalar_add(&r, &group::scalar_mul(&c, s));
        Proof { t, s }
    }

    /// Gas cost: 5.44
    public fun verify(
        trx: &mut fiat_shamir_transform::Transcript,
        b: &group::Element,
        p: &group::Element, // statement
        proof: &Proof
    ): bool {
        fiat_shamir_transform::append_group_element(trx, b);
        fiat_shamir_transform::append_group_element(trx, p);
        fiat_shamir_transform::append_group_element(trx, &proof.t);
        let c = fiat_shamir_transform::hash_to_scalar(trx);
        let ret = true;
        ret =
            ret
                && group::scale_element(b, &proof.s)
                    == group::element_add(&proof.t, &group::scale_element(p, &c));
        ret
    }

    #[test(framework = @0x1)]
    fun general(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let s = group::rand_scalar();
        let b = group::rand_element();
        let p = group::scale_element(&b, &s);
        let prover_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut prover_trx, b"SHARED_PREFIX");
        let proof = prove(&mut prover_trx, &b, &p, &s);

        let verifier_trx = fiat_shamir_transform::new_transcript();
        fiat_shamir_transform::append_raw_bytes(&mut verifier_trx, b"SHARED_PREFIX");
        assert!(verify(&mut verifier_trx, &b, &p, &proof), 999);
    }
}
