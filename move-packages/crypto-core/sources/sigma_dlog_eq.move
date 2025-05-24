/// Protocol to prove knowledge of scalar `s` such that `s*B0==P0, s*B1==P1` for public elements `B0, B1, P0, P1`.
module crypto_core::sigma_dlog_eq {
    use aptos_std::bcs_stream::BCSStream;
    use crypto_core::fiat_shamir_transform;
    use crypto_core::group;
    #[test_only]
    use aptos_framework::randomness;

    struct Proof has copy, drop, store {
        t0: group::Element,
        t1: group::Element,
        s: group::Scalar
    }

    public fun dummy_proof(): Proof {
        Proof {
            t0: group::dummy_element(),
            t1: group::dummy_element(),
            s: group::dummy_scalar()
        }
    }

    public fun decode_proof(stream: &mut BCSStream): Proof {
        let t0 = group::decode_element(stream);
        let t1 = group::decode_element(stream);
        let s = group::decode_scalar(stream);
        Proof { t0, t1, s }
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    /// NOTE: client needs to implement this.
    public fun prove(
        trx: &mut fiat_shamir_transform::Transcript,
        b0: &group::Element,
        p0: &group::Element,
        b1: &group::Element,
        p1: &group::Element, // statement
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

    /// Gas cost: 10.88
    public fun verify(
        trx: &mut fiat_shamir_transform::Transcript,
        b0: &group::Element,
        p0: &group::Element,
        b1: &group::Element,
        p1: &group::Element, // statement
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
        ret =
            ret
                && group::scale_element(b0, &proof.s)
                    == group::element_add(&proof.t0, &group::scale_element(p0, &c));
        ret =
            ret
                && group::scale_element(b1, &proof.s)
                    == group::element_add(&proof.t1, &group::scale_element(p1, &c));
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
        assert!(
            verify(&mut verifier_trx, &b0, &p0, &b1, &p1, &proof),
            999
        );
    }
}
