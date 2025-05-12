/// Utils for Fiat-Shamir transformation.
module crypto_core::fiat_shamir_transform {
    use std::bcs;
    use aptos_std::aptos_hash::sha3_512;
    use aptos_std::debug::print;
    use crypto_core::group;
    #[test_only]
    use aptos_framework::randomness;

    struct Transcript has copy, drop {
        recorded: vector<u8>
    }

    /// NOTE: client needs to implement this.
    public fun new_transcript(): Transcript {
        Transcript { recorded: vector[] }
    }

    /// NOTE: client needs to implement this.
    public fun append_group_element(
        trx: &mut Transcript, element: &group::Element
    ) {
        append_raw_bytes(trx, bcs::to_bytes(element))
    }

    /// NOTE: client needs to implement this.
    public fun append_raw_bytes(trx: &mut Transcript, raw: vector<u8>) {
        trx.recorded.append(raw)
    }

    /// NOTE: client needs to implement this.
    public fun hash_to_scalar(trx: &Transcript): group::Scalar {
        let bytes = sha3_512(trx.recorded);
        print(&bytes);
        group::scalar_from_big_endian_bytes_mod_q(bytes)
    }
    
    #[test(fx = @0x1)]
    fun basic(fx: signer) {
        randomness::initialize_for_testing(&fx);
        let trx = new_transcript();
        let (_, in, _) = group::decode_element(x"3085ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a87209");
        append_group_element(&mut trx, &in);
        let out = hash_to_scalar(&trx);
        assert!(x"20fe9b7b3d64c296e0e570363f091afb5be6422b9a8d3ff853b317e7662c2a3b61" == bcs::to_bytes(&out), 999);
    }
}
