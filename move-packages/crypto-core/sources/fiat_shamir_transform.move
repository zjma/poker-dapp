/// Utils for Fiat-Shamir transformation.
module crypto_core::fiat_shamir_transform {
    use aptos_std::aptos_hash::sha3_512;
    use aptos_std::debug::print;
    use crypto_core::group;
    #[test_only]
    use aptos_framework::randomness;
    #[test_only]
    use crypto_core::group::{encode_scalar, encode_element};

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
        append_raw_bytes(trx, group::encode_element(element))
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
        let (_, in, _) = group::decode_element(x"85ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a87209");
        append_group_element(&mut trx, &in);
        let out = hash_to_scalar(&trx);
        assert!(x"7c2b9ef979a61164ba8db00715cbc18eb4a501682b47467a69b7295e5ce9a532" == group::encode_scalar(&out), 999);
    }
}
