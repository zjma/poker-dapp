/// Utils for Fiat-Shamir transformation.
module crypto_core::fiat_shamir_transform {
    use std::bcs;
    use aptos_std::ristretto255;
    use crypto_core::group;

    struct Transcript has copy, drop {
        recorded: vector<u8>
    }

    /// NOTE: client needs to implement this.
    public fun new_transcript(): Transcript {
        Transcript { recorded: vector[] }
    }

    /// NOTE: client needs to implement this.
    ///
    /// Gas cost: 0.07
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
    ///
    /// Gas cost: 0.01*num_elemnts_appended
    public fun hash_to_scalar(trx: &Transcript): group::Scalar {
        let scalar_inner = ristretto255::new_scalar_from_sha2_512(trx.recorded);
        group::scalar_from_inner(&scalar_inner)
    }
}
