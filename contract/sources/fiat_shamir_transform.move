/// Utils for Fiat-Shamir transformation.
module contract_owner::fiat_shamir_transform {
    use std::vector;
    use aptos_std::aptos_hash::sha3_512;
    use contract_owner::group;

    struct Transcript has drop {
        recorded: vector<u8>,
    }

    public fun new_transcript(): Transcript {
        Transcript {
            recorded: vector[]
        }
    }

    public fun append_group_element(trx: &mut Transcript, element: &group::Element) {
        append_raw_bytes(trx, group::encode_element(element))
    }

    public fun append_raw_bytes(trx: &mut Transcript, raw: vector<u8>) {
        vector::append(&mut trx.recorded, raw)
    }

    public fun hash_to_scalar(trx: &Transcript): group::Scalar {
        let bytes = sha3_512(trx.recorded);
        group::scalar_from_little_endian_bytes_mod_q(bytes)
    }
}
