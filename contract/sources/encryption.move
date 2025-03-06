module contract_owner::encryption {
    use std::string;
    use std::vector;
    use aptos_std::type_info;
    use contract_owner::group;

    struct Ciphertext has copy, drop, store {
        enc_base: group::Element,
        c_0: group::Element,
        c_1: group::Element,
    }

    struct Plaintext has drop, store {}
    struct DecKey has drop, store {
        enc_base: group::Element,
        private_scalar: group::Scalar,
    }

    struct EncKey has copy, drop, store {
        enc_base: group::Element,
        public_point: group::Element,
    }

    public fun decode_enc_key(buf: vector<u8>): (vector<u64>, EncKey, vector<u8>) {
        let buf_len = vector::length(&buf);
        let header = *string::bytes(&type_info::type_name<EncKey>());
        let header_len = vector::length(&header);
        if (buf_len < header_len) return (vector[172706], dummy_enc_key(), buf);
        if (vector::slice(&buf, 0, header_len) != header) return (vector[172707], dummy_enc_key(), buf);
        let buf = vector::slice(&buf, header_len, buf_len);
        let (errors, enc_base, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 172708);
            return (errors, dummy_enc_key(), buf);
        };
        let (errors, public_point, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 172709);
            return (errors, dummy_enc_key(), buf);
        };
        let ret = EncKey { enc_base, public_point, };
        (vector[], ret, buf)
    }

    public fun encode_enc_key(ek: &EncKey): vector<u8> {
        let buf = *string::bytes(&type_info::type_name<EncKey>());
        vector::append(&mut buf, group::encode_element(&ek.enc_base));
        vector::append(&mut buf, group::encode_element(&ek.public_point));
        buf
    }

    public fun dummy_enc_key(): EncKey {
        EncKey {
            enc_base: group::group_identity(),
            public_point: group::group_identity(),
        }
    }

    public fun make_enc_key(enc_base: group::Element, public_point: group::Element): EncKey {
        EncKey {
            enc_base,
            public_point,
        }
    }

    public fun enc(ek: &EncKey, randomizer: &group::Scalar, ptxt: &group::Element): Ciphertext {
        Ciphertext {
            enc_base: ek.enc_base,
            c_0: group::scalar_mul(&ek.enc_base, randomizer),
            c_1: group::element_add(ptxt, &group::scalar_mul(&ek.public_point, randomizer)),
        }
    }

    public fun ciphertext_add(a: &Ciphertext, b: &Ciphertext): Ciphertext {
        Ciphertext {
            enc_base: a.enc_base,
            c_0: group::element_add(&a.c_0, &b.c_0),
            c_1: group::element_add(&a.c_1, &b.c_1),
        }
    }

    public fun unpack_ciphertext(ciphertext: &Ciphertext): (group::Element, group::Element, group::Element) {
        (ciphertext.enc_base, ciphertext.c_0, ciphertext.c_1)
    }

    #[test_only]
    public fun key_gen(enc_base: group::Element): (DecKey, EncKey) {
        let dk = group::rand_scalar();
        let ek = group::scalar_mul(&enc_base, &dk);
        (
            DecKey {
                enc_base,
                private_scalar: dk,
            },
            EncKey {
                enc_base,
                public_point: ek,
            },
        )
    }
}