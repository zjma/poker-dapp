/// ElGamal encryption instantiated with bls12-381 G1.
module contract_owner::elgamal {
    use std::vector;
    use contract_owner::group;
    #[test_only]
    use aptos_framework::randomness;

    struct Ciphertext has copy, drop, store {
        enc_base: group::Element,
        c_0: group::Element,
        c_1: group::Element
    }

    struct Plaintext has drop, store {}

    struct DecKey has copy, drop, store {
        enc_base: group::Element,
        private_scalar: group::Scalar
    }

    struct EncKey has copy, drop, store {
        enc_base: group::Element,
        public_point: group::Element
    }

    public fun decode_enc_key(buf: vector<u8>): (vector<u64>, EncKey, vector<u8>) {
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
        let ret = EncKey { enc_base, public_point };
        (vector[], ret, buf)
    }

    public fun encode_enc_key(ek: &EncKey): vector<u8> {
        let buf = vector[];
        vector::append(&mut buf, group::encode_element(&ek.enc_base));
        vector::append(&mut buf, group::encode_element(&ek.public_point));
        buf
    }

    public fun dummy_enc_key(): EncKey {
        EncKey {
            enc_base: group::group_identity(),
            public_point: group::group_identity()
        }
    }

    public fun make_enc_key(
        enc_base: group::Element, public_point: group::Element
    ): EncKey {
        EncKey { enc_base, public_point }
    }

    public fun make_ciphertext(
        enc_base: group::Element, c_0: group::Element, c_1: group::Element
    ): Ciphertext {
        Ciphertext { enc_base, c_0, c_1 }
    }

    public fun enc(
        ek: &EncKey, randomizer: &group::Scalar, ptxt: &group::Element
    ): Ciphertext {
        Ciphertext {
            enc_base: ek.enc_base,
            c_0: group::scale_element(&ek.enc_base, randomizer),
            c_1: group::element_add(
                ptxt, &group::scale_element(&ek.public_point, randomizer)
            )
        }
    }

    public fun dec(dk: &DecKey, ciph: &Ciphertext): group::Element {
        let unblinder = group::scale_element(&ciph.c_0, &dk.private_scalar);
        group::element_sub(&ciph.c_1, &unblinder)
    }

    public fun ciphertext_add(a: &Ciphertext, b: &Ciphertext): Ciphertext {
        Ciphertext {
            enc_base: a.enc_base,
            c_0: group::element_add(&a.c_0, &b.c_0),
            c_1: group::element_add(&a.c_1, &b.c_1)
        }
    }

    public fun ciphertext_mul(a: &Ciphertext, s: &group::Scalar): Ciphertext {
        Ciphertext {
            enc_base: a.enc_base,
            c_0: group::scale_element(&a.c_0, s),
            c_1: group::scale_element(&a.c_1, s)
        }
    }

    public fun weird_multi_exp(
        ciphs: &vector<Ciphertext>, scalars: &vector<group::Scalar>
    ): Ciphertext {
        let acc = Ciphertext {
            enc_base: vector::borrow(ciphs, 0).enc_base,
            c_0: group::group_identity(),
            c_1: group::group_identity()
        };
        vector::zip_ref(
            ciphs,
            scalars,
            |ciph, scalar| {
                acc = ciphertext_add(&acc, &ciphertext_mul(ciph, scalar))
            }
        );
        acc
    }

    public fun unpack_ciphertext(
        ciphertext: Ciphertext
    ): (group::Element, group::Element, group::Element) {
        let Ciphertext { enc_base, c_0, c_1 } = ciphertext;
        (enc_base, c_0, c_1)
    }

    public fun dummy_ciphertext(): Ciphertext {
        Ciphertext {
            enc_base: group::dummy_element(),
            c_0: group::dummy_element(),
            c_1: group::dummy_element()
        }
    }

    public fun encode_ciphertext(obj: &Ciphertext): vector<u8> {
        let buf = vector[];
        vector::append(&mut buf, group::encode_element(&obj.enc_base));
        vector::append(&mut buf, group::encode_element(&obj.c_0));
        vector::append(&mut buf, group::encode_element(&obj.c_1));
        buf
    }

    public fun decode_ciphertext(buf: vector<u8>): (vector<u64>, Ciphertext, vector<u8>) {
        let (errors, enc_base, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) return (vector[123129], dummy_ciphertext(), buf);
        let (errors, c_0, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) return (vector[123129], dummy_ciphertext(), buf);
        let (errors, c_1, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) return (vector[123129], dummy_ciphertext(), buf);
        let ret = Ciphertext { enc_base, c_0, c_1 };
        (vector[], ret, buf)
    }

    public fun derive_ek_from_dk(dk: &DecKey): EncKey {
        EncKey {
            enc_base: dk.enc_base,
            public_point: group::scale_element(&dk.enc_base, &dk.private_scalar)
        }
    }

    public fun unpack_enc_key(ek: EncKey): (group::Element, group::Element) {
        let EncKey { enc_base, public_point } = ek;
        (enc_base, public_point)
    }

    #[test_only]
    public fun unpack_dec_key(dk: DecKey): (group::Element, group::Scalar) {
        let DecKey { enc_base, private_scalar } = dk;
        (enc_base, private_scalar)
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    public fun key_gen(enc_base: group::Element): (DecKey, EncKey) {
        let dk = group::rand_scalar();
        let ek = group::scale_element(&enc_base, &dk);
        (
            DecKey { enc_base, private_scalar: dk },
            EncKey { enc_base, public_point: ek }
        )
    }

    #[test(framework = @0x1)]
    fun general(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let enc_base = group::rand_element();
        let (dk, ek) = key_gen(enc_base);
        let plaintext = group::rand_element();
        let r = group::rand_scalar();
        let ciphertext = enc(&ek, &r, &plaintext);
        let ciph_bytes = encode_ciphertext(&ciphertext);
        let (errors, ciphertext_another, remainder) = decode_ciphertext(ciph_bytes);
        assert!(vector::is_empty(&errors), 999);
        assert!(vector::is_empty(&remainder), 999);
        assert!(ciphertext_another == ciphertext, 999);
        let plaintext_another = dec(&dk, &ciphertext);
        assert!(plaintext_another == plaintext, 999);
    }
}
