/// ElGamal encryption instantiated with bls12-381 G1.
module crypto_core::elgamal {
    use aptos_std::bcs_stream::BCSStream;
    use crypto_core::group;
    #[test_only]
    use std::bcs;
    #[test_only]
    use aptos_std::bcs_stream;
    #[test_only]
    use aptos_framework::randomness;

    struct Ciphertext has copy, drop, store {
        c_0: group::Element,
        c_1: group::Element
    }

    struct DecKey has copy, drop, store {
        enc_base: group::Element,
        private_scalar: group::Scalar
    }

    struct EncKey has copy, drop, store {
        enc_base: group::Element,
        public_point: group::Element
    }
    
    public fun dummy_dec_key(): DecKey {
        DecKey {
            enc_base: group::dummy_element(),
            private_scalar: group::dummy_scalar(),
        }
    }

    /// Gas cost: 2.10
    public fun decode_dec_key(stream: &mut BCSStream): DecKey {
        let enc_base = group::decode_element(stream);
        let private_scalar = group::decode_scalar(stream);
        DecKey { enc_base, private_scalar }
    }

    /// Gas cost: 2.24
    public fun decode_enc_key(stream: &mut BCSStream): EncKey {
        let enc_base = group::decode_element(stream);
        let public_point = group::decode_element(stream);
        EncKey { enc_base, public_point }
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

    public fun make_ciphertext(c_0: group::Element, c_1: group::Element): Ciphertext { Ciphertext { c_0, c_1 } }

    /// Gas cost: 6.20
    public fun enc(
        ek: &EncKey, randomizer: &group::Scalar, ptxt: &group::Element
    ): Ciphertext {
        Ciphertext {
            c_0: group::scale_element(&ek.enc_base, randomizer),
            c_1: group::element_add(
                ptxt, &group::scale_element(&ek.public_point, randomizer)
            )
        }
    }

    /// Gas cost: 2.94
    public fun dec(dk: &DecKey, ciph: &Ciphertext): group::Element {
        let unblinder = group::scale_element(&ciph.c_0, &dk.private_scalar);
        group::element_sub(&ciph.c_1, &unblinder)
    }

    /// Gas cost: 1.36
    public fun ciphertext_add(a: &Ciphertext, b: &Ciphertext): Ciphertext {
        Ciphertext {
            c_0: group::element_add(&a.c_0, &b.c_0),
            c_1: group::element_add(&a.c_1, &b.c_1)
        }
    }

    /// Gas cost: 4.52
    public fun ciphertext_mul(a: &Ciphertext, s: &group::Scalar): Ciphertext {
        Ciphertext {
            c_0: group::scale_element(&a.c_0, s),
            c_1: group::scale_element(&a.c_1, s)
        }
    }

    /// Gas cost: 15+1.1n
    public fun multi_exp(ciphs: &vector<Ciphertext>, scalars: &vector<group::Scalar>): Ciphertext {
        let c_0_elements = vector[];
        let c_1_elements = vector[];
        ciphs.for_each_ref(|ciph|{
            c_0_elements.push_back(ciph.c_0);
            c_1_elements.push_back(ciph.c_1);
        });
        let c_0 = group::msm(&c_0_elements, scalars);
        let c_1 = group::msm(&c_1_elements, scalars);
        Ciphertext { c_0, c_1 }
    }

    public fun unpack_ciphertext(
        ciphertext: Ciphertext
    ): (group::Element, group::Element) {
        let Ciphertext { c_0, c_1 } = ciphertext;
        (c_0, c_1)
    }

    /// Gas cost: 3.96
    public fun decode_ciphertext(stream: &mut BCSStream): Ciphertext {
        let c_0 = group::decode_element(stream);
        let c_1 = group::decode_element(stream);
        Ciphertext { c_0, c_1 }
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
    public fun key_gen(enc_base: group::Element): (DecKey, EncKey) {
        let dk = group::rand_scalar();
        let ek = group::scale_element(&enc_base, &dk);
        (DecKey { enc_base, private_scalar: dk }, EncKey { enc_base, public_point: ek })
    }

    #[test(framework = @0x1)]
    fun general(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let enc_base = group::rand_element();
        let (dk, ek) = key_gen(enc_base);
        let plaintext = group::rand_element();
        let r = group::rand_scalar();
        let ciphertext = enc(&ek, &r, &plaintext);
        let ciph_bytes = bcs::to_bytes(&ciphertext);
        let ciphertext_another = decode_ciphertext(&mut bcs_stream::new(ciph_bytes));
        assert!(ciphertext_another == ciphertext, 999);
        let plaintext_another = dec(&dk, &ciphertext);
        assert!(plaintext_another == plaintext, 999);
    }
}
