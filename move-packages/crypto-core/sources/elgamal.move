/// ElGamal encryption instantiated with bls12-381 G1.
module crypto_core::elgamal {
    use crypto_core::group;
    #[test_only]
    use std::bcs;
    #[test_only]
    use std::vector;
    #[test_only]
    use aptos_std::debug::print;
    #[test_only]
    use aptos_framework::randomness;
    #[test_only]
    use crypto_core::group::{rand_element, rand_scalar};

    struct Ciphertext has copy, drop, store {
        enc_base: group::Element,
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

    /// Gas cost: ~12
    public fun decode_dec_key(buf: vector<u8>): (vector<u64>, DecKey, vector<u8>) {
        let (errors, enc_base, buf) = group::decode_element(buf);
        if (!errors.is_empty()) {
            errors.push_back(240835);
            return (errors, dummy_dec_key(), buf);
        };
        let (errors, private_scalar, buf) = group::decode_scalar(buf);
        if (!errors.is_empty()) {
            errors.push_back(240836);
            return (errors, dummy_dec_key(), buf);
        };
        let ret = DecKey { enc_base, private_scalar };
        (vector[], ret, buf)
    }

    /// Gas cost: ~11
    public fun decode_enc_key(buf: vector<u8>): (vector<u64>, EncKey, vector<u8>) {
        let (errors, enc_base, buf) = group::decode_element(buf);
        if (!errors.is_empty()) {
            errors.push_back(172708);
            return (errors, dummy_enc_key(), buf);
        };
        let (errors, public_point, buf) = group::decode_element(buf);
        if (!errors.is_empty()) {
            errors.push_back(172709);
            return (errors, dummy_enc_key(), buf);
        };
        let ret = EncKey { enc_base, public_point };
        (vector[], ret, buf)
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

    /// Gas cost: ~37
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

    /// Gas cost: 23
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

    /// Gas cost: 136 for size 3.
    public fun weird_multi_exp(
        ciphs: &vector<Ciphertext>, scalars: &vector<group::Scalar>
    ): Ciphertext {
        let acc = Ciphertext {
            enc_base: ciphs.borrow(0).enc_base,
            c_0: group::group_identity(),
            c_1: group::group_identity()
        };
        ciphs.zip_ref(scalars, |ciph, scalar| {
            acc = ciphertext_add(&acc, &ciphertext_mul(ciph, scalar))
        });
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

    public fun decode_ciphertext(buf: vector<u8>): (vector<u64>, Ciphertext, vector<u8>) {
        let (errors, enc_base, buf) = group::decode_element(buf);
        if (!errors.is_empty()) return (vector[123129], dummy_ciphertext(), buf);
        let (errors, c_0, buf) = group::decode_element(buf);
        if (!errors.is_empty()) return (vector[123129], dummy_ciphertext(), buf);
        let (errors, c_1, buf) = group::decode_element(buf);
        if (!errors.is_empty()) return (vector[123129], dummy_ciphertext(), buf);
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
        let (errors, ciphertext_another, remainder) = decode_ciphertext(ciph_bytes);
        assert!(errors.is_empty(), 999);
        assert!(remainder.is_empty(), 999);
        assert!(ciphertext_another == ciphertext, 999);
        let plaintext_another = dec(&dk, &ciphertext);
        assert!(plaintext_another == plaintext, 999);
    }

    #[lint::allow_unsafe_randomness]
    #[test(fx = @0x1)]
    fun basic(fx: signer) {
        randomness::initialize_for_testing(&fx);

        let (errors, dk, remainder) = decode_dec_key(x"3085ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a8720920e57e6c4d3f6c645d69549f0c62aebfb77ebbcf29d2a8f0cd597d4ecd8ed56458");
        assert!(errors.is_empty(), 999);
        assert!(remainder.is_empty(), 999);

        let (errors, ek, remainder) = decode_enc_key(x"3085ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a8720930ac39b219f3915eb90a4917931abbd5cf57709473bbc57f2169a311de51b397b882c29a1ba8fbf581ca12c388d69eecec");
        assert!(errors.is_empty(), 999);
        assert!(remainder.is_empty(), 999);

        let msgs = vector[
            x"30b2a87401bbed626666c5bab7d0a6503c04cbb7a91bb42a68f5f52370993658d8bd54e23cd7ae7ddd9a78eec823c0fdc1",
            x"30a9e85bd1b4f17ef0aadee7a420873ab8c4568c56f91686cd6cc03ab43ade4bf3d2c4a011667ade42c5dad1a8d32d8bf3",
            x"3092d67fcaac2fc24a4a92a4035fb4d2a64b0cdd5f3e80fb2ddfff640717eaf444fae9da821fac35e922e7014f6bbfacfe",
        ].map(|buf|{
            let (errors, element, remainder) = group::decode_element(buf);
            assert!(errors.is_empty(), 999);
            assert!(remainder.is_empty(), 999);
            element
        });

        let randomizers = vector[
            x"2023bcb6a5ec8328bb3772930f2e5f48df3ede9ee6ddabcdefbfe15cb029980311",
            x"204c55876a65167a1f9d901f3b7e28985f1353f4bc1e36e7c11be7d416fba70c5b",
            x"2041535947e0e5039cea76bc4960c8e25b1c36f717d16e19a00593a8f7bc5e842c",
        ].map(|buf|{
            let (errors, scalar, remainder) = group::decode_scalar(buf);
            assert!(errors.is_empty(), 999);
            assert!(remainder.is_empty(), 999);
            scalar
        });

        let ciphertexts = msgs.zip_map_ref(&randomizers, |msg, randomizer| enc(&ek, randomizer, msg));
        ciphertexts.for_each_ref(|ciph| {
            print(&bcs::to_bytes(ciph));
        });

        // let scalars = vector[rand_scalar(), rand_scalar(), rand_scalar()];
        // let agg_ciphertext = weird_multi_exp(&ciphertexts, &scalars);
        // let agg_msg = dec(&dk, &agg_ciphertext);
        // assert!(group::msm(&msgs, &scalars) == agg_msg, 999);
    }

    #[randomness]
    entry fun example(stop_after_step: u64) {
        let (errors, dk, remainder) = decode_dec_key(x"3085ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a8720920e57e6c4d3f6c645d69549f0c62aebfb77ebbcf29d2a8f0cd597d4ecd8ed56458");
        if (stop_after_step == 0) return;

        let (errors, ek, remainder) = decode_enc_key(x"3085ba9eae97029dee22680d4506d85d87146dbcc0b7b797d71500489eb23e0b399b5d8af1925f8871a7c2dc9f65a8720930ac39b219f3915eb90a4917931abbd5cf57709473bbc57f2169a311de51b397b882c29a1ba8fbf581ca12c388d69eecec");
        if (stop_after_step == 1) return;

        let msgs = vector[
            x"30b2a87401bbed626666c5bab7d0a6503c04cbb7a91bb42a68f5f52370993658d8bd54e23cd7ae7ddd9a78eec823c0fdc1",
            x"30a9e85bd1b4f17ef0aadee7a420873ab8c4568c56f91686cd6cc03ab43ade4bf3d2c4a011667ade42c5dad1a8d32d8bf3",
            x"3092d67fcaac2fc24a4a92a4035fb4d2a64b0cdd5f3e80fb2ddfff640717eaf444fae9da821fac35e922e7014f6bbfacfe",
        ].map(|buf|{
            let (errors, element, remainder) = group::decode_element(buf);
            assert!(errors.is_empty(), 999);
            assert!(remainder.is_empty(), 999);
            element
        });

        if (stop_after_step == 2) return;

        let randomizers = vector[
            x"2023bcb6a5ec8328bb3772930f2e5f48df3ede9ee6ddabcdefbfe15cb029980311",
            x"204c55876a65167a1f9d901f3b7e28985f1353f4bc1e36e7c11be7d416fba70c5b",
            x"2041535947e0e5039cea76bc4960c8e25b1c36f717d16e19a00593a8f7bc5e842c",
        ].map(|buf|{
            let (errors, scalar, remainder) = group::decode_scalar(buf);
            assert!(errors.is_empty(), 999);
            assert!(remainder.is_empty(), 999);
            scalar
        });

        if (stop_after_step == 3) return; // 42

        let ciphertexts = msgs.zip_map_ref(&randomizers, |msg, randomizer| enc(&ek, randomizer, msg));

        if (stop_after_step == 4) return; // 152

        let scalars = vector[group::rand_scalar(), group::rand_scalar(), group::rand_scalar()];
        if (stop_after_step == 5) return; // 188

        let agg_ciphertext = weird_multi_exp(&ciphertexts, &scalars);
        if (stop_after_step == 6) return; // 324

        let agg_msg = dec(&dk, &agg_ciphertext);
        if (stop_after_step == 7) return; // 347
    }
}
