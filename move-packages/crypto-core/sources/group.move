/// BLS12-381 G1 utils.
module crypto_core::group {
    use std::vector;
    use aptos_std::ristretto255;
    use aptos_framework::randomness;
    use crypto_core::utils;
    #[test_only]
    use std::bcs;
    #[test_only]
    use aptos_std::debug::print;

    /// Ristretto255 group order.
    const Q: u256 = 723700557733226221397318656304299424085711635937990760600195093828545425057;

    struct Element has copy, drop, store {
        bytes: vector<u8>
    }

    struct Scalar has copy, drop, store {
        bytes: vector<u8>
    }

    /// Gas cost: 0.98
    public fun decode_scalar(buf: vector<u8>): (vector<u64>, Scalar, vector<u8>) {
        let (errors, num_bytes, buf) = utils::decode_uleb128(buf);
        if (!errors.is_empty()) {
            errors.push_back(115603);
            return (errors, dummy_scalar(), buf);
        };
        if (num_bytes != 32) return (vector[115604], dummy_scalar(), buf);
        let buf_len = buf.length();
        if (buf_len < 32) return (vector[115605], dummy_scalar(), buf);
        let payload = buf.slice(0, 32);
        let maybe_inner = ristretto255::new_scalar_from_bytes(payload);
        if (maybe_inner.is_none()) return (vector[115606], dummy_scalar(), buf);
        let buf = buf.slice(32, buf.length());
        let ret = Scalar { bytes: payload };
        (vector[], ret, buf)
    }

    public fun dummy_scalar(): Scalar {
        Scalar { bytes: vector[] }
    }

    #[lint::allow_unsafe_randomness]
    /// Generate a random scalar.
    ///
    /// NOTE: client needs to implement this.
    ///
    /// Gas cost: 12
    public fun rand_scalar_slow(): Scalar {
        let rand_scalar_val = randomness::u256_range(0, Q);
        let bytes = vector::range(0, 32).map(|idx| {
            let idx = (idx as u8);
            (((rand_scalar_val >> (idx * 8)) & 0xff) as u8)
        });
        Scalar { bytes }
    }

    /// Gas cost: 1.11
    #[lint::allow_unsafe_randomness]
    public fun rand_scalar(): Scalar {
        let scalar_inner = ristretto255::new_scalar_from_sha2_512(randomness::bytes(64));
        scalar_from_inner(&scalar_inner)
    }

    /// Gas cost: ~13
    #[lint::allow_unsafe_randomness]
    public fun rand_element_slow(): Element {
        let scalar = rand_scalar();
        let scalar_inner = scalar_to_inner(&scalar);
        let inner = ristretto255::basepoint_mul(&scalar_inner);
        element_from_inner(&inner)
    }

    /// Gas cost: 1.56
    #[lint::allow_unsafe_randomness]
    public fun rand_element(): Element {
        let point_inner = ristretto255::new_point_from_sha2_512(randomness::bytes(64));
        element_from_inner(&point_inner)
    }

    /// Gas cost: ?
    public fun scalar_from_u64(v: u64): Scalar {
        let inner = ristretto255::new_scalar_from_u64(v);
        scalar_from_inner(&inner)
    }

    // public fun scalar_from_big_endian_bytes_mod_q(bytes: vector<u8>): Scalar {
    //     let ret = 0;
    //     bytes.for_each(|byte| {
    //         u8_to_big_endian_bits(byte).for_each(|bit| {
    //             ret = safe_add_mod(ret, ret, Q);
    //             if (bit) {
    //                 ret = safe_add_mod(ret, 1, Q);
    //             }
    //         });
    //     });
    //     Scalar { bytes: u256_to_little_endian_bytes(ret) }
    // }

    // fun u8_to_big_endian_bits(x: u8): vector<bool> {
    //     range(0, 8).map(|i| ((x >> (7-i as u8)) & 1) > 0)
    // }

    // fun u256_to_little_endian_bytes(x: u256): vector<u8> {
    //     vector::range(0, 32).map(|i| {
    //         let shift = ((8 * i) as u8);
    //         (((x >> shift) & 0xff) as u8)
    //     })
    // }

    // fun safe_add_mod(a: u256, b: u256, m: u256): u256 {
    //     let a_clone = a;
    //     let neg_b = m - b;
    //     if (a < neg_b) { a + b }
    //     else {
    //         a_clone - neg_b
    //     }
    // }

    public fun group_identity(): Element {
        let inner = ristretto255::point_identity();
        element_from_inner(&inner)
    }

    /// Gas cost: 0.68
    public fun element_add(a: &Element, b: &Element): Element {
        let inner_a = element_to_inner(a);
        let inner_b = element_to_inner(b);
        let inner_sum = ristretto255::point_add(&inner_a, &inner_b);
        element_from_inner(&inner_sum)
    }

    /// Gas cost: 0.68
    public fun element_add_assign(
        accumulator: &mut Element, add_on: &Element
    ) {
        *accumulator = element_add(accumulator, add_on);
    }

    /// Gas cost: 0.68
    public fun element_sub(a: &Element, b: &Element): Element {
        let inner_a = element_to_inner(a);
        let inner_b = element_to_inner(b);
        let inner_diff = ristretto255::point_sub(&inner_a, &inner_b);
        element_from_inner(&inner_diff)
    }

    public fun element_sub_assign(
        accumulator: &mut Element, add_on: &Element
    ) {
        *accumulator = element_sub(accumulator, add_on);
    }

    /// Gas cost: 2.26
    public fun scale_element(base: &Element, scalar: &Scalar): Element {
        let inner_b = element_to_inner(base);
        let inner_s = scalar_to_inner(scalar);
        let inner_res = ristretto255::point_mul(&inner_b, &inner_s);
        element_from_inner(&inner_res)
    }

    /// Gas cost: 0.23
    public fun scalar_add(a: &Scalar, b: &Scalar): Scalar {
        let inner_a = scalar_to_inner(a);
        let inner_b = scalar_to_inner(b);
        let inner_res = ristretto255::scalar_add(&inner_a, &inner_b);
        scalar_from_inner(&inner_res)
    }

    /// Gas cost: 0.23
    public fun scalar_sub(a: &Scalar, b: &Scalar): Scalar {
        let inner_a = scalar_to_inner(a);
        let inner_b = scalar_to_inner(b);
        let inner_res = ristretto255::scalar_sub(&inner_a, &inner_b);
        scalar_from_inner(&inner_res)
    }

    /// Gas cost: 0.23
    public fun scalar_mul(a: &Scalar, b: &Scalar): Scalar {
        let inner_a = scalar_to_inner(a);
        let inner_b = scalar_to_inner(b);
        let inner_res = ristretto255::scalar_mul(&inner_a, &inner_b);
        scalar_from_inner(&inner_res)
    }

    /// Gas cost: 1.12
    public fun decode_element(buf: vector<u8>): (vector<u64>, Element, vector<u8>) {
        let (errors, num_bytes, buf) = utils::decode_uleb128(buf);
        if (!errors.is_empty()) {
            errors.push_back(110507);
            return (errors, dummy_element(), buf);
        };
        if (num_bytes != 32) return (vector[110508], dummy_element(), buf);
        let buf_len = buf.length();
        if (buf_len < 32) return (vector[110509], dummy_element(), buf);
        let payload = buf.slice(0, 32);
        let maybe_inner = ristretto255::new_compressed_point_from_bytes(payload);
        if (maybe_inner.is_none()) return (vector[110510], dummy_element(), buf);
        let buf = buf.slice(32, buf_len);
        let ret = Element { bytes: payload };
        (vector[], ret, buf)
    }

    public fun dummy_element(): Element {
        Element { bytes: vector[] }
    }

    public fun element_sum(elements: vector<Element>): Element {
        let acc = group_identity();
        elements.for_each(|element| {
            element_add_assign(&mut acc, &element);
        });
        acc
    }

    public fun scalar_neg(s: &Scalar): Scalar {
        let s_inner = scalar_to_inner(s);
        let ret_inner = ristretto255::scalar_neg(&s_inner);
        scalar_from_inner(&ret_inner)
    }

    /// Gas cost: 4+0.6n
    public fun msm(elements: &vector<Element>, scalars: &vector<Scalar>): Element {
        let inner_elements = elements.map_ref(|e| element_to_inner(e));
        let inner_scalars = scalars.map_ref(|s| scalar_to_inner(s));
        let inner_ret = ristretto255::multi_scalar_mul(&inner_elements, &inner_scalars);
        element_from_inner(&inner_ret)
    }

    fun scalar_to_inner(scalar: &Scalar): ristretto255::Scalar {
        let maybe = ristretto255::new_scalar_from_bytes(scalar.bytes);
        maybe.extract()
    }

    public fun scalar_from_inner(inner: &ristretto255::Scalar): Scalar {
        let bytes = ristretto255::scalar_to_bytes(inner);
        Scalar { bytes }
    }

    fun element_to_inner(element: &Element): ristretto255::RistrettoPoint {
        let maybe = ristretto255::new_point_from_bytes(element.bytes);
        maybe.extract()
    }

    fun element_from_inner(inner: &ristretto255::RistrettoPoint): Element {
        let compressed = ristretto255::point_compress(inner);
        let bytes = ristretto255::point_to_bytes(&compressed);
        Element { bytes }
    }

    #[lint::allow_unsafe_randomness]
    #[test(framework = @0x1)]
    fun general(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let e0 = rand_element();
        print(&bcs::to_bytes(&e0));
        let sx = rand_scalar();
        print(&bcs::to_bytes(&sx));
        let e0_doubled = element_add(&e0, &e0);
        let e0_quadrupled = element_add(&e0_doubled, &e0_doubled);
        let ei = group_identity();
        assert!(e0 == element_sub(&e0, &ei), 999);
        assert!(e0 == element_add(&e0, &ei), 999);

        let e0_bytes = bcs::to_bytes(&e0);
        let (errors, e0_another, remainder) = decode_element(e0_bytes);
        assert!(errors.is_empty(), 999);
        assert!(remainder.is_empty(), 999);
        assert!(e0_another == e0, 999);

        let s7 = scalar_from_u64(7);
        assert!(
            scale_element(&e0, &s7)
                == element_sum(vector[e0, e0_doubled, e0_quadrupled]),
            999
        );
        assert!(element_sub(&e0_quadrupled, &e0_doubled) == e0_doubled, 999);
        assert!(group_identity() == element_sub(&e0_doubled, &e0_doubled), 999);

        let s0 = rand_scalar();
        let s0_bytes = bcs::to_bytes(&s0);
        let (errors, s0_another, remainder) = decode_scalar(s0_bytes);
        assert!(errors.is_empty(), 999);
        assert!(remainder.is_empty(), 999);
        assert!(s0_another == s0, 999);
    }

    #[test(fx = @0x1)]
    fun basic(fx: signer) {
        randomness::initialize_for_testing(&fx);
        let (errors, point_a, rem) = decode_element(x"20082267b53c21c9593128b9b0b511ec91423ef8dbc658eaa95f5be1418250e210");
        assert!(errors.is_empty(), 999);
        assert!(rem.is_empty(), 999);
        let (errors, scalar_b, rem) = decode_scalar(x"20437fd90bce77f32ad3dc57758bd1ccdf1ddc1c1229b41718833f54d476c9c600");
        assert!(errors.is_empty(), 999);
        assert!(rem.is_empty(), 999);
        let point_c = scale_element(&point_a, &scalar_b);
        assert!(x"30ac39b219f3915eb90a4917931abbd5cf57709473bbc57f2169a311de51b397b882c29a1ba8fbf581ca12c388d69eecec" == bcs::to_bytes(&point_c), 999);
    }
}
