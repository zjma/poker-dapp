/// Using Ristretto255.
module crypto_core::group {
    use std::error;
    use std::vector::range;
    use aptos_std::bcs_stream;
    use aptos_std::bcs_stream::BCSStream;
    use aptos_std::ristretto255;
    use aptos_framework::randomness;
    #[test_only]
    use std::bcs;
    #[test_only]
    use aptos_std::debug::print;

    struct Element has copy, drop, store {
        bytes: vector<u8>
    }

    struct Scalar has copy, drop, store {
        bytes: vector<u8>
    }

    /// Gas cost: 0.98
    public fun decode_scalar(stream: &mut BCSStream): Scalar {
        let bytes = bcs_stream::deserialize_vector(stream, |s|bcs_stream::deserialize_u8(s));
        let maybe_inner = ristretto255::new_scalar_from_bytes(bytes);
        assert!(maybe_inner.is_some(), error::invalid_argument(0x4528));
        Scalar { bytes }
    }

    public fun dummy_scalar(): Scalar {
        Scalar { bytes: vector[] }
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

    /// Gas cost: 1.35
    public fun decode_element(stream: &mut BCSStream): Element {
        let bytes = bcs_stream::deserialize_vector(stream, |s|bcs_stream::deserialize_u8(s));
        let maybe_inner = ristretto255::new_compressed_point_from_bytes(bytes);
        assert!(maybe_inner.is_some(), error::invalid_argument(0x4527));
        Element { bytes }
    }

    entry fun example_deser(breakpoint: u64) {
        if (breakpoint == 0) return;
        range(0, 100).for_each(|_|{
            let stream = bcs_stream::new(x"201ecc0ce6fbe58776429c3e0e8f95db8fc0e5c15eac92467bc7b9a2d2c3273c0d");
            decode_element(&mut stream);
        });
        if (breakpoint == 1) return;

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
        let stream = bcs_stream::new(e0_bytes);
        let e0_another = decode_element(&mut stream);
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
        let stream = bcs_stream::new(s0_bytes);
        let s0_another = decode_scalar(&mut stream);
        assert!(s0_another == s0, 999);
    }

    #[test(fx = @0x1)]
    fun serde(fx: signer) {
        randomness::initialize_for_testing(&fx);
        let point_a = decode_element(&mut bcs_stream::new(x"20082267b53c21c9593128b9b0b511ec91423ef8dbc658eaa95f5be1418250e210"));
        let scalar_b = decode_scalar(&mut bcs_stream::new(x"20437fd90bce77f32ad3dc57758bd1ccdf1ddc1c1229b41718833f54d476c9c600"));
        let point_c = scale_element(&point_a, &scalar_b);
        assert!(x"20424a085adc2d55d4602fe1a7c36a90353df303544233002a97eea89f24fac727" == bcs::to_bytes(&point_c), 999);
        let scalar_b_sqr = scalar_mul(&scalar_b, &scalar_b);
        assert!(x"209f1b909b70c1cfbd1f67555bfff89effec9a26401f8bc27d0f0c4ed8efa6a902" == bcs::to_bytes(&scalar_b_sqr), 999);
    }
}
