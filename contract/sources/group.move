/// BLS12-381 G1 utils.
module contract_owner::group {
    use std::option;
    use std::string;
    use std::vector;
    use aptos_std::bls12381_algebra;
    use aptos_std::crypto_algebra;
    use aptos_std::type_info;
    use aptos_framework::randomness;

    const Q: u256 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    struct Element has copy, drop, store {
        bytes: vector<u8>,
    }
    struct Scalar has copy, drop, store {
        bytes: vector<u8>,
    }

    public fun encode_scalar(obj: &Scalar): vector<u8> {
        obj.bytes
    }

    public fun decode_scalar(buf: vector<u8>): (vector<u64>, Scalar, vector<u8>) {
        let buf_len = vector::length(&buf);
        let payload = vector::slice(&buf, 0, 32);
        let maybe_inner = crypto_algebra::deserialize<bls12381_algebra::Fr, bls12381_algebra::FormatFrLsb>(&payload);
        if (option::is_none(&maybe_inner)) return (vector[115605], dummy_scalar(), buf);
        let buf = vector::slice(&buf, 32, buf_len);
        let ret = Scalar { bytes: payload };
        (vector[], ret, buf)
    }

    public fun dummy_scalar(): Scalar {
        Scalar { bytes: vector[] }
    }

    #[lint::allow_unsafe_randomness]
    public fun rand_scalar(): Scalar {
        let rand_scalar_val = randomness::u256_range(0, Q);
        let bytes = vector::map(vector::range(0, 32), |idx|{
            let idx = (idx as u8);
            (((rand_scalar_val >> (idx * 8)) & 0xff) as u8)
        });
        Scalar { bytes }
    }

    #[lint::allow_unsafe_randomness]
    public fun rand_element(): Element {
        let inner = crypto_algebra::hash_to<bls12381_algebra::G1, bls12381_algebra::HashG1XmdSha256SswuRo>(&b"RAND_GROUP_ELEMENT_FOR_POKER", &randomness::bytes(32));
        element_from_inner(&inner)
    }

    public fun scalar_from_u64(v: u64): Scalar {
        let inner = crypto_algebra::from_u64<bls12381_algebra::Fr>(v);
        scalar_from_inner(&inner)
    }

    public fun scalar_from_little_endian_bytes_mod_q(bytes: vector<u8>): Scalar {
        let ret = 0;
        vector::for_each(bytes, |byte|{
            vector::for_each(u8_to_little_endian_bits(byte), |bit|{
                ret = safe_add_mod(ret, ret, Q);
                if (bit) {
                    ret = safe_add_mod(ret, 1, Q);
                }
            });
        });
        Scalar { bytes: u256_to_little_endian_bytes(ret) }
    }

    fun u8_to_little_endian_bits(x: u8): vector<bool> {
        vector::map(vector::range(0, 8), |i|((x >> (i as u8)) & 1) > 0)
    }

    fun u256_to_little_endian_bytes(x: u256): vector<u8> {
        vector::map(vector::range(0, 32), |i|{
            let shift = ((8*i) as u8);
            (((x >> shift) & 0xff) as u8)
        })
    }

    fun safe_add_mod(a: u256, b: u256, m: u256): u256 {
        let a_clone = a;
        let neg_b = m - b;
        if (a < neg_b) {
            a + b
        } else {
            a_clone - neg_b
        }
    }

    public fun group_identity(): Element {
        let inner = crypto_algebra::zero<bls12381_algebra::G1>();
        element_from_inner(&inner)
    }

    public fun element_add(a: &Element, b: &Element): Element {
        let inner_a = element_to_inner(a);
        let inner_b = element_to_inner(b);
        let inner_sum = crypto_algebra::add(&inner_a, &inner_b);
        element_from_inner(&inner_sum)
    }

    public fun element_add_assign(accumulator: &mut Element, add_on: &Element) {
        *accumulator = element_add(accumulator, add_on);
    }

    public fun element_sub(a: &Element, b: &Element): Element {
        let inner_a = element_to_inner(a);
        let inner_b = element_to_inner(b);
        let inner_diff = crypto_algebra::sub(&inner_a, &inner_b);
        element_from_inner(&inner_diff)
    }

    public fun element_sub_assign(accumulator: &mut Element, add_on: &Element) {
        *accumulator = element_sub(accumulator, add_on);
    }

    public fun scale_element(base: &Element, scalar: &Scalar): Element {
        let inner_b = element_to_inner(base);
        let inner_s = scalar_to_inner(scalar);
        let inner_res = crypto_algebra::scalar_mul(&inner_b, &inner_s);
        element_from_inner(&inner_res)
    }

    public fun scalar_add(a: &Scalar, b: &Scalar): Scalar {
        let inner_a = scalar_to_inner(a);
        let inner_b = scalar_to_inner(b);
        let inner_res = crypto_algebra::add(&inner_a, &inner_b);
        scalar_from_inner(&inner_res)
    }

    public fun scalar_sub(a: &Scalar, b: &Scalar): Scalar {
        let inner_a = scalar_to_inner(a);
        let inner_b = scalar_to_inner(b);
        let inner_res = crypto_algebra::sub(&inner_a, &inner_b);
        scalar_from_inner(&inner_res)
    }

    public fun scalar_mul(a: &Scalar, b: &Scalar): Scalar {
        let inner_a = scalar_to_inner(a);
        let inner_b = scalar_to_inner(b);
        let inner_res = crypto_algebra::mul(&inner_a, &inner_b);
        scalar_from_inner(&inner_res)
    }

    public fun decode_element(buf: vector<u8>): (vector<u64>, Element, vector<u8>) {
        let buf_len = vector::length(&buf);
        if (buf_len < 48) return (vector[110509], dummy_element(), buf);
        let payload = vector::slice(&buf, 0, 48);
        let maybe_inner = crypto_algebra::deserialize<bls12381_algebra::G1, bls12381_algebra::FormatG1Compr>(&payload);
        if (option::is_none(&maybe_inner)) return (vector[110510], dummy_element(), buf);
        let buf = vector::slice(&buf, 48, buf_len);
        let ret = Element { bytes: payload };
        (vector[], ret, buf)
    }

    public fun encode_element(obj: &Element): vector<u8> {
        obj.bytes
    }

    public fun dummy_element(): Element {
        Element { bytes: vector[] }
    }

    public fun element_sum(elements: vector<Element>): Element {
        let acc = group_identity();
        vector::for_each(elements, |element|{
            element_add_assign(&mut acc, &element);
        });
        acc
    }

    public fun scalar_neg(s: &Scalar): Scalar {
        let s_inner = scalar_to_inner(s);
        let ret_inner = crypto_algebra::neg(&s_inner);
        scalar_from_inner(&ret_inner)
    }

    public fun msm(elements: &vector<Element>, scalars: &vector<Scalar>): Element {
        let inner_elements = vector::map_ref(elements, |e|element_to_inner(e));
        let inner_scalars = vector::map_ref(scalars, |s|scalar_to_inner(s));
        let inner_ret =  crypto_algebra::multi_scalar_mul(&inner_elements, &inner_scalars);
        element_from_inner(&inner_ret)
    }

    fun scalar_to_inner(scalar: &Scalar): crypto_algebra::Element<bls12381_algebra::Fr> {
        let maybe= crypto_algebra::deserialize<bls12381_algebra::Fr, bls12381_algebra::FormatFrLsb>(&scalar.bytes);
        option::extract(&mut maybe)
    }

    fun scalar_from_inner(inner: &crypto_algebra::Element<bls12381_algebra::Fr>): Scalar {
        let bytes = crypto_algebra::serialize<bls12381_algebra::Fr, bls12381_algebra::FormatFrLsb>(inner);
        Scalar { bytes }
    }

    fun element_to_inner(element: &Element): crypto_algebra::Element<bls12381_algebra::G1> {
        let maybe= crypto_algebra::deserialize<bls12381_algebra::G1, bls12381_algebra::FormatG1Compr>(&element.bytes);
        option::extract(&mut maybe)
    }

    fun element_from_inner(inner: &crypto_algebra::Element<bls12381_algebra::G1>): Element {
        let bytes = crypto_algebra::serialize<bls12381_algebra::G1, bls12381_algebra::FormatG1Compr>(inner);
        Element { bytes }
    }

    #[lint::allow_unsafe_randomness]
    #[test(framework = @0x1)]
    fun general(framework: signer) {
        randomness::initialize_for_testing(&framework);
        let e0 = rand_element();
        let e0_doubled = element_add(&e0, &e0);
        let e0_quadrupled = element_add(&e0_doubled, &e0_doubled);
        let ei = group_identity();
        assert!(e0 == element_sub(&e0, &ei), 999);
        assert!(e0 == element_add(&e0, &ei), 999);

        let e0_bytes = encode_element(&e0);
        let (errors, e0_another, remainder) = decode_element(e0_bytes);
        assert!(vector::is_empty(&errors), 999);
        assert!(vector::is_empty(&remainder), 999);
        assert!(e0_another == e0, 999);

        let s7 = scalar_from_u64(7);
        assert!(scale_element(&e0, &s7) == element_sum(vector[e0, e0_doubled, e0_quadrupled]), 999);
        assert!(element_sub(&e0_quadrupled, &e0_doubled) == e0_doubled, 999);
        assert!(group_identity() == element_sub(&e0_doubled, &e0_doubled), 999);

        let s0 = rand_scalar();
        let s0_bytes = encode_scalar(&s0);
        let (errors, s0_another, remainder) = decode_scalar(s0_bytes);
        assert!(vector::is_empty(&errors), 999);
        assert!(vector::is_empty(&remainder), 999);
        assert!(s0_another == s0, 999);
    }
}
