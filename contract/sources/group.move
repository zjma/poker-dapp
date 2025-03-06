module contract_owner::group {
    struct Element has copy, drop, store {}
    struct Scalar has copy, drop, store {}
    public native fun rand_scalar(): Scalar;
    public native fun rand_element(): Element;
    public native fun zero_scalar(): Scalar;
    public native fun group_identity(): Element;
    public native fun element_add(a: &Element, b: &Element): Element;
    public native fun element_add_assign(accumulator: &mut Element, add_on: &Element);
    public native fun element_sub_assign(accumulator: &mut Element, add_on: &Element);
    public native fun scalar_mul(base: &Element, scalar: &Scalar): Element;
    public native fun decode_element(buf: vector<u8>): (vector<u64>, Element, vector<u8>);
    public native fun encode_element(obj: &Element): vector<u8>;
    public native fun default_element(): Element;
    public native fun element_sum(elements: vector<Element>): Element;
}
