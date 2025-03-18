module contract_owner::utils {
    use std::string::{String, utf8};
    use std::vector;

    public fun decode_u64(buf: vector<u8>): (vector<u64>, u64, vector<u8>) {
        let buf_len = vector::length(&buf);
        if (buf_len < 8) return (vector[182413], 0, buf);

        let ret = 0;
        let i = 0;
        while (i < 8) {
            let byte = *vector::borrow(&buf, i);
            ret = ret + ((byte as u64) << (8 * (i as u8)));
            i = i + 1;
        };

        let buf = vector::slice(&buf, 8, buf_len);
        (vector[], ret, buf)
    }

    public fun encode_u64(x: u64): vector<u8> {
        vector::map(vector::range(0, 8), |i|{
            (((x >> ((i*8) as u8)) & 0xff) as u8)
        })
    }

    const SUITE_TEXTS: vector<vector<u8>> = vector[b"S", b"H", b"D", b"C"];
    const NUMBER_TEXTS: vector<vector<u8>> = vector[b"__A", b"__2", b"__3", b"__4", b"__5", b"__6", b"__7", b"__8", b"__9", b"_10", b"__J", b"__Q", b"__K"];
    public fun get_card_text(card_val: u64): String {
        let suite = card_val / 13;
        let number = card_val % 13;
        let ret = *vector::borrow(&SUITE_TEXTS, suite);
        vector::append(&mut ret, *vector::borrow(&NUMBER_TEXTS, number));
        utf8(ret)
    }
}