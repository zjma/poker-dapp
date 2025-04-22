module contract_owner::utils {
    use std::string::{String, utf8};
    use std::vector;

    public fun decode_u64(buf: vector<u8>): (vector<u64>, u64, vector<u8>) {
        let buf_len = buf.length();
        if (buf_len < 8) return (vector[182413], 0, buf);

        let ret = 0;
        let i = 0;
        while (i < 8) {
            ret += ((buf[i] as u64) << (8 * (i as u8)));
            i += 1;
        };

        let buf = buf.slice(8, buf_len);
        (vector[], ret, buf)
    }

    /// NOTE: client needs to implement this.
    public fun encode_u64(x: u64): vector<u8> {
        vector::range(0, 8).map(|i| {
            (((x >> ((i * 8) as u8)) & 0xff) as u8)
        })
    }

    const SUITE_TEXTS: vector<vector<u8>> = vector[b"S", b"H", b"D", b"C"];
    const NUMBER_TEXTS: vector<vector<u8>> = vector[
        b"__A",
        b"__2",
        b"__3",
        b"__4",
        b"__5",
        b"__6",
        b"__7",
        b"__8",
        b"__9",
        b"_10",
        b"__J",
        b"__Q",
        b"__K"
    ];
    public fun get_card_text(card_val: u64): String {
        let suite = card_val / 13;
        let number = card_val % 13;
        let ret = SUITE_TEXTS[suite];
        ret.append(NUMBER_TEXTS[number]);
        utf8(ret)
    }
}
