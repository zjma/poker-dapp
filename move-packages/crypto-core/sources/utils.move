module crypto_core::utils {
    use std::string::{String, utf8};
    use std::vector;

    public fun decode_uleb128(buf: vector<u8>): (vector<u64>, u128, vector<u8>) {
        let buf_len = buf.length();
        let ret = 0;
        let num_bytes_accepted = 0;
        while (num_bytes_accepted < buf_len) {
            let byte = buf[num_bytes_accepted];
            let payload = byte & 0x7f;
            let is_last_byte = (byte >> 7) == 0;
            if (num_bytes_accepted == 18) {
                if (payload >= 4) return (vector[351125], 0, buf);
                if (!is_last_byte) return (vector[351126], 0, buf);
            };
            ret += (payload as u128) << (7 * num_bytes_accepted as u8);
            num_bytes_accepted += 1;
            if (is_last_byte) break;
        };
        if (num_bytes_accepted == 0) return (vector[351127], 0, buf);
        (vector[], ret, buf.slice(num_bytes_accepted, buf_len))
    }

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

    #[test]
    fun extra() {
        let x = 12364789;
        assert!(encode_u64(x) == std::bcs::to_bytes(&x), 999);
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
