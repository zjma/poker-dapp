module crypto_core::utils {
    use std::string::{String, utf8};

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
