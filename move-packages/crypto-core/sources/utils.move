module crypto_core::utils {
    use std::string::{String, utf8};

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
