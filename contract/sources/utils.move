module contract_owner::utils {
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
            (((x >> (i as u8)) & 0xff) as u8)
        })
    }
}