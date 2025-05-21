import { Deserializer, Serializer } from '@aptos-labs/ts-sdk';
import { Element, Scalar } from './group';
import { Transcript } from './fiat_shamir_transform';
import * as Pedersen from './pedersenCommitment';

export class Proof {
    vec_d_cmt: Element;
    cmt_2: Element;
    cmt_3: Element;
    vec_a_tilde: Scalar[];
    vec_b_tilde: Scalar[];
    r_tilde: Scalar;
    s_tilde: Scalar;

    constructor(vec_d_cmt: Element, cmt_2: Element, cmt_3: Element, vec_a_tilde: Scalar[], vec_b_tilde: Scalar[], r_tilde: Scalar, s_tilde: Scalar) {
        this.vec_d_cmt = vec_d_cmt;
        this.cmt_2 = cmt_2;
        this.cmt_3 = cmt_3;
        this.vec_a_tilde = vec_a_tilde;
        this.vec_b_tilde = vec_b_tilde;
        this.r_tilde = r_tilde;
        this.s_tilde = s_tilde;
    }

    static decode(deserializer: Deserializer): Proof {
        const vec_d_cmt = Element.decode(deserializer);
        const cmt_2 = Element.decode(deserializer);
        const cmt_3 = Element.decode(deserializer);
        const vec_a_tilde = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Scalar.decode(deserializer));
        const vec_b_tilde = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Scalar.decode(deserializer));
        const r_tilde = Scalar.decode(deserializer);
        const s_tilde = Scalar.decode(deserializer);
        return new Proof(vec_d_cmt, cmt_2, cmt_3, vec_a_tilde, vec_b_tilde, r_tilde, s_tilde);
    }

    encode(serializer: Serializer): void {
        this.vec_d_cmt.encode(serializer);
        this.cmt_2.encode(serializer);
        this.cmt_3.encode(serializer);
        serializer.serializeU32AsUleb128(this.vec_a_tilde.length);
        for (let i = 0; i < this.vec_a_tilde.length; i++) {
            this.vec_a_tilde[i].encode(serializer);
        }
        serializer.serializeU32AsUleb128(this.vec_b_tilde.length);
        for (let i = 0; i < this.vec_b_tilde.length; i++) {
            this.vec_b_tilde[i].encode(serializer);
        }
        this.r_tilde.encode(serializer);
        this.s_tilde.encode(serializer);
    }
}

export function prove(
    pedersen_ctxt: Pedersen.Context,
    trx: Transcript,
    n: number,
    vec_a_cmt: Element,
    b: Scalar,
    vec_a: Scalar[],
    r: Scalar
): Proof {
    const vec_b = [vec_a[0]];
    for (let i = 1; i < n; i++) {
        const new_item = vec_b[i - 1].mul(vec_a[i]);
        vec_b.push(new_item);
    };

    const vec_d = Array.from({length: n}, (_) => Scalar.rand());
    const r_d = Scalar.rand();
    const vec_delta = [vec_d[0]];
    for (let i = 1; i < n - 1; i++) {
        vec_delta.push(Scalar.rand());
    }
    vec_delta.push(Scalar.fromU64(BigInt(0)));
    const s_1 = Scalar.rand();
    const s_x = Scalar.rand();
    const vec_d_cmt = pedersen_ctxt.commit(r_d, vec_d);
    const vec_2 = Array.from({length: n - 1}, (_, i) => vec_d[i+1].mul(vec_delta[i]).neg());
    const cmt_2 = pedersen_ctxt.commit(s_1, vec_2);
    const vec_3 = Array.from({length: n - 1}, (_, i) => {
        const tmp = vec_a[i+1].mul(vec_delta[i]).add(vec_b[i].mul(vec_d[i+1]));
        return vec_delta[i+1].sub(tmp);
    });
    const cmt_3 = pedersen_ctxt.commit(s_x, vec_3);
    trx.appendGroupElement(vec_d_cmt);
    trx.appendGroupElement(cmt_2);
    trx.appendGroupElement(cmt_3);
    const x = trx.hashToScalar();
    const vec_a_tilde = Array.from({length: n}, (_, i) => vec_d[i].add(vec_a[i].mul(x)));
    const vec_b_tilde = Array.from({length: n}, (_, i) => vec_delta[i].add(vec_b[i].mul(x)));
    const r_tilde = x.mul(r).add(r_d);
    const s_tilde = x.mul(s_x).add(s_1);

    return new Proof(
        vec_d_cmt,
        cmt_2,
        cmt_3,
        vec_a_tilde,
        vec_b_tilde,
        r_tilde,
        s_tilde
    );
}
