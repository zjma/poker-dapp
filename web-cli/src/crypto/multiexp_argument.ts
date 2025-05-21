import { Element, Scalar } from './group';
import { Transcript } from './fiat_shamir_transform';
import * as ElGamal from './elgamal';
import * as Pedersen from './pedersenCommitment';
import { Deserializer, Serializer } from '@aptos-labs/ts-sdk';

export class Proof {
    cmt_a0: Element;
    cmt_b0: Element;
    cmt_b1: Element;
    e_0: ElGamal.Ciphertext;
    e_1: ElGamal.Ciphertext;
    a_vec: Scalar[];
    r: Scalar;
    b: Scalar;
    s: Scalar;
    tau: Scalar;

    constructor(cmt_a0: Element, cmt_b0: Element, cmt_b1: Element, e_0: ElGamal.Ciphertext, e_1: ElGamal.Ciphertext, a_vec: Scalar[], r: Scalar, b: Scalar, s: Scalar, tau: Scalar) {
        this.cmt_a0 = cmt_a0;
        this.cmt_b0 = cmt_b0;
        this.cmt_b1 = cmt_b1;
        this.e_0 = e_0;
        this.e_1 = e_1;
        this.a_vec = a_vec;
        this.r = r;
        this.b = b;
        this.s = s;
        this.tau = tau;
    }

    static decode(deserializer: Deserializer): Proof {
        const cmt_a0 = Element.decode(deserializer);
        const cmt_b0 = Element.decode(deserializer);
        const cmt_b1 = Element.decode(deserializer);
        const e_0 = ElGamal.Ciphertext.decode(deserializer);
        const e_1 = ElGamal.Ciphertext.decode(deserializer);
        const a_vec = Array.from({length: deserializer.deserializeUleb128AsU32()}, (_) => Scalar.decode(deserializer));
        const r = Scalar.decode(deserializer);
        const b = Scalar.decode(deserializer);
        const s = Scalar.decode(deserializer);
        const tau = Scalar.decode(deserializer);
        return new Proof(cmt_a0, cmt_b0, cmt_b1, e_0, e_1, a_vec, r, b, s, tau);
    }

    encode(serializer: Serializer): void {
        this.cmt_a0.encode(serializer);
        this.cmt_b0.encode(serializer);
        this.cmt_b1.encode(serializer);
        this.e_0.encode(serializer);
        this.e_1.encode(serializer);
        serializer.serializeU32AsUleb128(this.a_vec.length);
        for (let i = 0; i < this.a_vec.length; i++) {
            this.a_vec[i].encode(serializer);
        }
        this.r.encode(serializer);
        this.b.encode(serializer);
        this.s.encode(serializer);
        this.tau.encode(serializer);
    }
}


export function prove(
    ek: ElGamal.EncKey,
    pedersen_ctxt: Pedersen.Context,
    trx: Transcript,
    vec_c: ElGamal.Ciphertext[],
    c: ElGamal.Ciphertext,
    vec_a_cmt: Element,
    vec_a: Scalar[],
    r: Scalar,
    rho: Scalar
): Proof {
    let n = vec_a.length;
    let vec_a_0 = Array.from({length: n}, (_) => Scalar.rand());
    let r_0 = Scalar.rand();
    let b_vec = [Scalar.rand(), Scalar.fromU64(BigInt(0))];
    let s_vec = [Scalar.rand(), Scalar.fromU64(BigInt(0))];
    let tau_vec = [Scalar.rand(), rho];
    let vec_a_0_cmt = pedersen_ctxt.commit(r_0, vec_a_0);
    let b_cmt_vec = Array.from({length: 2}, (_, k) => pedersen_ctxt.commit(s_vec[k], [b_vec[k]]));
    let e_vec = Array.from({length: 2}, (_, k) => {
        const msg = ek.encBase.scale(b_vec[k]);
        let chunk0 = ElGamal.enc(ek, tau_vec[k], msg);
        let chunk1 = k == 0 ? ElGamal.weirdMultiExp(vec_c, vec_a_0) : ElGamal.weirdMultiExp(vec_c, vec_a);
        return chunk0.add(chunk1);
    });
    trx.appendGroupElement(vec_a_0_cmt);
    trx.appendGroupElement(b_cmt_vec[0]);
    trx.appendRawBytes(e_vec[0].toBytes());
    trx.appendGroupElement(b_cmt_vec[1]);
    trx.appendRawBytes(e_vec[1].toBytes());
    const x = trx.hashToScalar();
    let a_out_vec = Array.from({length: n}, (_, i) => vec_a_0[i].add(vec_a[i].mul(x)));
    const r_out = r_0.add(r.mul(x));
    const b_out = b_vec[0].add(b_vec[1].mul(x));
    const s_out = s_vec[0].add(s_vec[1].mul(x));
    const tau_out = tau_vec[0].add(tau_vec[1].mul(x));
    return new Proof(
        vec_a_0_cmt,
        b_cmt_vec[0],
        b_cmt_vec[1],
        e_vec[0],
        e_vec[1],
        a_out_vec,
        r_out,
        b_out,
        s_out,
        tau_out
    );
}
