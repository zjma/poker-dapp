import { Element, Scalar } from './group';
import { Transcript } from './fiat_shamir_transform';
import * as ElGamal from './elgamal';
import * as Pedersen from './pedersenCommitment';
import * as MultiExpArgument from './multiexp_argument';
import * as ProductArgument from './product_argument';
import { Deserializer, Serializer } from '@aptos-labs/ts-sdk';

export class Proof {
    vec_a_cmt: Element;
    vec_b_cmt: Element;
    multiexp_proof: MultiExpArgument.Proof;
    product_proof: ProductArgument.Proof;

    constructor(vec_a_cmt: Element, vec_b_cmt: Element, multiexp_proof: MultiExpArgument.Proof, product_proof: ProductArgument.Proof) {
        this.vec_a_cmt = vec_a_cmt;
        this.vec_b_cmt = vec_b_cmt;
        this.multiexp_proof = multiexp_proof;
        this.product_proof = product_proof;
    }

    static decode(deserializer: Deserializer): Proof {
        const vec_a_cmt = Element.decode(deserializer);
        const vec_b_cmt = Element.decode(deserializer);
        const multiexp_proof = MultiExpArgument.Proof.decode(deserializer);
        const product_proof = ProductArgument.Proof.decode(deserializer);
        return new Proof(vec_a_cmt, vec_b_cmt, multiexp_proof, product_proof);
    }

    encode(serializer: Serializer): void {
        this.vec_a_cmt.encode(serializer);
        this.vec_b_cmt.encode(serializer);
        this.multiexp_proof.encode(serializer);
        this.product_proof.encode(serializer);
    }
}

function powersOfX(x: Scalar, n: number): Scalar[] {
    const ret = [x];
    for (let i = 1; i < n; i++) {
        const new_item = x.mul(ret[i - 1]);
        ret.push(new_item);
    };
    return ret;
}

export function prove(
    ek: ElGamal.EncKey,
    pedersenCtxt: Pedersen.Context,
    trx: Transcript,
    original: ElGamal.Ciphertext[],
    shuffled: ElGamal.Ciphertext[],
    permutation: number[],
    vec_rho: Scalar[],
): Proof {
    const n = original.length;
    const vec_a = permutation.map((v) => Scalar.fromU64(BigInt(v + 1)));
    const r = Scalar.rand();
    const vec_a_cmt = pedersenCtxt.commit(r, vec_a);
    trx.appendGroupElement(vec_a_cmt);
    const x = trx.hashToScalar();
    const x_powers = powersOfX(x, n);
    const vec_b = Array.from({length: n}, (_, i) => x_powers[permutation[i]]);
    const s = Scalar.rand();
    const vec_b_cmt = pedersenCtxt.commit(s, vec_b);
    trx.appendGroupElement(vec_b_cmt);
    const y = trx.hashToScalar();
    trx.appendRawBytes(new TextEncoder().encode('NUDGE'));
    const z = trx.hashToScalar();
    const neg_z = z.neg();
    const vec_neg_z = Array.from({length: n}, (_) => neg_z);
    const vec_neg_z_cmt = pedersenCtxt.commit(Scalar.fromU64(BigInt(0)), vec_neg_z);
    const vec_d_cmt = vec_a_cmt.scale(y).add(vec_b_cmt);
    const vec_d = Array.from({length: n}, (_, i) => y.mul(vec_a[i]).add(vec_b[i]));
    const t = y.mul(r).add(s);

    const tmp_vec = Array.from({length: n}, (_, i) => vec_d[i].sub(z));
    let tmp_product = Scalar.fromU64(BigInt(1));
    tmp_vec.forEach((v) => {
        tmp_product = tmp_product.mul(v);
    });
    const trx_branch = trx.clone();
    const product_proof =
        ProductArgument.prove(
            pedersenCtxt,
            trx_branch,
            n,
            vec_d_cmt.add(vec_neg_z_cmt),
            tmp_product,
            tmp_vec,
            t
        );

    let rho = Scalar.fromU64(BigInt(0));
    for (let i = 0; i < n; i++) {
        const new_item = vec_rho[i].mul(vec_b[i]);
        rho = rho.add(new_item);
    }
    const tmp_ciph = ElGamal.multiExp(original, x_powers);
    const multiexp_proof =
        MultiExpArgument.prove(
            ek,
            pedersenCtxt,
            trx,
            shuffled,
            tmp_ciph,
            vec_b_cmt,
            vec_b,
            s,
            rho.neg()
        );
    return new Proof(vec_a_cmt, vec_b_cmt, multiexp_proof, product_proof);
}
