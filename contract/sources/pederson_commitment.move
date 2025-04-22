module contract_owner::pederson_commitment {
    use std::vector;
    use contract_owner::group;

    struct Context has copy, drop, store {
        bases: vector<group::Element>
    }

    public fun dummy_context(): Context {
        Context { bases: vector[] }
    }

    #[lint::allow_unsafe_randomness]
    public fun rand_context(n: u64): Context {
        Context {
            bases: vector::range(0, n + 1).map(|_| group::rand_element())
        }
    }

    /// NOTE: client needs to implement this.
    public fun vec_commit(
        context: &Context, randomizer: &group::Scalar, vec: &vector<group::Scalar>
    ): group::Element {
        let num_padding_zeros = context.bases.length() - 1
            - vec.length();
        let scalars = vector[*randomizer];
        scalars.append(*vec);
        scalars.append(vector::range(0, num_padding_zeros).map(|_| { group::scalar_from_u64(0) }));
        group::msm(&context.bases, &scalars)
    }
}
