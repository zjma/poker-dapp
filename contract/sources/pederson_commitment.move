module contract_owner::pederson_commitment {
    use std::vector;
    use contract_owner::group;

    struct Context has drop {
        bases: vector<group::Element>,
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    public fun rand_context(n: u64): Context {
        Context {
            bases: vector::map(vector::range(0, n+1), |idx|{ group::rand_element()}),
        }
    }

    public fun vec_commit(context: &Context, randomizer: &group::Scalar, vec: &vector<group::Scalar>): group::Element {
        let num_padding_zeros = vector::length(&context.bases) - 1 - vector::length(vec);
        let scalars = vector[*randomizer];
        vector::append(&mut scalars, *vec);
        vector::append(&mut scalars, vector::map(vector::range(0, num_padding_zeros), |_|{ group::scalar_from_u64(0)}));
        group::msm(&context.bases, &scalars)
    }
}
