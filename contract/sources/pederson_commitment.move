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
            bases: vector::map(
                vector::range(0, n + 1),
                |_| group::rand_element()
            )
        }
    }

    /// NOTE: client needs to implement this.
    public fun vec_commit(
        context: &Context, randomizer: &group::Scalar, vec: &vector<group::Scalar>
    ): group::Element {
        let num_padding_zeros = vector::length(&context.bases) - 1
            - vector::length(vec);
        let scalars = vector[*randomizer];
        vector::append(&mut scalars, *vec);
        vector::append(
            &mut scalars,
            vector::map(
                vector::range(0, num_padding_zeros),
                |_| { group::scalar_from_u64(0) }
            )
        );
        group::msm(&context.bases, &scalars)
    }
}
