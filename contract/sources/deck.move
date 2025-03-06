module contract_owner::deck {
    use std::option;
    use std::option::Option;
    use std::vector;
    use contract_owner::group;
    use contract_owner::encryption;

    struct UnblinderKey has copy, drop {
        draw_pile_idx: u64,
        src: address,
    }

    struct Deck has copy, drop, store {
        num_players: u64,
        card_ek: encryption::EncKey,
        ek_shares: vector<encryption::EncKey>,
        /// The group elemnts that represents [SA, S2..., SK, HA, H2, ..., HK, C1, ..., CK, D1, ..., DK].
        original_cards: vector<group::Element>,
        draw_pile: vector<encryption::Ciphertext>,
        /// `unblinders[i][j]` stores the unblinder for card `i` from player `j`.
        unblinders: vector<vector<Option<group::Element>>>,
        unblinder_counts: vector<u64>,
        /// For a publicly opened card at position `p` in the deck, store its value in `unblinded_values[p]`.
        ///
        /// More formally, if `unblinded_values[p] == t` for a t in `[0,52)`,
        /// we guarantee that `unblinders[p]` has all `n` entries (where `n` is the number of players),
        /// and decrypting `draw_pile[p]` results in `original_cards[t]`.
        unblinded_values: vector<u64>,
    }

    struct ShuffleProof has drop, store {}

    struct UnblinderProof has drop, store {}

    const STILL_BLINDED: u64 = 162827;

    public fun dummy_deck(): Deck {
        Deck {
            num_players: 0,
            card_ek: encryption::dummy_enc_key(),
            ek_shares: vector[],
            original_cards: vector[],
            draw_pile: vector[],
            unblinders: vector[],
            unblinder_counts: vector[],
            unblinded_values: vector[],
        }
    }

    public fun new(card_ek: encryption::EncKey, ek_shares: vector<encryption::EncKey>): (vector<u64>, Deck) {
        let num_players = vector::length(&ek_shares);
        let all_cards = vector::range(0, 52);
        let original_cards = vector::map(vector::range(0, 52), |_|group::rand_element());
        let draw_pile = vector::map(original_cards, |ptxt|encryption::enc(&card_ek, &group::zero_scalar(), &ptxt));
        let deck = Deck {
            num_players,
            card_ek,
            ek_shares,
            original_cards,
            draw_pile,
            unblinders: vector::map(vector::range(0, 52), |_|{
                vector::map(vector::range(0, num_players), |_|{
                    option::none()
                })
            }),
            unblinder_counts: vector::map(all_cards, |_|0),
            unblinded_values: vector::map(all_cards, |_|STILL_BLINDED),
        };
        (vector[], deck)
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    public fun shuffle(deck: &Deck): (vector<encryption::Ciphertext>, ShuffleProof) {
        let perm = aptos_framework::randomness::permutation(52);
        let new_draw_pile = vector::map(vector::range(0, 52), |new_idx| {
            let old_idx = *vector::borrow(&perm, new_idx);
            let old_ciphertext = vector::borrow(&deck.draw_pile, old_idx);
            let identity = group::group_identity();
            let r = group::rand_scalar();
            let diff = encryption::enc(&deck.card_ek, &r, &identity);
            encryption::ciphertext_add(old_ciphertext, &diff)
        });
        //TODO: real proof
        (new_draw_pile, ShuffleProof {})
    }

    public fun apply_shuffle(deck: &mut Deck, new_draw_pile: vector<encryption::Ciphertext>, _proof: ShuffleProof): vector<u64> {
        //TODO: verify the shuffle
        deck.draw_pile = new_draw_pile;
        vector[]
    }

    public fun add_unblinders(deck: &mut Deck, player_idx: u64, card_idx: u64, unblinder: group::Element, _proof: UnblinderProof): vector<u64> {
        //TODO: verify unblinder
        {
            let card_unblinders = vector::borrow_mut(&mut deck.unblinders, card_idx);
            let unblinder_slot = vector::borrow_mut(card_unblinders, player_idx);
            option::fill(unblinder_slot, unblinder);
        };
        let counter = vector::borrow_mut(&mut deck.unblinder_counts, card_idx);
        *counter = *counter + 1;
        if (*counter == deck.num_players) {
            let (_, _, c1) = encryption::unpack_ciphertext(vector::borrow(&deck.draw_pile, card_idx));
            let card_unblinders = vector::borrow(&mut deck.unblinders, card_idx);
            vector::for_each_ref(card_unblinders, |maybe_unblinder|{
                let unblinder = *option::borrow(maybe_unblinder);
                group::element_sub_assign(&mut c1, &unblinder);
            });
            let (found, card_value) = vector::index_of(&deck.original_cards, &c1);
            assert!(found, 164057);
            *vector::borrow_mut(&mut deck.unblinded_values, card_idx) = card_value;
        };
        vector[]
    }

    public native fun decode_shuffle_result(buf: vector<u8>): (vector<u64>, vector<encryption::Ciphertext>, vector<u8>);
    public native fun encode_shuffle_result(result: &vector<encryption::Ciphertext>): vector<u8>;
    public native fun decode_shuffle_proof(buf: vector<u8>): (vector<u64>, ShuffleProof, vector<u8>);
    public native fun encode_shuffle_proof(proof: &ShuffleProof): vector<u8>;
}