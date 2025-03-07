module contract_owner::deck {
    use std::bcs;
    use std::option;
    use std::option::Option;
    use std::signer::address_of;
    use std::string;
    use std::string::utf8;
    use std::vector;
    use aptos_std::crypto_algebra::add;
    use aptos_std::debug;
    use aptos_std::type_info;
    use contract_owner::dkg_v0;
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
        shuffle_contributors: vector<address>,
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
            shuffle_contributors: vector[],
            draw_pile: vector[],
            unblinders: vector[],
            unblinder_counts: vector[],
            unblinded_values: vector[],
        }
    }

    public fun dummy_proof(): ShuffleProof {
        ShuffleProof {}
    }

    #[lint::allow_unsafe_randomness]
    public fun new(shared_secret_public_info: dkg_v0::SharedSecretPublicInfo): (vector<u64>, Deck) {
        let (agg_ek, ek_shares) = dkg_v0::unpack_shared_secret_public_info(shared_secret_public_info);
        let num_players = vector::length(&ek_shares);
        let all_cards = vector::range(0, 52);
        let original_cards = vector::map(vector::range(0, 52), |_|group::rand_element());
        let draw_pile = vector::map(original_cards, |ptxt|encryption::enc(&agg_ek, &group::scalar_from_u64(0), &ptxt));
        let deck = Deck {
            num_players,
            card_ek: agg_ek,
            ek_shares,
            original_cards,
            shuffle_contributors: vector[],
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

    public fun has_shuffle_contribution_from(deck: &Deck, addr: address): bool {
        let (found, idx) = vector::index_of(&deck.shuffle_contributors, &addr);
        found
    }

    /// Client needs to implement this.
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

    public fun apply_shuffle(contributor: &signer, deck: &mut Deck, new_draw_pile: vector<encryption::Ciphertext>, _proof: ShuffleProof) {
        //TODO: verify the shuffle
        deck.draw_pile = new_draw_pile;
        vector::push_back(&mut deck.shuffle_contributors, address_of(contributor));
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

    public fun decode_shuffle_result(buf: vector<u8>): (vector<u64>, vector<encryption::Ciphertext>, vector<u8>) {
        let buf_len = vector::length(&buf);
        if (buf_len < 8) return (vector[123739], vector[], buf);
        let num_items = 0;
        vector::for_each(vector::range(0, 8), |idx|{
            let digit = (*vector::borrow(&buf, idx) as u64);
            num_items = num_items + (digit << ((idx as u8) * 8));
        });
        let buf = vector::slice(&buf, 8, buf_len);
        let ret = vector[];
        let i = 0;
        while (i < num_items) {
            let (errors, ciphertext, remainder) = encryption::decode_ciphertext(buf);
            if (!vector::is_empty(&errors)) {
                vector::push_back(&mut errors, 123740 + i);
                return (errors, vector[], remainder);
            };
            buf = remainder;
            vector::push_back(&mut ret, ciphertext);
            i = i + 1;
        };
        (vector[], ret, buf)
    }

    public fun encode_shuffle_result(obj: &vector<encryption::Ciphertext>): vector<u8> {
        let num_items = vector::length(obj);
        let buf = vector::map(vector::range(0, 8), |idx| {
            (((num_items >> ((8*idx) as u8)) & 0xff) as u8)
        });
        vector::for_each_ref(obj, |ciph|{
            vector::append(&mut buf, encryption::encode_ciphertext(ciph));
        });
        buf
    }

    public fun decode_shuffle_proof(buf: vector<u8>): (vector<u64>, ShuffleProof, vector<u8>) {
        let buf_len = vector::length(&buf);
        let header = *string::bytes(&type_info::type_name<ShuffleProof>());
        let header_len = vector::length(&header);
        if (buf_len < header_len) return (vector[124629], dummy_proof(), buf);
        if (header != vector::slice(&buf, 0, header_len)) return (vector[124630], dummy_proof(), buf);
        let buf = vector::slice(&buf, header_len, buf_len);
        (vector[], ShuffleProof {}, buf)
    }
    public fun encode_shuffle_proof(proof: &ShuffleProof): vector<u8> {
        let buf = *string::bytes(&type_info::type_name<ShuffleProof>());
        buf
    }
}