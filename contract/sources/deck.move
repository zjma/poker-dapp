module contract_owner::deck {
    use std::signer::address_of;
    use std::string;
    use std::string::{utf8, String};
    use std::vector;
    use aptos_std::type_info;
    use contract_owner::encryption::Ciphertext;
    use contract_owner::dkg_v0;
    use contract_owner::group;
    use contract_owner::encryption;

    struct UnblinderKey has copy, drop {
        draw_pile_idx: u64,
        src: address,
    }

    struct Deck has copy, drop, store {
        num_players: u64,
        players: vector<address>,
        card_ek: encryption::EncKey,
        ek_shares: vector<encryption::EncKey>,
        /// The group elemnts that represents [SA, S2..., SK, HA, H2, ..., HK, DA, ..., DK, CA, ..., CK].
        plaintext_reprs: vector<group::Element>,
        shuffle_contributors: vector<address>,
        draw_pile: vector<encryption::Ciphertext>,
    }

    struct ShuffleProof has drop, store {}

    struct UnblinderProof has drop, store {}

    const STILL_BLINDED: u64 = 162827;

    public fun dummy_deck(): Deck {
        Deck {
            num_players: 0,
            players: vector[],
            card_ek: encryption::dummy_enc_key(),
            ek_shares: vector[],
            plaintext_reprs: vector[],
            shuffle_contributors: vector[],
            draw_pile: vector[],
        }
    }

    public fun dummy_proof(): ShuffleProof {
        ShuffleProof {}
    }

    #[lint::allow_unsafe_randomness]
    public fun new(players: vector<address>, shared_secret_public_info: dkg_v0::SharedSecretPublicInfo): (vector<u64>, Deck) {
        let num_players = vector::length(&players);
        let (agg_ek, ek_shares) = dkg_v0::unpack_shared_secret_public_info(shared_secret_public_info);
        assert!(num_players == vector::length(&ek_shares), 135421);
        let plaintext_reprs = vector::map(vector::range(0, 52), |_|group::rand_element());
        let draw_pile = vector::map(plaintext_reprs, |ptxt|encryption::enc(&agg_ek, &group::scalar_from_u64(0), &ptxt));
        let deck = Deck {
            num_players,
            players,
            card_ek: agg_ek,
            ek_shares,
            plaintext_reprs,
            shuffle_contributors: vector[],
            draw_pile,
        };
        (vector[], deck)
    }

    public fun has_shuffle_contribution_from(deck: &Deck, addr: address): bool {
        let (found, idx) = vector::index_of(&deck.shuffle_contributors, &addr);
        found
    }

    public fun get_card_ciphertext(deck: &Deck, idx: u64): Ciphertext {
        *vector::borrow(&deck.draw_pile, idx)
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

    const SUITE_TEXTS: vector<vector<u8>> = vector[b"S", b"H", b"D", b"C"];
    const NUMBER_TEXTS: vector<vector<u8>> = vector[b"__A", b"__2", b"__3", b"__4", b"__5", b"__6", b"__7", b"__8", b"__9", b"_10", b"__J", b"__Q", b"__K"];
    public fun get_card_text(card_val: u64): String {
        let suite = card_val / 13;
        let number = card_val % 13;
        let ret = *vector::borrow(&SUITE_TEXTS, suite);
        vector::append(&mut ret, *vector::borrow(&NUMBER_TEXTS, number));
        utf8(ret)
    }

    public fun get_card_val(deck: &Deck, card_repr: &group::Element): (bool, u64) {
        vector::index_of(&deck.plaintext_reprs, card_repr)
    }

    public fun card_reprs(deck: &Deck): vector<group::Element> {
        deck.plaintext_reprs
    }
}
