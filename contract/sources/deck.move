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
    use contract_owner::fiat_shamir_transform;
    use contract_owner::encryption::Ciphertext;
    use contract_owner::sigma_dlog_eq;
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
        /// The group elemnts that represents [SA, S2..., SK, HA, H2, ..., HK, C1, ..., CK, D1, ..., DK].
        original_cards: vector<group::Element>,
        shuffle_contributors: vector<address>,
        draw_pile: vector<encryption::Ciphertext>,
        /// `unblinders[i][j]` stores the unblinder for card `i` from player `j`.
        decryption_shares: vector<vector<Option<group::Element>>>,
        decryption_share_counts: vector<u64>,
        /// For a publicly opened card at position `p` in the deck, store its value in `unblinded_values[p]`.
        ///
        /// More formally, if `unblinded_values[p] == t` for a t in `[0,52)`,
        /// we guarantee that `unblinders[p]` has all `n` entries (where `n` is the number of players),
        /// and decrypting `draw_pile[p]` results in `original_cards[t]`.
        decrypted_values: vector<u64>,
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
            original_cards: vector[],
            shuffle_contributors: vector[],
            draw_pile: vector[],
            decryption_shares: vector[],
            decryption_share_counts: vector[],
            decrypted_values: vector[],
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
        let all_cards = vector::range(0, 52);
        let original_cards = vector::map(vector::range(0, 52), |_|group::rand_element());
        let draw_pile = vector::map(original_cards, |ptxt|encryption::enc(&agg_ek, &group::scalar_from_u64(0), &ptxt));
        let deck = Deck {
            num_players,
            players,
            card_ek: agg_ek,
            ek_shares,
            original_cards,
            shuffle_contributors: vector[],
            draw_pile,
            decryption_shares: vector::map(vector::range(0, 52), |_|{
                vector::map(vector::range(0, num_players), |_|{
                    option::none()
                })
            }),
            decryption_share_counts: vector::map(all_cards, |_|0),
            decrypted_values: vector::map(all_cards, |_|STILL_BLINDED),
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

    public fun add_unblinders(deck: &mut Deck, player_idx: u64, card_idx: u64, unblinder: group::Element, _proof: UnblinderProof): vector<u64> {
        //TODO: verify unblinder
        {
            let card_unblinders = vector::borrow_mut(&mut deck.decryption_shares, card_idx);
            let unblinder_slot = vector::borrow_mut(card_unblinders, player_idx);
            option::fill(unblinder_slot, unblinder);
        };
        let counter = vector::borrow_mut(&mut deck.decryption_share_counts, card_idx);
        *counter = *counter + 1;
        if (*counter == deck.num_players) {
            let (_, _, c1) = encryption::unpack_ciphertext(*vector::borrow(&deck.draw_pile, card_idx));
            let card_unblinders = vector::borrow(&mut deck.decryption_shares, card_idx);
            vector::for_each_ref(card_unblinders, |maybe_unblinder|{
                let unblinder = *option::borrow(maybe_unblinder);
                group::element_sub_assign(&mut c1, &unblinder);
            });
            let (found, card_value) = vector::index_of(&deck.original_cards, &c1);
            assert!(found, 164057);
            *vector::borrow_mut(&mut deck.decrypted_values, card_idx) = card_value;
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

    public fun dummy_decryption_share(): VerifiableDecryptionShare {
        VerifiableDecryptionShare {
            decryption_share: group::dummy_element(),
            proof: sigma_dlog_eq::dummy_proof(),
        }
    }

    public fun encode_decryption_share(share: &VerifiableDecryptionShare): vector<u8> {
        let buf = *string::bytes(&type_info::type_name<VerifiableDecryptionShare>());
        vector::append(&mut buf, group::encode_element(&share.decryption_share));
        vector::append(&mut buf, sigma_dlog_eq::encode_proof(&share.proof));
        buf
    }

    public fun decode_decryption_share(buf: vector<u8>): (vector<u64>, VerifiableDecryptionShare, vector<u8>) {
        let buf_len = vector::length(&buf);
        let header = *string::bytes(&type_info::type_name<VerifiableDecryptionShare>());
        let header_len = vector::length(&header);
        if (buf_len < header_len) return (vector[125105], dummy_decryption_share(), buf);
        if (header != vector::slice(&buf, 0, header_len)) return (vector[125106], dummy_decryption_share(), buf);
        let buf = vector::slice(&buf, header_len, buf_len);
        let (errors, share, buf) = group::decode_element(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 125107);
            return (errors, dummy_decryption_share(), buf);
        };
        let (errors, proof, buf) = sigma_dlog_eq::decode_proof(buf);
        if (!vector::is_empty(&errors)) {
            vector::push_back(&mut errors, 125108);
            return (errors, dummy_decryption_share(), buf);
        };
        let ret = VerifiableDecryptionShare { decryption_share: share, proof };
        (vector[], ret, buf)
    }

    public fun process_decryption_share(player: &signer, deck: &mut Deck, card_idx: u64, share: VerifiableDecryptionShare) {
        let player_addr = address_of(player);
        let (player_found, player_idx) = vector::index_of(&deck.players, &player_addr);
        assert!(player_found, 133908);
        let (enc_base, c_0, _) = encryption::unpack_ciphertext(*vector::borrow(&deck.draw_pile, card_idx));
        let (_, ek_share) = encryption::unpack_enc_key(*vector::borrow(&deck.ek_shares, player_idx));
        let VerifiableDecryptionShare { decryption_share: decryption_share, proof } = share;
        let valid = sigma_dlog_eq::verify(&mut fiat_shamir_transform::new_transcript(), &enc_base, &ek_share, &c_0, &decryption_share, &proof);
        assert!(valid, 133909);

        // Save the share.
        let share_holders = vector::borrow_mut(&mut deck.decryption_shares, card_idx);
        let share_holder = vector::borrow_mut(share_holders, player_idx);
        option::fill(share_holder, decryption_share);

        // Update the dec share counter for the card.
        let counter = vector::borrow_mut(&mut deck.decryption_share_counts, card_idx);
        *counter = *counter + 1;
    }

    #[lint::allow_unsafe_randomness]
    #[test_only]
    public fun compute_card_decryption_share(player: &signer, deck: &Deck, card_idx: u64, dk_share: &dkg_v0::SecretShare): VerifiableDecryptionShare {
        let player_addr = address_of(player);
        let (player_found, player_idx) = vector::index_of(&deck.players, &player_addr);
        assert!(player_found, 123349);

        let card_ciph = *vector::borrow(&deck.draw_pile, card_idx);
        let (enc_base, c_0, _) = encryption::unpack_ciphertext(card_ciph);
        let (_, ek_share) = encryption::unpack_enc_key(*vector::borrow(&deck.ek_shares, player_idx));
        let secret_share = dkg_v0::unpack_secret_share(*dk_share);
        let decryption_share = group::scale_element(&c_0, &secret_share);
        let proof = sigma_dlog_eq::prove(&mut fiat_shamir_transform::new_transcript(), &enc_base, &ek_share, &c_0, &decryption_share, &secret_share);
        VerifiableDecryptionShare { decryption_share, proof }
    }

    public fun get_decryption_share(deck: &Deck, card_idx: u64, player: address): Option<group::Element> {
        let (player_found, player_idx) = vector::index_of(&deck.players, &player);
        assert!(player_found, 143107);
        let share_holders = vector::borrow(&deck.decryption_shares, card_idx);
        *vector::borrow(share_holders, player_idx)
    }

    struct VerifiableDecryptionShare has drop {
        decryption_share: group::Element,
        proof: sigma_dlog_eq::Proof,
    }
}