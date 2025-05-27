## Protocol-level architecture of the Poker dApp 

The proposed Poker dapp can be described in terms of multiple layers of protocols,
presented below from the lowest to the highest level.

All protocols leverage the blockchain as a broadcast channel,
which is assumed the only way for the users to communicate with each other.

### Naive n-out-of-n DKG
In this protocol, a group of users joinly generates a random scalar `s` such that:
- no individual learns the value of `s`;
- The group element `s*G` is publicly known, where group element `G` is a public parameter;
- `s` is secret-shared among the participants:
  - user `i` privately holds the `i`-th share, denoted by `s(i)`, which itself is a scalar;
  - anyone with access to all shares can reconstruct `s`.

NOTE: we may soon migrate to a t-out-of-n secret instead of the current n-out-of-n secret.

The caller initializes a DKG with following on-chain states:
- a list of allowed participants;
- a deadline;
- some other parameters that can be randomly generated using on-chain randomness.

Then, concurrently, participants each:
- fetches the parameters;
- locally generates their own DKG contribution;
- sends a transaction to publish the contribution on chain.

At the end, anyone can send a transaction to:
- mark the DKG as succeeded;
- conclude the generation of `s` and make `s*G` available on chain.

If one or more users didn't submit a valid contribution before the deadline, anyone can send a transaction to:
- mark the DKG as failed;
- report the culprits to the caller.

Reference implementation: [move-packages/crypto-core/sources/dkg_v0.move](https://github.com/zjma/poker-dapp/blob/main/move-packages/crypto-core/sources/dkg_v0.move).

### Shuffle
In this protocol, a group of users joinly shuffles a list of [ElGamal](https://en.wikipedia.org/wiki/ElGamal_encryption) ciphertexts,
which are independently encrypted by the same publicly known encryption key `ek`.

The caller initializes a shuffle with the following on-chain parameters.
- An ordered list of allowed contributors.
- Deadlines for every contributor.
- The ElGamal encryption key `ek`.
- The original ciphertexts.

Next, the contributors take turns to:
- fetch the current ciphertexts on chain;
- sample a random permutation privately;
- apply the permutation to the ciphertexts, re-randomize each ciphertext independently;
- generate a [BG12](http://www0.cs.ucl.ac.uk/staff/J.Groth/MinimalShuffle.pdf) verifiable shuffle proof;
- send a transaction to publish the permuted and re-randomized ciphertexts along with a BG12 proof;

In the end, anyone can send a transaction to:
- mark the shuffle as succeeded;
- report the final ciphertext list back to the caller.

If it is someone's turn but they didn't submit a valid contribution before their deadline, anyone can send a transaction to:
- mark the shuffle as failed;
- report the culprit to the caller.

Reference implementation: [move-packages/crypto-core/shuffle.move](https://github.com/zjma/poker-dapp/blob/main/move-packages/crypto-core/sources/shuffle.move).

### Threshold scalar multiplication
In this protocol, a group of users has previously shared a secret scalar `s`,
and now collaboratively compute `s*P` for a group element `P` without revealing `s`.

NOTE: called "threshold" since we may soon migrate to a t-out-of-n secret instead of the current n-out-of-n secret.

The caller initializes a scalar multiplication as follows.
- On-chain state: the group element `P` to be raised.
- On-chain state: the public information of the shared secret scalar `s`.
- Private state assumed: participants `i` has the `i`-th share of the secret `s`.

Then, concurrently, users each:
- computes `s(i)*P` locally and generate a proof of correct computation;
- publish `s(i)*P` and the proof on chain.

In the end, anyone can send a transaction to:
- mark the operation as succeeded;
- conclude the computation and make `s*P` available on chain.

If one or more users didn't submit a valid contribution in time, anyone can send a transaction to:
- mark the operation as failed;
- report the culprits to the caller.

Reference implementation: [move-packages/crypto-core/threshold_scalar_mul.move](https://github.com/zjma/poker-dapp/blob/main/move-packages/crypto-core/sources/threshold_scalar_mul.move).

### Private card dealing
In this protocol, a group of users has previously shared a secret scalar `s`,
and now collaborate with a target user to transform a card encrypted against `s` such that:
the target can decrypt the card, but no one else can.

The caller initializes a private card dealing as follows.
- On-chain states:
  - the public info of `s` (including the "public key" `s*G`);
  - the encrypted card;
  - the address of the target user;
  - sub-operation deadlines;
- Private states of user `i`:
  - the `i`-th share of `s`.

Recall the ElGamal ciphertext is in the form `(C0 = r*H, C1 = r*s*H+P)`, where `P` is the plaintext card representation.

First, the target user:
- uses random scalars `r', s'` to transform the card ciphertext to `(C0' = (r+r')*H, C1' = (r+r')*(s+s')*P)`...
  - effectively the same plaintext encrypted against a new secret `s + s'` with a new randomizer `r + r'`;
- computes a proof that the above step is performed correctly;
- send a transaction to publish the new ciphertext with the proof.

Next, the secret sharing group runs a threshold scalar multiplication protocol to compute an `s*C0'`.

Then, the target user can reveal `P` as `C1' - s*C0' - u*C0'`.

if the target user didn't provide a valid transformation in time, or the threshold scalar multiplication failed,
anyone can send a transaction to:
- mark this private dealing as failed;
- report the culprits to the caller.

Reference implementation: [move-packages/crypto-core/reencryption.move](https://github.com/zjma/poker-dapp/blob/main/move-packages/crypto-core/sources/reencryption.move).

### Public card opening
In this protocol, a group of users has previously shared a secret scalar `s`,
and now collaborates to publicly open a card encrypted against `s`.

The caller initializes a public card opening as follows.
- On-chain states:
    - the public info of `s` (including the "public key" `s*G`);
    - the encrypted card;
    - the deadlines;
- Private states of user `i`:
    - the `i`-th share of `s`.

Recall the ElGamal ciphertext is in the form `(C0 = r*H, C1 = r*s*H+P)`, where `P` is the plaintext card representation.
The group simply runs a threshold scalar multiplication protocol to compute `s * C0`,
and `P` can then be derived trivially as `C1 - s * C0`.

If the threshold scalar multiplication failed, anyone can send a transaction to:
- mark this public card opening as failed;
- report the culprit info to the caller.

### The hand protocol

In this protocol, `n` players have previously shared a secret scalar `s`,
the 52 cards have been encrypted against `s` and shuffled,
now they play an actual poker hand with it.

The caller initializes a hand as follows.
- On-chain states:
    - the player list, and their chips in hand;
    - the public info of the secret `s`;
    - the encrypted and shuffled deck;
    - any other necessary hand configurations, e.g., player betting time limits.
- Player `i` private states:
    - the `i`-th share of `s`.

Then the regular poker logic follows, utilizing the protocols introduced above.
- `2*n` private dealing protocols run concurrently to privately deal the `2*i`-th card and the `2*i+1`-th to the `i`-th player.
- Players place their pre-flop bets.
- If necessary, 3 public opening protocols run concurrently to deal the flop.
- Players place their post-flop bets.
- If necessary, 1 public opening protocol runs to deal the turn.
- Players place their post-turn bets.
- If necessary, 1 public opening protocol runs to deal the river.
- Players place their final bets.
- If necessary, a showdown is triggered, where players concurrently reveal their hands.
- At the end, anyone can send a transaction to conclude the gains & losses of this hand, available for the caller to read.


If any private dealing protocols/public opening protocols failed, the hand became unplayable.
Anyone can send a transaction to:
- mark the hand as failed;
- declare the hand void, bets returned;
- report the culprits to the caller.

If it is someone's turn to bet/reveal cards in showdown but they failed to act correctly in time, they are automatically folded.

Reference implementation: [move-packages/game-specific/hand.move](https://github.com/zjma/poker-dapp/blob/main/move-packages/game-specific/sources/hand.move).

### The poker room protocol

In this protocol, a **host** creates a poker room on chain, then `n` **players** join to play poker in a tournament-like setting.

The host sends a transaction to initialize a poker room with:
- a list of addresses of the players allowed to join;
- any other necessary game configurations (e.g., small blind/big blind ratios).

Once the room is created, any allowed player sends a transaction to join the poker room,
together with any tournament setting specific to this player (e.g, an `AptosCoin` whose amount represents the player's starting chips).

Once all players joined:
- (A) a secret `s` is generated and shared between all currently alive and connected players (via the DKG protocol)...
  - alive: having 1+ chips;
  - connected: a flag indicating if the player is online and following the protocol correctly;
- the deck for the 0-th hand is shuffled and encrypted against the secret `s` (via the shuffle protocol);
- the 0th hand is played (via the hand protocol), meanwhile the deck for the 1-th hand is shuffled and encrypted against the secret `s`;
- wait for both hand 0 and shuffle 1 to finish, then start hand 1 and shuffle 2 simultaneously;
- wait for both hand 1 and shuffle 2 to finish, then start hand 2 and shuffle 3 simultaneously;
- ...
- if a player's chips in hand reaches 0 after some hand, this player is eliminated...
  - if we still have 2+ players alive and connected, go back to (A);
  - otherwise, the tournament is done, and anyone can send a transaction to distribute the prizes to the winner.

Initially, every player has `connected` flag set to 1.
In case when a hand/shuffle failed, the culprits are temporarily kicked out of the room by setting their `connected` flag to 0.
and the poker room control has to jump back to (A) so the following games won't be affected by the culprits.
The culprits are allowed to rejoin, which:
- resets their `connected` flag to 1;
- triggers a poker room control jump to (A), once the current hand succeeds/fails.

To prevent malicious players from interfering the tournament indefinitely, any player misbehavior needs to be penalized.
The penalization mechanism needs more thinking and discussion (and requires input from the real players too).
Here is an initial design:
- if a player misbehaved in a hand, all their chips are burned (immediate elimination).
- if a player misbehaved in a shuffle, `ceil(max(starting_chips, current_chips)/3)+1` chips from their hand are burned...
  - So if someone misbehaved 3 times, an elimination is guaranteed;

That said, players may occasionally experience short-term connectivity issues that are accidental and unintentional,
and there is no way to differentiate it from malicious misbehaviors.
To tolerate such situations, the following timeout mechanism (not yet implemented) may help:
- initially, every player is granted `x` minutes of extra operation time as a buffer;
- when a player exceeds the initial deadline for any action in any protocol, the buffer begins to deplete;
- an action is considered timeout only if the actioner's buffer fully exhausted.

Reference implementation: [move-packages/game-specific/poker_room.move](https://github.com/zjma/poker-dapp/blob/main/move-packages/game-specific/sources/poker_room.move).
