## Real time limits at contract level
Currently, every time-limited user action is given a 999999999-second time limit.

Ideally there should be a per-action countdown happens first,
followed by a per-player cumulative countdown.

## DKG v1
`crypto-core/dkg_v0.move` is a naive n-out-of-n DKG,
which means even just 1 accidental player disconnection will make the current hand unplayable.

We probably need a real t-out-of-n DKG so we can better tolerate accidental disconnections.

## deckgen with multi-round shuffle
Function `crypto_core::shuffle::process_contribution()` when working with 52 cards and a full BG12 proof,
costs more 1000+ gas units which exceeds the single transaction execution limit (920 gas units).

The BG12 proof is current skipped.
A better mitigation is probably to do multiple shuffle in one deckgen.
A rough idea would be to:
- divide the deck into 2 halves;
- verifiably shuffle the 1st half and the 2nd half;
- use on-chain randomness to pick 13 from the 1st half and 13 from the 2nd half, and exchange them;
- verifiably shuffle the 1st half and the 2nd half.


## Enforce all cryptographic proof verifications
The cryptographic proof verifications are currently optional for prototyping.
They should eventually be mandatory.
Blocked by [deckgen with multi-round shuffle](#deckgen-with-multi-round-shuffle).
