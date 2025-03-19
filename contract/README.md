## About this contract

This is an on-chain Poker implementation, where:
- a **host** creates a **Poker room** and defines the **players** allowed to join and play;
- players collaborate to shuffle/deal the cards in a decentralized manner (only using the chain as the broadcast channel).

## Run example

A move unit test `poker_room::example` is built to demonstrate an end-to-end usage.

Because of the complexity of this test case, it won't run with the official aptos-cli.
Use the following commands to build a special aptos-cli locally.
```bash
cd /tmp
git clone https://github.com/aptos-labs/aptos-core.git
cd /tmp/aptos-core
git checkout run_poker_ut
cargo run -p aptos
# Now the special aptos-cli is at `/tmp/aptos-core/target/debug/aptos`.
```

Now you can run the UT.
```bash
/tmp/aptos-core/target/debug/aptos move test --filter poker_room --gas-limit 999999999
```

## TODOs
- Decide the real DKG to use and implement it.
  - Currently, it is a naive DKG that produces n-out-of-n sharing.
- Design the penalty when the game is stuck.
- Involve on-chain assets?
- Implement the other cryptography TODOs.
- Implement poker hand ranking.
- Player/host action gas cost benchmarking and optimization.

## Implementation notes
TODO
