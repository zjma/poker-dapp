rm -rf /tmp/poker-game
cp -r move-packages/poker-game /tmp/
sed -i '' 's/0x123/_/g' /tmp/poker-game/Move.toml
sed -i '' 's/0x234/_/g' /tmp/poker-game/Move.toml
aptos move create-resource-account-and-publish-package \
  --package-dir /tmp/poker-game \
  --named-addresses crypto_core=0xeb2ddd8af47156e6680e05a19977c9b42e199175a1e703954194db391e976dcd \
  --address-name poker_game \
  --seed $(openssl rand -hex 32) \
  --profile devnet-user0

