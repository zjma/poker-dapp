rm -rf /tmp/poker-game
cp -r move-packages/poker-game /tmp/
sed -i '' 's/0x123/_/g' /tmp/poker-game/Move.toml
sed -i '' 's/0x234/_/g' /tmp/poker-game/Move.toml
aptos move create-resource-account-and-publish-package \
  --package-dir /tmp/poker-game \
  --named-addresses crypto_core=0xfd20cef653ef1c17fb9f2a1a3d0510994baac0f2a1492a7b358730160d10c16d \
  --address-name poker_game \
  --seed $(openssl rand -hex 32) \
  --profile devnet-user0

