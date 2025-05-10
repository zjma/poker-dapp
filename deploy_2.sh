rm -rf /tmp/poker-game
cp -r move-packages/poker-game /tmp/
sed -i '' 's/0x123/_/g' /tmp/poker-game/Move.toml
sed -i '' 's/0x234/_/g' /tmp/poker-game/Move.toml
aptos move create-resource-account-and-publish-package \
  --package-dir /tmp/poker-game \
  --named-addresses crypto_core=0xb6d648a558352f346b9274264264e67dbde2c17d28214917d1b0e97a1bc5aa35 \
  --address-name poker_game \
  --seed $(openssl rand -hex 32) \
  --profile devnet-user0

