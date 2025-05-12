rm -rf /tmp/poker-game
cp -r move-packages/poker-game /tmp/
sed -i '' 's/0x123/_/g' /tmp/poker-game/Move.toml
sed -i '' 's/0x234/_/g' /tmp/poker-game/Move.toml
aptos move create-resource-account-and-publish-package \
  --package-dir /tmp/poker-game \
  --named-addresses crypto_core=0xec2e87adcc74601cb3c76a9c767638de75056e6d3bd7213c54ef2ac45902231f \
  --address-name poker_game \
  --seed $(openssl rand -hex 32) \
  --profile devnet-user0

