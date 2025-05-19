rm -rf /tmp/poker-game
cp -r move-packages/poker-game /tmp/
sed -i '' 's/0x123/_/g' /tmp/poker-game/Move.toml
sed -i '' 's/0x234/_/g' /tmp/poker-game/Move.toml
aptos move create-resource-account-and-publish-package \
  --package-dir /tmp/poker-game \
  --named-addresses crypto_core=0xe859b7d58a7c7d961a9ab8ae3827cfcd904b054b5e7d16e22b5bdfda4b6bbe49 \
  --address-name poker_game \
  --seed $(openssl rand -hex 32) \
  --profile devnet-user0

