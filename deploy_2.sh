set -e
set -x
rm -rf /tmp/poker-game
cp -r move-packages/poker-game /tmp/
sed -i '' 's/0x123/_/g' /tmp/poker-game/Move.toml
sed -i '' 's/0x234/_/g' /tmp/poker-game/Move.toml
aptos move create-resource-account-and-publish-package \
  --package-dir /tmp/poker-game \
  --named-addresses crypto_core=0x4bbd81cdda9d9d2d016ece603b1d81ebdc9d221cc50b9ed1db5c3c51e7e32cc4 \
  --address-name poker_game \
  --seed $(openssl rand -hex 32) \
  --profile devnet-user0

