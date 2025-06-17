set -e
set -x
rm -rf /tmp/poker-game
cp -r move-packages/poker-game /tmp/
sed -i '' 's/0x123/_/g' /tmp/poker-game/Move.toml
sed -i '' 's/0x234/_/g' /tmp/poker-game/Move.toml
aptos move create-resource-account-and-publish-package \
  --package-dir /tmp/poker-game \
  --named-addresses crypto_core=0x378e6cca3f73cf78e7ec8046b91f6402b547678fe3eda777a21acfc4b77449eb \
  --address-name poker_game \
  --seed $(openssl rand -hex 32) \
  --profile devnet-user0

