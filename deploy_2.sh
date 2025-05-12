rm -rf /tmp/poker-game
cp -r move-packages/poker-game /tmp/
sed -i '' 's/0x123/_/g' /tmp/poker-game/Move.toml
sed -i '' 's/0x234/_/g' /tmp/poker-game/Move.toml
aptos move create-resource-account-and-publish-package \
  --package-dir /tmp/poker-game \
  --named-addresses crypto_core=0x9e348542462bc22d2ccdbaf7b093b5f4697e6cd9e731b4ff77986b00bc4a36ae \
  --address-name poker_game \
  --seed $(openssl rand -hex 32) \
  --profile devnet-user0

