#NOTE: this should be copied from `deploy-crypto-core.sh` output, from a line like:
# `There is a Do you want to publish this package under the resource account's address 0xd209996a76fa1370bce1ff037bbe7ba3eefccd83ef1a9fddc53372367b3c4ed3? [yes/no] >`
CRYPTO_CORE_ADDR=0xd209996a76fa1370bce1ff037bbe7ba3eefccd83ef1a9fddc53372367b3c4ed3

rm -rf /tmp/poker-game
cp -r move-packages/poker-game /tmp/
sed -i '' 's/0x123/_/g' /tmp/poker-game/Move.toml
sed -i '' 's/0x234/_/g' /tmp/poker-game/Move.toml
aptos move create-resource-account-and-publish-package \
  --package-dir /tmp/poker-game \
  --named-addresses crypto_core=$CRYPTO_CORE_ADDR \
  --address-name poker_game \
  --seed $(openssl rand -hex 32) \

