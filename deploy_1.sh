rm -rf /tmp/crypto-core
cp -r move-packages/crypto-core /tmp/
sed -i '' 's/0x123/_/g' /tmp/crypto-core/Move.toml
aptos move create-resource-account-and-publish-package \
  --package-dir /tmp/crypto-core \
  --address-name crypto_core \
  --seed $(openssl rand -hex 32) \
  --profile devnet-user0
