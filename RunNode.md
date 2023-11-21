# Run ICON Node With AWS KMS

#### I. Prerequisites
https://docs.icon.community/getting-started/how-to-run-a-validator-node

#### II. How to run node
1. Config wallet plugin
for arch arm please change the config to
```bash
GOLOOP_KEY_PLUGIN: "/goloop/config/wallet.so"
```
2. Import wallet to AWS KMS 
3. Update node config following configuration
```bash
GOLOOP_KEY_PLUGIN_OPTIONS: '{"region":"REGION","access_key_id":"ACCESS_KEY","secret_access_key":"SECRET_KEY","key_id":"KEY_ID"}'
```
4. Run node
```bash
docker compose up
```
