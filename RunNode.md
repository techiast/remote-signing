# Run ICON Node With AWS KMS

#### I. Prerequisites
https://docs.icon.community/getting-started/how-to-run-a-validator-node

#### II. How to configure on a node
1. Copy the correct wallet.so file to your node config folder
- For AMD machine on AWS, please copy `wallet_amd.so`
- For other machines, please copy `wallet.so`
2. Import the node private key to AWS KMS 
3. Update docker configuration of your node to include the following options at environment variables:
```bash
GOLOOP_KEY_PLUGIN: "/goloop/config/wallet.so"
GOLOOP_KEY_PLUGIN_OPTIONS: '{"region":"REGION","access_key_id":"ACCESS_KEY","secret_access_key":"SECRET_KEY","key_id":"KEY_ID"}'
```
4. Run node
```bash
docker-compose up
```
5. Diagram 
![wallet-plugin-structure](https://github.com/techiast/remote-signing/assets/116485607/9b92b560-16b9-426e-96ef-dc72ee29ad87)

#### III. Docker compose example
```
version: "3"
services:
   prep:
      image: iconloop/icon2-node:v1.3.13 #iconloop/icon2-node:v1.3.11-dev  #iconloop/goloop-icon:v1.3.11
      container_name: "node"
      #network_mode: host
      restart: "on-failure"
      stdin_open: true
      environment:
         #SERVICE: ""  # MainNet, SejongNet  ## network type
         SERVICE: "TechTeamNet"
         IS_AUTOGEN_CERT: "true"
         GOLOOP_LOG_LEVEL: "debug" # trace, debug, info, warn, error, fatal, panic
         #KEY_STORE_FILENAME: "kms.json" # e.g. keystore.json read a config/keystore.json
         # e.g. "/goloop/config/keystore.json" read a "config/keystore.json" of host machine
         #KEY_PASSWORD: "gochain@123"
         #FASTEST_START: "true"    # It can be restored from latest Snapshot DB.
         #GOLOOP_KEY_SECRET: ""
         #GOLOOP_KEY_STORE: ""
         #GOLOOP_CONFIG: "/goloop/config/server.json"
         GOLOOP_KEY_PLUGIN: "/goloop/config/wallet.so"
         GOLOOP_KEY_PLUGIN_OPTIONS: '{"kms_type":"1","region":"ap-southeast-1","access_key_id":"UTYAVHWOFN7VMREB4LCH","secret_access_key":"ktccGoXXxvTesteMGCzJbfNJCFozi274094qhpjW","key_id":"f8464e92-7e46-84f2-29af-ea47dff78ef7"}'

         ROLE: 1 # Validator = 3, API Endpoint = 0

      cap_add:
         - SYS_TIME

      volumes:
         - ./data:/goloop/data # mount a data volumes
         - ./config:/goloop/config # mount a config volumes ,Put your used keystore file here.
         - ./logs:/goloop/logs
      ports:
         - 9000:9000
         - 7100:7100
```