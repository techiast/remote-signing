# Demo signs an ICON transaction with AWS KMS

#### I. Prerequisites
1. Create KMS asymmetric key in AWS KMS
2. Key material imported to KMS

#### II. How to run
1. Install dependencies

```bash
npm i
#or
yarn
```
2. create .env bases on the .env.example file and fill your variables


```bash
# KMS Key id
KMS_KEY_ID=

# AWS config
AWS_REGION=
AWS_ACCESS_KEY=
AWS_SECRET_KEY=

# ICON config
ICON_ADDRESS_TO=
ICON_RPC_URL=
```

# example
```
ICON_ADDRESS_TO=hxcf3c97ceb9ee43b0bd1cf1aaecb988b1605af9d2
ICON_RPC_URL=https://berlin.net.solidwallet.io/api/v3
```

3. Run demo
```bash
npm test
# or
yarn test
```
