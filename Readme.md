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
2. Update the variable
```js
const KEY_ID = "your kms key id";
const KMS = new AWS.KMS({
  region: 'your kms region',
  accessKeyId: 'your access key id',
  secretAccessKey: 'your secret access key'
});

// Icon transaction parameters
const ICON_TX_TO = "your wallet address";
const ICON_RPC_URL = 'icon rpc url';

// example
// const ICON_TX_TO = "hxcf3c97ceb9ee43b0bd1cf1aaecb988b1605af9d2";
// const ICON_RPC_URL = 'https://berlin.net.solidwallet.io/api/v3';

```
3. Run demo
```bash
npm start
# or
yarn start
```
