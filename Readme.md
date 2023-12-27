# Demo to sign multiple ICON transactions with AWS KMS

## I. Prerequisites

### 1. Create KMS asymmetric key in AWS KMS
Create IAM account with access key and secret key with the permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:CreateAlias",
        "kms:CreateKey",
        "kms:DeleteAlias",
        "kms:Describe*",
        "kms:GenerateRandom",
        "kms:Get*",
        "kms:List*",
        "kms:TagResource",
        "kms:UntagResource",
        "iam:ListGroups",
        "iam:ListRoles",
        "iam:ListUsers"
      ],
      "Resource": "*"
    }
  ]
}
```

Make sure you already installed all dependencies by run:

```bash
yarn
# or
npm i
```


### 2. Import Private Key to KMS
Run the following command
```bash
yarn import:aws:key
# or
npm run import:aws:key
```
#### Screenshot for option `Import Key`

<img width="916" alt="Screenshot 2023-12-25 at 23 18 00" src="https://github.com/techiast/remote-signing/assets/116485607/33263071-d15f-40ce-811a-3b2668a98dcf">

#### Screenshot for option `Get Wallet Address`

<img width="534" alt="Screenshot 2023-12-25 at 23 18 27" src="https://github.com/techiast/remote-signing/assets/116485607/8b09a722-c9ac-4897-b84a-64102d938ec1">

## II. Configure environment variables
Install dependencies

```bash
npm i
#or
yarn
```

Create .env based on the .env.example file and fill your variables

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

##### Example:

```
ICON_ADDRESS_TO=hxcf3c97ceb9ee43b0bd1cf1aaecb988b1605af9d2
ICON_RPC_URL=https://berlin.net.solidwallet.io/api/v3
```
To run a simple demo
```bash
npm run test-kms
# or
yarn test-kms
```

## III. Perform stress test

- The test script was placed at: src/scripts/stress-test.js
- Replace with your ICON wallet private keys and send more ICX to these wallets. The purpose of the stress test script is push many transactions to blockchain and based on that your *Node* need to verify.
```js
main('${KEY-1}');
main('${KEY-2}');
main('${KEY-3}');
main('${KEY-4}');
```

Run command
```
yarn stress-test
# or
npm run stress-test
```
