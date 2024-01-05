# Demo to sign multiple ICON transactions with AWS KMS

## I. Prerequisites

### 1. Create IAM account
#### Amazon Web Service
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

#### Google Cloud Platform
Create IAM account with the permission as image below and download your JSON
<img width="547" alt="Screenshot 2024-01-05 at 11 20 37" src="https://github.com/techiast/remote-signing/assets/116485607/9e020662-2b10-43bb-9c46-dcab9e4fb659">


***Note:** To create JSON Credential (Key) please follow the menu (IAM & Admin > Service Account > Create Service Account)*

#### Install Node dependencies packages

**Version:**

- *node:* >= v20.10.0
- *npm:* >= 10.2.3
- *yarn:* >= 1.22.19

Make sure you already installed all dependencies by run:

```bash
yarn
# or
npm i
```


## 2. Run CLI tool to import Private Key to KMS
Run the following command
```bash
yarn cli:run
# or
npm run cli:run
```
<img width="452" alt="Screenshot 2024-01-05 at 11 28 40" src="https://github.com/techiast/remote-signing/assets/116485607/1bbf078a-f4e6-479e-8ea7-21d402edd58e">


#### Screenshot for option `Import Key`
<img width="916" alt="Screenshot 2023-12-25 at 23 18 00" src="https://github.com/techiast/remote-signing/assets/116485607/a67d0efa-7199-453f-bdf8-68dd6491bcd3">


#### Screenshot for option `Get Wallet Address`

<img width="534" alt="Screenshot 2023-12-25 at 23 18 27" src="https://github.com/techiast/remote-signing/assets/116485607/8b09a722-c9ac-4897-b84a-64102d938ec1">

## II. Configure environment variables for testing
The purpose of this is to send ICX to another ICON wallet address using KMS to sign.

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

# GCP config
PROJECT_ID=
LOCATION_ID=
KEY_RING_ID=
KEY_ID=
VERSION_ID=
# copy your json credential file to root folder and leave the name of it here
JSON_CREDENTIAL_PATH=

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
npm run test-aws
npm run test-gcp
# or
yarn test-aws
yarn test-gcp
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
