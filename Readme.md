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
2. Create .env bases on the .env.example file and fill your variables


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

3. Run demo
```bash
npm run test-kms
# or
yarn test-kms
```


# Create AWS KMS and import your raw ICON private key to AWS KMS
### Prerequisites:
- Create IAM account with access key and secret key with the permissions:
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
- Make sure you already installed all dependencies by run:
```bash
yarn
# or
npm i
```
### Run cli tool:
```bash
yarn import:aws:key
# or
npm run import:aws:key
```
### Demo:
#### For option `Import Key`
<img width="916" alt="Screenshot 2023-12-25 at 23 18 00" src="https://github.com/techiast/remote-signing/assets/116485607/33263071-d15f-40ce-811a-3b2668a98dcf">

#### For option `Get Wallet Address`
<img width="534" alt="Screenshot 2023-12-25 at 23 18 27" src="https://github.com/techiast/remote-signing/assets/116485607/8b09a722-c9ac-4897-b84a-64102d938ec1">

