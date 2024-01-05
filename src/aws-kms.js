#!/usr/bin/env node
const path = require('path')
const prompts = require('prompts')
const asn1 = require('asn1.js')
const { execSync } = require('child_process')
const { sha3_256: sha3256 } = require('js-sha3')
const { KMSClient, CreateKeyCommand, GetParametersForImportCommand, ImportKeyMaterialCommand, GetPublicKeyCommand } = require('@aws-sdk/client-kms')
const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts')
const { readFileSync, writeFileSync } = require('fs')
const { convertEthPrivateKeyToDER, encryptPrivateKey, ensureTempFolderExists } = require('./utils.js')
const tempFolderPath = path.join(__dirname, 'temp')

let kms = {}
let sts = {}

let accessKeyId = ''
let secretAccessKey = ''
let region = ''

const policy = {
  Id: 'key-consolepolicy-3',
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'Enable IAM User Permissions',
      Effect: 'Allow',
      Principal: {
        AWS: 'arn:aws:iam::<accountId>:root'
      },
      Action: 'kms:*',
      Resource: '*'
    },
    {
      Sid: 'Allow access for Key Administrators',
      Effect: 'Allow',
      Principal: {
        AWS: '<user>'
      },
      Action: [
        'kms:Create*',
        'kms:Describe*',
        'kms:Enable*',
        'kms:List*',
        'kms:Put*',
        'kms:Update*',
        'kms:Revoke*',
        'kms:Disable*',
        'kms:Get*',
        'kms:Delete*',
        'kms:ImportKeyMaterial',
        'kms:TagResource',
        'kms:UntagResource',
        'kms:ScheduleKeyDeletion',
        'kms:CancelKeyDeletion'
      ],
      Resource: '*'
    },
    {
      Sid: 'Allow use of the key',
      Effect: 'Allow',
      Principal: {
        AWS: '<user>'
      },
      Action: [
        'kms:DescribeKey',
        'kms:GetPublicKey',
        'kms:Sign',
        'kms:Verify'
      ],
      Resource: '*'
    },
    {
      Sid: 'Allow attachment of persistent resources',
      Effect: 'Allow',
      Principal: {
        AWS: '<user>'
      },
      Action: [
        'kms:CreateGrant',
        'kms:ListGrants',
        'kms:RevokeGrant'
      ],
      Resource: '*',
      Condition: {
        Bool: {
          'kms:GrantIsForAWSResource': 'true'
        }
      }
    }
  ]
}

function welcomeScreen() {
  console.log('\n-------------------------------------------------')
  console.log('Welcome to the Remote Sign with AWS KMS Utility Script!')
  console.log('-------------------------------------------------\n')
}

async function setAccessKeys() {
  const response = await prompts([
    {
      type: 'password',
      name: 'accessKeyId',
      message: 'Enter your AWS access key ID:',
      initial: accessKeyId || 'Your access key'
    },
    {
      type: 'password',
      name: 'secretAccessKey',
      message: 'Enter your AWS secret access key:',
      initial: secretAccessKey || 'Your secret key'
    },
    {
      type: 'text',
      name: 'region',
      message: 'Enter the AWS region:',
      initial: 'ap-southeast-1'
    }
  ])

  if (!response.accessKeyId && !response.secretAccessKey && !response.region) {
    console.error('Missing required information')
  }
  accessKeyId = response.accessKeyId
  secretAccessKey = response.secretAccessKey
  region = response.region
}
async function getCallerIdentity() {
  const command = new GetCallerIdentityCommand({})
  try {
    const data = await sts.send(command)
    return data
  } catch (err) {
    console.error('\r Error getting caller identity:', err)
    throw err
  }
}

function rebuildKmsPolicy(identity) {
  const statements = policy.Statement
  for (let index = 0; index < statements.length; index++) {
    if (index !== 0) {
      statements[index].Principal.AWS = statements[index].Principal.AWS.replace('<user>', identity.Arn)
    }
    statements[index].Principal.AWS = statements[index].Principal.AWS.replace('<accountId>', identity.Account)
  }
  console.log('\r ✔ Rebuild KMS policy successful\n')
}

async function createAsymmetricKey() {
  const params = new CreateKeyCommand({
    KeyUsage: 'SIGN_VERIFY',
    CustomerMasterKeySpec: 'ECC_SECG_P256K1',
    Origin: 'EXTERNAL',
    MultiRegion: false,
    Policy: JSON.stringify(policy)
  })

  const result = await kms.send(params)
  return result.KeyMetadata.KeyId
}

async function getParamToImportKMSKey(kmsKeyId, wrappingAlgorithm = 'RSAES_OAEP_SHA_256', wrappingKeySpec = 'RSA_4096') {
  const params = new GetParametersForImportCommand({
    KeyId: kmsKeyId,
    WrappingAlgorithm: wrappingAlgorithm,
    WrappingKeySpec: wrappingKeySpec
  })
  const result = await kms.send(params)
  return { publicKey: result.PublicKey, importToken: result.ImportToken }
}

async function getPublicKey(keyId) {
  const params = new GetPublicKeyCommand({
    KeyId: keyId
  })
  const result = await kms.send(params)
  return result.PublicKey
}

async function importKeyToKMS(keyId) {
  const keyMaterial = readFileSync(path.join(tempFolderPath, 'EncryptedKeyMaterial.bin'))
  const importToken = readFileSync(path.join(tempFolderPath, 'ImportToken.bin'))

  const params = new ImportKeyMaterialCommand({
    KeyId: keyId,
    ImportToken: importToken,
    EncryptedKeyMaterial: keyMaterial,
    ExpirationModel: 'KEY_MATERIAL_DOES_NOT_EXPIRE'
  })

  await kms.send(params)
}

async function importKeyAwsKms() {
  const response = await prompts([
    {
      type: 'password',
      name: 'key',
      message: 'Enter the 32-byte raw private key in hex format:',
      initial: 'Your ICON private key'
    },
    {
      type: 'text',
      name: 'name',
      message: 'Enter KMS alias name',
      initial: 'wallet'
    }
  ])
  try {
    if (!response.key || !response.name) {
      throw new Error('Missing required information\n')
    }

    const indentity = await getCallerIdentity()

    rebuildKmsPolicy(indentity)

    // Create Asymmetric Key in KMS
    const keyId = await createAsymmetricKey(response.name)
    console.log('\r ✔ An KMS Asymmetric Key created with Id: ' + keyId + '\n')

    const data = await getParamToImportKMSKey(keyId)

    ensureTempFolderExists()
    writeFileSync(path.join(tempFolderPath, 'PublicKey.b64'), Buffer.from(data.publicKey).toString('base64'))
    console.log('\r ✔ PublicKey.b64 written in temp folder\n')

    execSync(`openssl enc -d -base64 -A -in ${path.join(tempFolderPath, 'PublicKey.b64')} -out ${path.join(tempFolderPath, 'WrappingPublicKey.bin')}`)
    console.log('\r ✔ WrappingPublicKey.bin created from PublicKey.b64\n')

    writeFileSync(path.join(tempFolderPath, 'ImportToken.b64'), Buffer.from(data.importToken).toString('base64'))
    console.log('\r ✔ ImportToken.b64 written in temp folder\n')

    execSync(`openssl enc -d -base64 -A -in ${path.join(tempFolderPath, 'ImportToken.b64')} -out ${path.join(tempFolderPath, 'ImportToken.bin')}`)
    console.log('\r ✔ ImportToken.bin created from ImportToken.b64\n')

    convertEthPrivateKeyToDER(response.key)
    encryptPrivateKey()
    await importKeyToKMS(keyId)

    console.log('\r ✔ Import your ICON wallet private key successful!!! \n')
  } catch (error) {
    console.error('\nError:', error.message + '\n')
  }
  await selectMenu()
}

const EcdsaPubKey = asn1.define('EcdsaPubKey', function () {
  this.seq().obj(
    this.seq().obj(
      this.objid(),
      this.objid()
    ),
    this.key('pubKey').bitstr()
  )
})

async function getWalletAddressAwsKms() {
  const response = await prompts([
    {
      type: 'text',
      name: 'kmsKey',
      message: 'Enter the kms key'
    }
  ])

  if (kms && accessKeyId && secretAccessKey && region && response.kmsKey) {
    const publicKey = await getPublicKey(response.kmsKey)
    const res = EcdsaPubKey.decode(Buffer.from(publicKey), 'der')
    let pubKeyBuffer = res.pubKey.data

    pubKeyBuffer = pubKeyBuffer.slice(1)
    // Convert the public key to hex using sha3_256
    const iconPublicKeySha3 = Buffer.from(sha3256.array(pubKeyBuffer).slice(-20))
    const iconAddress = 'hx' + iconPublicKeySha3.toString('hex')
    console.log('\n ==> ICON wallet address:', iconAddress + '\n')
  }
  await selectMenu()
}

async function selectMenu() {
  const options = await prompts([
    {
      type: 'select',
      name: 'option',
      message: 'Choose an option:',
      choices: [
        { title: 'Import Key', value: 'importKey' },
        { title: 'Get Wallet Address', value: 'getWalletAddress' },
        { title: 'Exit', value: 'exit' }
      ]
    }
  ])

  switch (options.option) {
    case 'importKey':
      await importKeyAwsKms()
      break
    case 'getWalletAddress':
      await getWalletAddressAwsKms()
      break
    case 'exit':
      console.log('Exiting the program. Goodbye!')
  }
}


async function handleAwsKms() {
  await welcomeScreen()
  await setAccessKeys()
  kms = new KMSClient({
    region,
    credentials: {
      accessKeyId,
      secretAccessKey
    }
  })

  sts = new STSClient({
    region,
    credentials: {
      accessKeyId,
      secretAccessKey
    }
  })
  await selectMenu()
}

module.exports = {
  handleAwsKms,
  getWalletAddressAwsKms,
  importKeyAwsKms
}