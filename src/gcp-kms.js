/* eslint-disable no-undef */
const { KeyManagementServiceClient } = require('@google-cloud/kms');
const prompts = require('prompts')
const { writeFileSync, readFileSync } = require('fs')
const path = require('path')
const crc32c = require('fast-crc32c');
const asn1 = require('asn1.js')
const { execSync } = require('child_process')
const { sha3_256: sha3256 } = require('js-sha3');
const { encryptPrivateKey, convertEthPrivateKeyToDER, sleep, ensureTempFolderExists } = require('./utils');
const tempFolderPath = path.join(__dirname, 'temp')

let projectId = '';
let locationId = '';
let keyRingId = '';
let keyId = '';
let credentialsPath = '';
let versionId = '';
let client;
let versionName;


async function handleGcpKms() {
  if (!credentialsPath || !client) {
    let response = await prompts([{
      type: 'text',
      name: 'credentialsPath',
      message: 'Enter the path to your service account JSON key file:',
    }]);
    const gcpKey = loadServiceAccountKey(path.join(path.join(__dirname), '../' + response.credentialsPath))
    client = new KeyManagementServiceClient({
      credentials: gcpKey,
    });
  }
  await selectMenu();
}

function loadServiceAccountKey(path) {
  try {
    const content = readFileSync(path, 'utf8');
    return JSON.parse(content);
  } catch (err) {
    console.error('Error loading service account key file:', err);
    throw err;
  }
}


async function getUserInput() {
  let response = await prompts([
    {
      type: 'text',
      name: 'projectId',
      message: 'Enter your project ID:',
      initial: projectId || 'remote-sign-407206'
    },
    {
      type: 'text',
      name: 'locationId',
      message: 'Enter your location ID:',
      initial: locationId || 'asia-southeast1'
    },
    {
      type: 'text',
      name: 'keyRingId',
      message: 'Enter your key ring ID:',
      initial: keyRingId || 'remote-sign'
    },
    {
      type: 'text',
      name: 'keyId',
      message: 'Enter your key ID:',
      initial: keyId || 'remote-sign'
    },
    {
      type: 'text',
      name: 'versionId',
      message: 'Enter your version ID:',
      initial: versionId || '1'
    }
  ]);
  if (!response.projectId || !response.locationId || !response.keyRingId || !response.keyId || !response.versionId) {
    throw new Error('Missing required information\n')
  }

  projectId = response.projectId;
  locationId = response.locationId;
  keyRingId = response.keyRingId;
  keyId = response.keyId;
  versionId = response.versionId;

  versionName = client.cryptoKeyVersionPath(projectId, locationId, keyRingId, keyId, versionId);
  console.log(`\n ✔ Version Name: ${versionName}\n`)
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

async function getWalletAddressGcpKms() {
  await getUserInput();
  let pubKeyPem = await getPublicKey();
  getICONAddress(pubKeyPem);
  await selectMenu();
}


async function createKeyRing() {
  try {
    const locationName = client.locationPath(projectId, locationId);
    const [keyRing] = await client.createKeyRing({
      parent: locationName,
      keyRingId: keyRingId,
    });
    console.log(`\rCreated key ring: ${keyRing.name}`);
    return keyRing;
  } catch (error) {
    console.log(error.details + '\n');
    if (!error.details.includes('already exists')) {
      throw error
    }
    console.log('\r ===> Skip create Key Ring\n');
  }
}

async function createImportJob(keyRingName) {
  try {
    let [importJob] = await client.createImportJob({
      parent: keyRingName,
      importJobId: keyId,
      importJob: {
        protectionLevel: 'HSM',
        importMethod: 'RSA_OAEP_4096_SHA256',
      },
    });

    if (importJob.state.includes('PENDING'));
    await sleep(2000);

  } catch (error) {
    console.error(error.details);
    if (!error.details.includes('already exists')) {
      throw error
    }
    console.log('\r ===> Skip create Import Job\n');
  }

  [importJob] = await client.getImportJob({
    name: keyRingName + '/importJobs/' + keyId
  });
  return importJob.name
}


async function getPublicKey() {
  let [publicKey] = await client.getPublicKey({
    name: versionName,
  });

  if (publicKey.name !== versionName) {
    throw new Error('GetPublicKey: request corrupted in-transit');
  }
  if (crc32c.calculate(publicKey.pem) !== Number(publicKey.pemCrc32c.value)) {
    throw new Error('GetPublicKey: response corrupted in-transit');
  }

  return publicKey.pem;
}


function getICONAddress(publicKey) {
  console.log('\rStart to get KMS public key')

  let base64Key = publicKey.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\n)/g, '');
  let derKey = Buffer.from(base64Key, 'base64');
  let res = EcdsaPubKey.decode(derKey, 'der')
  let pubKeyBuffer = res.pubKey.data

  pubKeyBuffer = pubKeyBuffer.slice(1)

  // Convert the public key to hex using sha3_256
  let iconPublicKeySha3 = Buffer.from(sha3256.array(pubKeyBuffer).slice(-20))
  let iconAddress = 'hx' + iconPublicKeySha3.toString('hex')
  console.log('\r\n ===> ICON wallet address:', iconAddress + '\n')
}


function convertImportJobToWrappingPublicKey() {
  const command = `openssl rsa -in ${path.join(tempFolderPath, 'ImportJob.pem')} -pubin -outform DER -out ${path.join(tempFolderPath, 'WrappingPublicKey.bin')}`;
  try {
    execSync(command)
    console.log('\r ✔ WrappingPublicKey.bin created \n')
  } catch (err) {
    console.error('\rError converting Import Job to Warapping Public Key:', err)
    throw err
  }
}

async function importKeyGcpKms() {
  ensureTempFolderExists()
  await getUserInput();
  await createKeyRing();

  const response = await prompts([
    {
      type: 'text',
      name: 'privateKey',
      message: 'Enter your raw ICON private key:',
    },
  ])
  const privateKey = response.privateKey;

  const keyRingName = client.keyRingPath(projectId, locationId, keyRingId);
  // Construct the key name
  const keyName = client.cryptoKeyPath(projectId, locationId, keyRingId, keyId);
  // Generate an Elliptic Curve secp256k1 key
  const keyAlgorithm = 'EC_SIGN_SECP256K1_SHA256';

  const importJobName = await createImportJob(keyRingName)

  writeFileSync(path.join(tempFolderPath, 'ImportJob.pem'), Buffer.from(importJob.publicKey.pem).toString())
  console.log('\r ✔ ImportJob.pem written in temp folder\n')

  convertEthPrivateKeyToDER(privateKey)
  convertImportJobToWrappingPublicKey()
  encryptPrivateKey()

  const keyMaterial = readFileSync(path.join(tempFolderPath, 'EncryptedKeyMaterial.bin'))
  // Import the raw ETH private key
  const importRequest = {
    parent: keyName,
    algorithm: keyAlgorithm,
    importJob: importJobName,
    rsaAesWrappedKey: keyMaterial
  };

  const [importedKeyVersion] = await client.importCryptoKeyVersion(importRequest);
  console.log(`\r ✔ Imported a new Key with version: ${importedKeyVersion.name}`);

  if (importedKeyVersion.state.includes('PENDING'))
    await sleep(2000);

  const [cryptoKeyVersion] = await client.getCryptoKeyVersion({
    name: importedKeyVersion.name,
  });

  console.log(cryptoKeyVersion)


  console.log(`\r ✔ New Key Version ${cryptoKeyVersion.name} state: ${cryptoKeyVersion.state}`);
  await selectMenu();
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
      await importKeyGcpKms()
      break
    case 'getWalletAddress':
      await getWalletAddressGcpKms()
      break
    case 'exit':
      console.log('\rExiting the program. Goodbye!')
  }
}

module.exports = {
  handleGcpKms,
  getWalletAddressGcpKms,
  importKeyGcpKms
}