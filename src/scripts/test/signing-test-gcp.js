const { KeyManagementServiceClient } = require('@google-cloud/kms');
const { IconBuilder, IconConverter, IconUtil, IconAmount } = require('icon-sdk-js').default
const axios = require('axios')
const fs = require('fs')
const path = require('path')
const crc32c = require('fast-crc32c');
const asn1 = require('asn1.js')
const ethutil = require('ethereumjs-util')
const BN = require('bn.js')
const { keccak256, sha3_256: sha3256 } = require('js-sha3')

// Google Cloud KMS configuration
const projectId = process.env.PROJECT_ID || 'remote-sign-407206'
const locationId = process.env.LOCATION_ID || 'asia-southeast1'
const keyRingId = process.env.KEY_RING_ID || 'remote-sign'
const keyId = process.env.KEY_ID || 'remote-sign';
const versionId = process.env.VERSION_ID || '1';
const serviceAccountKeyPath = path.join(path.join(__dirname, '../../../'), process.env.JSON_CREDENTIAL_PATH || 'remote-sign-407206-8b50af709ec3.json');

// ICON transaction configuration
const ICON_ADDRESS_TO = process.env.ICON_ADDRESS_TO
const ICON_RPC_URL = process.env.ICON_RPC_URL || 'https://berlin.net.solidwallet.io/api/v3'

const ICON_TX_VALUE = IconConverter.toHex(IconAmount.of(1, IconAmount.Unit.ICX).toLoop())
const ICON_TX_NID = IconConverter.toHex(7)
const ICON_TX_STEP_LIMIT = IconConverter.toHex(100000)
const ICON_TX_NONCE = IconConverter.toHex(1)
const ICON_TX_VERSION = IconConverter.toHex(3)
const ICON_TX_TIMESTAMP = IconConverter.toHex((new Date()).getTime() * 1000)


const EcdsaSigAsnParse = asn1.define('EcdsaSig', function () {
  this.seq().obj(
    this.key('r').int(),
    this.key('s').int()
  )
})

const EcdsaPubKey = asn1.define('EcdsaPubKey', function () {
  this.seq().obj(
    this.seq().obj(
      this.objid(),
      this.objid()
    ),
    this.key('pubKey').bitstr()
  )
})

function recoverPubKeyFromSig(msg, r, s, v) {
  const rBuffer = r.toBuffer();
  const sBuffer = s.toBuffer();


  const pubKey = ethutil.ecrecover(msg, v, rBuffer, sBuffer)
  const addrBuf = Buffer.from(sha3256.array(pubKey).slice(-20))
  const recoveredICONAddr = 'hx' + addrBuf.toString('hex')

  return recoveredICONAddr
}


// Load the service account JSON key file
async function loadServiceAccountKey() {
  try {
    const content = fs.readFileSync(serviceAccountKeyPath, 'utf8');
    return JSON.parse(content);
  } catch (err) {
    console.error('Error loading service account key file:', err);
    throw err;
  }
}

// Sign data using Google Cloud KMS
async function signWithKMS(digestBuffer, versionName, client) {
  try {
    // Create a digest of the message.
    // const hash = crypto.createHash('sha256');
    // hash.update(digestBuffer);
    // const digest = hash.digest();
    // Sign the message with Cloud KMS

    const [signResponse] = await client.asymmetricSign({
      name: versionName,
      digest: {
        sha256: digestBuffer,
      },
    });

    // Optional, but recommended: perform integrity verification on signResponse.
    if (signResponse.name !== versionName) {
      throw new Error('AsymmetricSign: request corrupted in-transit');
    }
    // Example of how to display signature. Encode the output before printing.
    const encoded = signResponse.signature.toString('base64');
    console.log(`Signature: ${encoded}`);

    return signResponse.signature;
  } catch (err) {
    console.error('Error signing data with Cloud KMS:', err);
    throw err;
  }
}

async function sendSignedTransaction(iconTx, signature) {
  const axiosConfig = {
    method: 'POST',
    url: ICON_RPC_URL,
    data: {
      jsonrpc: '2.0',
      method: 'icx_sendTransaction',
      params: {
        ...iconTx,
        signature
      },
      id: 1234
    }
  }
  const response = await axios(axiosConfig)
  return response?.data
}

function findRightKey(msg, r, s, expectedICONAddr) {
  let v = 27
  let pubKey = recoverPubKeyFromSig(msg, r, s, v)
  if (pubKey !== expectedICONAddr) {
    v = 28
    pubKey = recoverPubKeyFromSig(msg, r, s, v)
  }
  console.log('signature v:', v)
  console.log('Recovered ICON Address from tx hash and signature:', pubKey)
  return { pubKey, v }
}

function findICONSig(signature) {
  if (signature === undefined) {
    throw new Error('Signature is undefined.')
  }
  const decoded = EcdsaSigAsnParse.decode(Buffer.from(signature, 'base64'), 'der')
  const r = decoded.r
  let s = decoded.s
  const secp256k1N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)
  const secp256k1halfN = secp256k1N.div(new BN(2))
  if (s.gt(secp256k1halfN)) {
    s = secp256k1N.sub(s)
    return { r, s }
  }
  console.log('signature r:', r.toString('hex'))
  console.log('signature s:', s.toString('hex'))
  return { r, s }
}

function getICONAddress(publicKey) {
  console.log('Start to get KMS public key')

  const base64Key = publicKey.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\n)/g, '');
  const derKey = Buffer.from(base64Key, 'base64');

  const res = EcdsaPubKey.decode(derKey, 'der')
  let pubKeyBuffer = res.pubKey.data
  pubKeyBuffer = pubKeyBuffer.slice(1)

  // Convert the public key to hex using sha3_256
  const iconPublicKeySha3 = Buffer.from(sha3256.array(pubKeyBuffer).slice(-20))

  // Convert the public key to hex using keccak256
  const iconPublicKeyKeccak = Buffer.from(keccak256.array(pubKeyBuffer).slice(-20))

  const iconAddress = 'hx' + iconPublicKeySha3.toString('hex')
  const ethAddress = '0x' + iconPublicKeyKeccak.toString('hex')
  console.log('ICON Public Key (sha3_256):', iconAddress)
  console.log('ICON Public Key (keccak256):', ethAddress)
  return iconAddress
}

async function getPublicKey(client, versionName) {
  const [publicKey] = await client.getPublicKey({
    name: versionName,
  });

  // Optional, but recommended: perform integrity verification on publicKey.
  // For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
  // https://cloud.google.com/kms/docs/data-integrity-guidelines
  if (publicKey.name !== versionName) {
    throw new Error('GetPublicKey: request corrupted in-transit');
  }
  if (crc32c.calculate(publicKey.pem) !== Number(publicKey.pemCrc32c.value)) {
    throw new Error('GetPublicKey: response corrupted in-transit');
  }

  console.log(`Public key pem: ${publicKey.pem}`);

  return publicKey.pem;
}

// Create ICON transaction after signing
async function createIconTransaction() {
  try {
    // Load the service account key
    const serviceAccountKey = await loadServiceAccountKey();

    const client = new KeyManagementServiceClient({ credentials: serviceAccountKey });

    // // Build the version name
    const versionName = client.cryptoKeyVersionPath(projectId, locationId, keyRingId, keyId, versionId);

    const publicKeyPem = await getPublicKey(client, versionName);

    const iconAddress = getICONAddress(publicKeyPem);

    // Create an ICON transaction (example: transfer 1 ICX from 'fromAddress' to 'toAddress')
    const iconTx = new IconBuilder.IcxTransactionBuilder()
      .to(ICON_ADDRESS_TO)
      .from(iconAddress)
      .value(ICON_TX_VALUE)
      .nid(ICON_TX_NID)
      .stepLimit(ICON_TX_STEP_LIMIT)
      .nonce(ICON_TX_NONCE)
      .version(ICON_TX_VERSION)
      .timestamp(ICON_TX_TIMESTAMP)
      .build()

    const digestBuffer = Buffer.from(IconUtil.makeTxHash(iconTx), 'hex')

    const signature = await signWithKMS(digestBuffer, versionName, client);


    const sign = findICONSig(signature.toString('base64'));
    const recoveredPubAddr = findRightKey(digestBuffer, sign.r, sign.s, iconAddress)
    const signatureRSV = Buffer.from(sign.r.toString(16) + sign.s.toString(16) + '0' + (recoveredPubAddr.v - 27).toString(16), 'hex').toString('base64')
    const response = await sendSignedTransaction(iconTx, signatureRSV)

    console.log('Transaction Hash:', response);
  } catch (err) {
    console.error('Error:', err);
  }
}

// Call the async function
createIconTransaction();
