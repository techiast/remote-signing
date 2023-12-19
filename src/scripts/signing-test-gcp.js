const { KeyManagementServiceClient } = require('@google-cloud/kms');
const { IconBuilder, IconConverter, IconUtil, IconAmount } = require('icon-sdk-js').default
const axios = require('axios')
const fs = require('fs')
const path = require('path')
const crc32c = require('fast-crc32c');
const crypto = require('crypto');
const asn1 = require('asn1.js')
const ethutil = require('ethereumjs-util')
const BN = require('bn.js')
const secp256k1 = require('secp256k1');
const { keccak256, sha3_256: sha3256 } = require('js-sha3')

// Google Cloud KMS configuration
const projectId = 'remote-sign-407206'
const locationId = 'asia-southeast1'
const keyRingId = 'remote-sign'
const keyName = 'remote-sign'
const keyId = 'remote-sign';
const versionId = '1';
const serviceAccountKeyPath = path.join(path.join(__dirname, './'), 'remote-sign-407206-8b50af709ec3.json')

// ICON transaction configuration
const ICON_ADDRESS_TO = process.env.ICON_ADDRESS_TO
const ICON_RPC_URL = process.env.ICON_RPC_URL || 'https://berlin.net.solidwallet.io/api/v3'

const ICON_TX_VALUE = IconConverter.toHex(IconAmount.of(1, IconAmount.Unit.ICX).toLoop())
const ICON_TX_NID = IconConverter.toHex(7)
const ICON_TX_STEP_LIMIT = IconConverter.toHex(100000)
const ICON_TX_NONCE = IconConverter.toHex(1)
const ICON_TX_VERSION = IconConverter.toHex(3)
const ICON_TX_TIMESTAMP = IconConverter.toHex((new Date()).getTime() * 1000)


// ICON transaction configuration
const nodeEndpoint = 'https://ctz.solidwallet.io/api/v3';


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
  const rBuffer = r
  const sBuffer = s

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
async function signWithKMS(dataToSign, versionName, client) {
  try {
    // Convert the data to Buffer if it's not already
    const dataBuffer = Buffer.from(dataToSign);

    // Create a digest of the message.
    const hash = crypto.createHash('sha256');
    hash.update(dataBuffer);
    const digest = hash.digest();

    // Optional but recommended: Compute digest's CRC32C.
    const digestCrc32c = crc32c.calculate(digest);

    // Sign the message with Cloud KMS
    const [signResponse] = await client.asymmetricSign({
      name: versionName,
      digest: {
        sha256: digest,
      },
      digestCrc32c: {
        value: digestCrc32c,
      },
    });

    // Optional, but recommended: perform integrity verification on signResponse.
    if (signResponse.name !== versionName) {
      throw new Error('AsymmetricSign: request corrupted in-transit');
    }
    if (!signResponse.verifiedDigestCrc32c) {
      throw new Error('AsymmetricSign: request corrupted in-transit');
    }
    if (
      crc32c.calculate(signResponse.signature) !==
      Number(signResponse.signatureCrc32c.value)
    ) {
      throw new Error('AsymmetricSign: response corrupted in-transit');
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
  const decoded = EcdsaSigAsnParse.decode(signature, 'der')
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

// Create ICON transaction after signing
async function createIconTransaction() {
  try {
    // Load the service account key
    const serviceAccountKey = await loadServiceAccountKey();

    const client = new KeyManagementServiceClient({ credentials: serviceAccountKey });

    // Build the version name
    const versionName = client.cryptoKeyVersionPath(projectId, locationId, keyRingId, keyId, versionId);

    // Create an ICON transaction (example: transfer 1 ICX from 'fromAddress' to 'toAddress')
    const iconTx = new IconBuilder.IcxTransactionBuilder()
      .to(ICON_ADDRESS_TO)
      .from('hxcc4de7edbe8a0d93b866c44b76a0ce080c193191')
      .value(ICON_TX_VALUE)
      .nid(ICON_TX_NID)
      .stepLimit(ICON_TX_STEP_LIMIT)
      .nonce(ICON_TX_NONCE)
      .version(ICON_TX_VERSION)
      .timestamp(ICON_TX_TIMESTAMP)
      .build()

    const dataToSign = JSON.stringify(iconTx);

    // Sign the data using Cloud KMS
    const iconTxHash = Buffer.from(IconUtil.makeTxHash(iconTx), 'hex')
    const signature = await signWithKMS(iconTxHash, versionName, client);

    // const sign = findICONSig(signature)
    // const recoveredPubAddr = findRightKey(iconTxHash, sign.r, sign.s, 'hxcc4de7edbe8a0d93b866c44b76a0ce080c193191')
    // const signatureRSV = Buffer.from(sign.r.toString(16) + sign.s.toString(16) + '0' + (recoveredPubAddr.v - 27).toString(16), 'hex').toString('base64')
    // const response = await sendSignedTransaction(iconTx, signatureRSV)

    // console.log('Transaction Hash:', response);
  } catch (err) {
     console.error('Error:', err);
  }
}

// Call the async function
createIconTransaction();
