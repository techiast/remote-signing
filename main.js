const { IconBuilder, IconConverter, IconUtil, IconAmount } = require('icon-sdk-js').default;
const { createHash } = require('crypto');
const AWS = require('aws-sdk');
const elliptic = require('elliptic');
const axios = require('axios');
const asn1 = require('asn1.js');
const ethutil = require('ethereumjs-util');
const BN = require('bn.js');
const { keccak256, sha3_256: sha3256 } = require('js-sha3');

// AWS KMS
const KEY_ID = "KMS_KEY_ID";
const KMS = new AWS.KMS({
  region: 'your kms region',
  accessKeyId: 'your access key',
  secretAccessKey: 'your secret access key'
});

// Icon transaction parameters
const ICON_TX_TO = "to icon address";
const ICON_RPC_URL = 'https://berlin.net.solidwallet.io/api/v3';

const ICON_TX_VALUE = IconConverter.toHex(IconAmount.of(1, IconAmount.Unit.ICX).toLoop())
const ICON_TX_NID = IconConverter.toHex(7);
const ICON_TX_STEP_LIMIT = IconConverter.toHex(100000);
const ICON_TX_NONCE = IconConverter.toHex(1);
const ICON_TX_VERSION = IconConverter.toHex(3);
const ICON_TX_TIMESTAMP = IconConverter.toHex((new Date()).getTime() * 1000);


const EcdsaSigAsnParse = asn1.define('EcdsaSig', function () {
  this.seq().obj(
    this.key('r').int(),
    this.key('s').int(),
  );
});

const EcdsaPubKey = asn1.define('EcdsaPubKey', function () {
  this.seq().obj(
    this.seq().obj(
      this.objid(),
      this.objid(),
    ),
    this.key('pubKey').bitstr()
  );
});


function findICONSig(signData) {
  if (signData.Signature == undefined) {
    throw new Error('Signature is undefined.');
  }
  let decoded = EcdsaSigAsnParse.decode(signData.Signature, 'der');
  let r = decoded.r;
  let s = decoded.s;
  let secp256k1N = new BN("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
  let secp256k1halfN = secp256k1N.div(new BN(2));
  if (s.gt(secp256k1halfN)) {
    s = secp256k1N.sub(s);
    return { r, s }
  }
  console.log('signature r:', r.toString('hex'));
  console.log('signature s:', s.toString('hex'));
  return { r, s }
}

function recoverPubKeyFromSig(msg, r, s, v) {
  const rBuffer = r.toBuffer();
  const sBuffer = s.toBuffer();

  const pubKey = ethutil.ecrecover(msg, v, rBuffer, sBuffer);
  const addrBuf = Buffer.from(sha3256.array(pubKey).slice(-20));
  const recoveredICONAddr = "hx" + addrBuf.toString('hex');

  return recoveredICONAddr;
}


function findRightKey(msg, r, s, expectedICONAddr) {
  let v = 27;
  let pubKey = recoverPubKeyFromSig(msg, r, s, v);
  if (pubKey != expectedICONAddr) {
    v = 28;
    pubKey = recoverPubKeyFromSig(msg, r, s, v)
  }
  console.log('signature v:', v);
  console.log('Recovered ICON Address from tx hash and signature:', pubKey);
  return { pubKey, v };
}

// Sign the Icon transaction hash with AWS KMS
async function signTransaction(iconTxHash) {
  const signParams = {
    KeyId: KEY_ID,
    Message: iconTxHash,
    SigningAlgorithm: "ECDSA_SHA_256",
    MessageType: "DIGEST",
  };
  const signResponse = await KMS.sign(signParams).promise();
  return signResponse;
}

// Get address from KMS
async function getAddress() {
  console.log('Start to get KMS public key');

  const data = await KMS.getPublicKey({ KeyId: KEY_ID }).promise();

  console.log('KMS public key:', data.PublicKey.toString('hex'))

  let res = EcdsaPubKey.decode(data.PublicKey, 'der');
  let pubKeyBuffer = res.pubKey.data;
  pubKeyBuffer = pubKeyBuffer.slice(1);

  // Convert the public key to hex using sha3_256
  const iconPublicKeySha3 = Buffer.from(sha3256.array(pubKeyBuffer).slice(-20));

  // Convert the public key to hex using keccak256
  const iconPublicKeyKeccak = Buffer.from(keccak256.array(pubKeyBuffer).slice(-20));

  const iconAddress = "hx" + iconPublicKeySha3.toString('hex');
  const ethAddress = "0x" + iconPublicKeyKeccak.toString('hex')
  console.log('ICON Public Key (sha3_256):', iconAddress);
  console.log('ICON Public Key (keccak256):', ethAddress);
  return iconAddress;
}


// Send the Icon signed transaction
async function sendSignedTransaction(iconTx, signature) {
  const axiosConfig = {
    method: "POST",
    url: ICON_RPC_URL,
    data: {
      jsonrpc: "2.0",
      method: "icx_sendTransaction",
      params: {
        ...iconTx,
        signature
      },
      id: 1234,
    },
  }
  const response = await axios(axiosConfig);
  return response?.data;
}

async function main() {
  const iconAddress = await getAddress();
  // Build the Icon transaction
  const iconTx = new IconBuilder.IcxTransactionBuilder()
    .to(ICON_TX_TO)
    .from(iconAddress)
    .value(ICON_TX_VALUE)
    .nid(ICON_TX_NID)
    .stepLimit(ICON_TX_STEP_LIMIT)
    .nonce(ICON_TX_NONCE)
    .version(ICON_TX_VERSION)
    .timestamp(ICON_TX_TIMESTAMP)
    .build()

  // Serialize the Icon transaction
  const iconTxHash = Buffer.from(IconUtil.makeTxHash(iconTx), 'hex');
  const signature = await signTransaction(iconTxHash);
  const sign = findICONSig(signature);
  const recoveredPubAddr = findRightKey(iconTxHash, sign.r, sign.s, iconAddress);
  const signatureRSV = Buffer.from(sign.r.toString(16) + sign.s.toString(16) + '0' + (recoveredPubAddr.v - 27).toString(16), 'hex').toString('base64')
  const response = await sendSignedTransaction(iconTx, signatureRSV);

  console.log(JSON.stringify(response));
}

main();