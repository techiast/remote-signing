const path = require('path')
const { execSync } = require('child_process')
const { existsSync, mkdirSync } = require('fs')
const tempFolderPath = path.join(__dirname, 'temp')

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}


function convertEthPrivateKeyToDER(rawPrivateKey) {
  const command = `echo 302e0201010420${rawPrivateKey}a00706052b8104000a | xxd -r -p | openssl pkcs8 -topk8 -outform der -nocrypt > ${path.join(tempFolderPath, 'ECC_SECG_P256K1_PrivateKey.der')}`

  try {
    execSync(command)
    console.log('\r ✔ ECC_SECG_P256K1_PrivateKey.der created \n')
  } catch (err) {
    console.error('\rError converting ICON private key:', err)
    throw err
  }
}

function encryptPrivateKey() {
  const command = `openssl pkeyutl -encrypt -in ${path.join(tempFolderPath, 'ECC_SECG_P256K1_PrivateKey.der')} -out ${path.join(tempFolderPath, 'EncryptedKeyMaterial.bin')} -inkey ${path.join(tempFolderPath, 'WrappingPublicKey.bin')} -keyform DER -pubin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256`
  try {
    execSync(command)
    console.log('\r ✔ EncryptedKeyMaterial.bin created \n')
  } catch (err) {
    console.error('\rError converting Ethereum private key:', err)
    throw err
  }
}


function ensureTempFolderExists() {
  try {
    if (!existsSync(tempFolderPath)) {
      mkdirSync(tempFolderPath)
      console.log(`\r ✔ Temporary folder created at: ${tempFolderPath}\n`)
    }
  } catch (err) {
    console.error('Error creating temporary folder:', err + '\n')
    throw err
  }
}

module.exports = {
  convertEthPrivateKeyToDER,
  encryptPrivateKey,
  ensureTempFolderExists,
  sleep
}