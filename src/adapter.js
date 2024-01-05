const prompts = require('prompts')
const { getWalletAddressGcpKms, importKeyGcpKms } = require('./gcp-kms.js')
const { getWalletAddressAwsKms, importKeyAwsKms } = require('./aws-kms.js')
const { KMS_TYPE } = require('./constant.js')

async function selectMenu(kmsType) {
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
      await importKey(kmsType)
      break
    case 'getWalletAddress':
      await getWalletAddress(kmsType)
      break
    case 'exit':
      console.log('Exiting the program. Goodbye!')
  }
}



async function importKey(kmsType) {
  switch (kmsType) {
    case KMS_TYPE.GCP:
      await importKeyGcpKms();
      break;
    case KMS_TYPE.AWS:
      await importKeyAwsKms();
      break;
    default:
      break;
  }
}

async function getWalletAddress(kmsType) {
  switch (kmsType) {
    case KMS_TYPE.GCP:
      await getWalletAddressGcpKms();
      break;
    case KMS_TYPE.AWS:
      await getWalletAddressAwsKms();
      break;
    default:
      break;
  }

  await selectMenu(kmsType)
}
module.exports = {
  selectMenu,
  importKey,
  getWalletAddress,
}