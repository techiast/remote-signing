#!/usr/bin/env node
const prompts = require('prompts')
const { handleGcpKms, } = require('./gcp-kms.js')
const { handleAwsKms, } = require('./aws-kms.js')
const { KMS_TYPE } = require('./constant.js')


function welcomeScreen() {
  console.log('\n-------------------------------------------------')
  console.log('Welcome to the Remote Sign with KMS Utility Script!')
  console.log('-------------------------------------------------\n')
}

async function selectKMSType() {
  const options = await prompts([
    {
      type: 'select',
      name: 'option',
      message: 'Choose an option:',
      choices: [
        { title: 'Google Cloud KMS', value: KMS_TYPE.GCP },
        { title: 'Amazon Web Service KMS', value: KMS_TYPE.AWS },
        { title: 'Exit', value: 'exit' }
      ]
    }
  ])

  switch (options.option) {
    case KMS_TYPE.GCP:
      await handleGcpKms(KMS_TYPE.GCP)
      break
    case KMS_TYPE.AWS:
      await handleAwsKms(KMS_TYPE.AWS)
      break
    case 'exit':
      console.log('Exiting the program. Goodbye!')
  }
}

(async () => {
  welcomeScreen()
  await selectKMSType()
}
)()
