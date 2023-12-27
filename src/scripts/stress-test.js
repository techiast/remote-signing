const IconService = require("icon-sdk-js");
const { IconBuilder, IconConverter, IconWallet, IconAmount, HttpProvider,   SignedTransaction } = IconService.default;
// stress test key
// 07b773b8d06dee6e721c7be1aa9da5c7ef801fd9e48711088d893c02bf2f0fce

// Icon transaction parameters
const ICON_TX_TO = "hxcc4de7edbe8a0d93b866c44b76a0ce080c193191";
const ICON_RPC_URL = 'https://techteam.net.solidwallet.io/api/v3';

const ICON_TX_VALUE = IconConverter.toHex(IconAmount.of(0, IconAmount.Unit.ICX).toLoop())
const ICON_TX_NID = IconConverter.toHex(10);
const ICON_TX_STEP_LIMIT = IconConverter.toHex(100000);
const ICON_TX_NONCE = IconConverter.toHex(1);
const ICON_TX_VERSION = IconConverter.toHex(3);
const ICON_TX_TIMESTAMP = IconConverter.toHex((new Date()).getTime() * 1000);

async function main(key) {
    const walletLoadedByPrivateKey = IconWallet.loadPrivateKey(key);
    // Build the Icon transaction
    const httpProvider = new HttpProvider(ICON_RPC_URL);
    const iconService = new IconService.default(httpProvider);


    let nonce = 14
    for (let i = nonce; i < nonce + 1000; i++) {
        const iconTx = new IconBuilder.IcxTransactionBuilder()
            .to(ICON_TX_TO)
            .from(walletLoadedByPrivateKey.getAddress())
            .value(ICON_TX_VALUE)
            .nid(ICON_TX_NID)
            .stepLimit(ICON_TX_STEP_LIMIT)
            .nonce(IconConverter.toHex(i))
            .version(ICON_TX_VERSION)
            .timestamp(ICON_TX_TIMESTAMP)
            .build()


        const signedTx = new SignedTransaction(iconTx, walletLoadedByPrivateKey);
        try {
            const txHash = await iconService.sendTransaction(signedTx).execute();
            console.log(`TxHash: ${txHash}`);
        } catch (e) {
            console.log(e);
        }
    }
}

// Add your ICON wallet private key to here to push many transaction to blockchain

main('${KEY-1}');
main('${KEY-2}');
main('${KEY-3}');
main('${KEY-4}');
// add more key here