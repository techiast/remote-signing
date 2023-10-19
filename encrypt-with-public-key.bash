# convert raw private key 32 bits to der file
echo 302e0201010420 <your_raw_private_key> a00706052b8104000a | xxd -r -p | openssl pkcs8 -topk8 -outform der -nocrypt > ECC_SECG_P256K1_PrivateKey.der
# encrypt private key der file with wrapping public key download from aws kms and o
OPENSSL pkeyutl \
    -encrypt \
    -in ECC_SECG_P256K1_PrivateKey.der \
    -out EncryptedKeyMaterial.bin \
    -inkey WrappingPublicKey.bin \
    -keyform DER \
    -pubin \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256