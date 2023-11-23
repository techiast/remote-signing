package main

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/remote-signing/wallet_plugin/address"
	crypto "github.com/remote-signing/wallet_plugin/key"
)

const awsKmsSignOperationMessageType = "DIGEST"
const awsKmsSignOperationSigningAlgorithm = "ECDSA_SHA_256"

var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

type asn1EcPublicKeyInfo struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

type asn1EcPublicKey struct {
	EcPublicKeyInfo asn1EcPublicKeyInfo
	PublicKey       asn1.BitString
}

type Wallet struct {
	//pk    *crypto.PrivateKey
	pkey  *crypto.PublicKey
	svc   *kms.Client
	keyId string
	addr  *address.Address
}

type asn1EcSig struct {
	R asn1.RawValue
	S asn1.RawValue
}

func (w Wallet) Address() address.IAddress {
	return w.addr
}

func (w Wallet) Sign(data []byte) ([]byte, error) {
	rBytes, sBytes, err := getSignatureFromKms(context.Background(), w.svc, w.keyId, data)
	if err != nil {
		return nil, err
	}

	// Adjust S value from signature according to Ethereum standard
	sBigInt := new(big.Int).SetBytes(sBytes)
	if sBigInt.Cmp(secp256k1halfN) > 0 {
		sBytes = new(big.Int).Sub(secp256k1N, sBigInt).Bytes()
	}

	signature, err := w.getEthereumSignature(data, rBytes, sBytes)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (w Wallet) getEthereumSignature(data []byte, r []byte, s []byte) ([]byte, error) {
	rsSignature := append(adjustSignatureLength(r), adjustSignatureLength(s)...)
	signature := append(rsSignature, []byte{0}...)
	// ParseSignatureVRS
	signatureInst, err := crypto.ParseSignature(signature)
	if err != nil {
		return nil, err
	}

	pubKeyFromSig, err := signatureInst.RecoverPublicKey(data)
	if err != nil || pubKeyFromSig.String() != w.pkey.String() {
		signature = append(rsSignature, []byte{1}...)
		signatureInst, err = crypto.ParseSignature(signature)
		if err != nil {
			return nil, err
		}

		pubKeyFromSig, err = signatureInst.RecoverPublicKey(data)
		if err != nil || pubKeyFromSig.String() != w.pkey.String() {
			return nil, errors.New("can not reconstruct public key from sig")
		}
	}

	return signature, nil
}

func (w Wallet) PublicKey() []byte {
	return w.pkey.SerializeCompressed()
}

// goloop entry here
func NewWallet(params map[string]string) (interface{}, error) {
	//var key *crypto.PrivateKey
	//// load key from input params
	//if _, ok := params["private_key"]; ok {
	//	keyBytes, err := hex.DecodeString(params["private_key"])
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//	key, err = crypto.ParsePrivateKey(keyBytes)
	//	if err != nil {
	//		return nil, err
	//	}
	//} else {
	//	key, _ = crypto.GenerateKeyPair()
	//}

	var region, accessKeyId, secretAccessKey, keyId string
	if _, ok := params["region"]; ok {
		region = params["region"]
	}

	if _, ok := params["access_key_id"]; ok {
		accessKeyId = params["access_key_id"]
	}

	if _, ok := params["secret_access_key"]; ok {
		secretAccessKey = params["secret_access_key"]
	}

	if _, ok := params["key_id"]; ok {
		keyId = params["key_id"]
	}

	if len(region)*len(accessKeyId)*len(secretAccessKey)*len(keyId) == 0 {
		return nil, errors.New("invalid inputs")
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	awsCfg.Region = region
	provider := aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID:     accessKeyId,
			SecretAccessKey: secretAccessKey,
		}, nil
	})
	awsCfg.Credentials = provider
	kmsSvc := kms.NewFromConfig(awsCfg)
	pubkeyFromAws, err := GetPubKeyCtx(context.Background(), kmsSvc, keyId)
	if err != nil {
		return nil, err
	}

	wallet := Wallet{
		svc:   kmsSvc,
		pkey:  pubkeyFromAws,
		keyId: keyId,
		addr:  NewAccountAddressFromPublicKey(pubkeyFromAws),
	}

	fmt.Printf("wallet address: %+v \n", wallet.addr.String())
	fmt.Printf("pubkey: %+v \n", wallet.pkey.SerializeCompressed())

	return wallet, nil
}

func getSignatureFromKms(
	ctx context.Context, svc *kms.Client, keyId string, txHashBytes []byte,
) ([]byte, []byte, error) {
	signInput := &kms.SignInput{
		KeyId:            aws.String(keyId),
		SigningAlgorithm: awsKmsSignOperationSigningAlgorithm,
		MessageType:      awsKmsSignOperationMessageType,
		Message:          txHashBytes,
	}

	signOutput, err := svc.Sign(ctx, signInput)
	if err != nil {
		return nil, nil, err
	}

	var sigAsn1 asn1EcSig
	_, err = asn1.Unmarshal(signOutput.Signature, &sigAsn1)
	if err != nil {
		return nil, nil, err
	}

	return sigAsn1.R.Bytes, sigAsn1.S.Bytes, nil
}

func GetPubKeyCtx(ctx context.Context, svc *kms.Client, keyId string) (*crypto.PublicKey, error) {
	pubKeyBytes, err := getPublicKeyDerBytesFromKMS(ctx, svc, keyId)
	if err != nil {
		return nil, err
	}

	pubkey, err := crypto.ParsePublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}

func NewAccountAddressFromPublicKey(pubKey *crypto.PublicKey) *address.Address {
	pk := pubKey.SerializeUncompressed()
	if pk == nil {
		fmt.Printf("FAIL invalid public key: %v \n", pubKey)
	}
	digest := crypto.SHA3Sum256(pk[1:])
	return address.NewAddress(digest[len(digest)-address.AddressIDBytes:])
}

func getPublicKeyDerBytesFromKMS(ctx context.Context, svc *kms.Client, keyId string) ([]byte, error) {
	getPubKeyOutput, err := svc.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyId),
	})
	if err != nil {
		return nil, err
	}

	var asn1pubk asn1EcPublicKey
	_, err = asn1.Unmarshal(getPubKeyOutput.PublicKey, &asn1pubk)
	if err != nil {
		return nil, err
	}

	return asn1pubk.PublicKey.Bytes, nil
}

func adjustSignatureLength(buffer []byte) []byte {
	buffer = bytes.TrimLeft(buffer, "\x00")
	for len(buffer) < 32 {
		zeroBuf := []byte{0}
		buffer = append(zeroBuf, buffer...)
	}
	return buffer
}
