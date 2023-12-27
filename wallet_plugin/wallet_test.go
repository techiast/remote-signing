package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func TestWalletImport(t *testing.T) {
	params := make(map[string]string)
	params["kms_type"] = AWS
	params["region"] = os.Getenv("REGION")
	params["access_key_id"] = os.Getenv("ACCESS_KEY_ID")
	params["secret_access_key"] = os.Getenv("SECRET_ACCESS_KEY")
	params["key_id"] = os.Getenv("KEY_ID")

	iWallet, err := NewWallet(params)
	if err != nil {
		panic(err)
	}
	walletInst := iWallet.(Wallet)
	signData, _ := hex.DecodeString("356355dae4212533ce182cbb31492a6c2665fcf8f17e089d929e7a3efd1d1ba1")
	signature, err := walletInst.Sign(signData)
	if err != nil {
		panic(err)
	}

	fmt.Printf("signature: %+v", signature)
}

func TestGCPKms(t *testing.T) {
	params := make(map[string]string)
	params["kms_type"] = GCP
	params["project_id"] = "remote-sign-407206"
	params["location_id"] = "asia-southeast1"
	params["key_ring"] = "remote-sign"
	params["key"] = "remote-sign"
	params["key_version"] = "1"
	params["credential_path"] = "remote-sign-407206-8b50af709ec3.json"

	iWallet, err := NewWallet(params)
	if err != nil {
		panic(err)
	}
	walletInst := iWallet.(KMS)
	fmt.Printf("pubkey: %+v \n", walletInst.PublicKey())

	// test sign
	signData, _ := hex.DecodeString("356355dae4212533ce182cbb31492a6c2665fcf8f17e089d929e7a3efd1d1ba1")
	signature, err := walletInst.Sign(signData)
	if err != nil {
		panic(err)
	}

	fmt.Printf("signature: %+v \n", signature)
	// get pubkey

	fmt.Println(walletInst.Address().String())
}
