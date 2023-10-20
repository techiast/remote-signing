package main

import (
	"encoding/hex"
	"fmt"
	"github.com/remote-signing/wallet_plugin/address"
	crypto "github.com/remote-signing/wallet_plugin/key"
)

type Wallet struct {
	pk   *crypto.PrivateKey
	pkey *crypto.PublicKey
}

func NewAccountAddressFromPublicKey(pubKey *crypto.PublicKey) *address.Address {
	pk := pubKey.SerializeUncompressed()
	if pk == nil {
		fmt.Printf("FAIL invalid public key: %v \n", pubKey)
	}
	digest := crypto.SHA3Sum256(pk[1:])
	return address.NewAddress(digest[len(digest)-address.AddressIDBytes:])
}

// todo: update kms
func (w Wallet) Address() address.IAddress {
	return NewAccountAddressFromPublicKey(w.pkey)
}

// todo: update kms
func (w Wallet) Sign(data []byte) ([]byte, error) {
	sig, err := crypto.NewSignature(data, w.pk)
	if err != nil {
		return nil, err
	}
	return sig.SerializeRSV()
}

// todo: update kms
func (w Wallet) PublicKey() []byte {
	return w.pkey.SerializeCompressed()
}

// goloop entry here
func NewWallet(params map[string]string) (interface{}, error) {
	var key *crypto.PrivateKey
	// load key from input params
	if _, ok := params["private_key"]; ok {
		keyBytes, err := hex.DecodeString(params["private_key"])
		if err != nil {
			return nil, err
		}

		key, err = crypto.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}
	} else {
		key, _ = crypto.GenerateKeyPair()
	}

	wallet := Wallet{
		pk:   key,
		pkey: key.PublicKey(),
	}

	return wallet, nil
}
