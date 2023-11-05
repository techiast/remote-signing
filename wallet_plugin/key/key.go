package crypto

import (
	"encoding/hex"

	"github.com/remote-signing/wallet_plugin/secp256k1"
	"github.com/remote-signing/wallet_plugin/sha3"
)

const (
	// PrivateKeyLen is the byte length of a private key
	PrivateKeyLen = 32
)

// TODO add 'func ToECDSA() ecdsa.PrivateKey' if needed

const (
	// PublicKeyLenCompressed is the byte length of a compressed public key
	PublicKeyLenCompressed = 33
	// PublicKeyLenUncompressed is the byte length of an uncompressed public key
	PublicKeyLenUncompressed = 65
)

// PublicKey is a type representing a public key, which can be serialized to
// or deserialized from compressed or uncompressed formats.
type PublicKey struct {
	real *secp256k1.PublicKey
}

// ParsePublicKey parses the public key into a PublicKey instance. It supports
// uncompressed and compressed formats.
// NOTE: For the efficiency, it may use the slice directly. So don't change any
// internal value of the public key
func ParsePublicKey(pubKey []byte) (*PublicKey, error) {
	pk, err := secp256k1.ParsePubKey(pubKey)
	if err != nil {
		return nil, err
	}
	return &PublicKey{real: pk}, nil
}

// SerializeCompressed serializes the public key in a 33-byte compressed format.
// For the efficiency, it returns the slice internally used, so don't change
// any internal value in the returned slice.
func (key *PublicKey) SerializeCompressed() []byte {
	return key.real.SerializeCompressed()
}

// SerializeUncompressed serializes the public key in a 65-byte uncompressed format.
func (key *PublicKey) SerializeUncompressed() []byte {
	return key.real.SerializeUncompressed()
}

// Equal returns true if the given public key is same as this instance
// semantically
func (key *PublicKey) Equal(key2 *PublicKey) bool {
	return key.real.IsEqual(key2.real)
}

// String returns the string representation.
func (key *PublicKey) String() string {
	return "0x" + hex.EncodeToString(key.SerializeCompressed())
}

func SHA3Sum256(m []byte) []byte {
	d := sha3.Sum256(m)
	return d[:]
}
