package cryptoballot

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	//"github.com/davecgh/go-spew/spew"
	"strconv"
)

const (
	absoluteMinPublicKeySize = 2048 // We cannot go lower than this since it would hinder our ability to differentiate between public keys and tagsets on ballots
)

var (
	MinPublicKeySize = 4096 // Recommended minimum public key size -- this can be changed
)

// A DER encoded public key
type PublicKey []byte

// Create a new PublicKey from a base64 encoded item, as we would get in a PUT or POST request
// This function also performs error checking to make sure the key is valid.
func NewPublicKey(base64PublicKey []byte) (PublicKey, error) {
	decodedLen := base64.StdEncoding.DecodedLen(len(base64PublicKey))
	dbuf := make([]byte, decodedLen)
	n, err := base64.StdEncoding.Decode(dbuf, base64PublicKey)
	if err != nil {
		return nil, err
	}
	pk := PublicKey(dbuf[:n])

	// Check the key length
	keylen, err := pk.KeyLength()
	if err != nil {
		return nil, err
	}
	if MinPublicKeySize < absoluteMinPublicKeySize {
		panic("MinPublicKeySize has been set less than the allowed absoluteMinPublicKeySize of 2048")
	}
	if keylen < MinPublicKeySize {
		return nil, errors.New("Invalid public key - too short. Please use at least " + strconv.Itoa(MinPublicKeySize) + " bits")
	}

	return pk, nil
}

// Create a new PublicKey from an rsa.PublicKey struct
func NewPublicKeyFromCryptoKey(pub *rsa.PublicKey) (PublicKey, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return PublicKey(derBytes), nil
}

// Extract the bytes out of the public key
func (pk PublicKey) Bytes() []byte {
	return []byte(pk)
}

// Parse the PublicKey (which is stored as a der encoded key) into a rsa.PublicKey object, ready to be used for crypto functions
func (pk PublicKey) GetCryptoKey() (*rsa.PublicKey, error) {
	pubkey, err := x509.ParsePKIXPublicKey(pk.Bytes())
	if err != nil {
		return nil, err
	}
	return pubkey.(*rsa.PublicKey), nil
}

// Get the corresponding ID, which is the (hex encoded) SHA256 of the (base64 encoded) public key.
func (pk PublicKey) GetSHA256() []byte {
	h := sha256.New()
	h.Write([]byte(pk.String()))
	sha256hex := make([]byte, hex.EncodedLen(sha256.Size))
	hex.Encode(sha256hex, h.Sum(nil))
	return sha256hex
}

// Get the number of bits in the key
func (pk PublicKey) KeyLength() (int, error) {
	pubkey, err := pk.GetCryptoKey()
	if err != nil {
		return 0, nil
	}
	return pubkey.N.BitLen(), nil
}

// Check if the public key is empty of any bytes
func (pk PublicKey) IsEmpty() bool {
	if len(pk) == 0 {
		return true
	} else {
		return false
	}
}

// Implements Stringer
func (pk PublicKey) String() string {
	return base64.StdEncoding.EncodeToString(pk)
}
