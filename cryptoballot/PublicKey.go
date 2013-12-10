package cryptoballot

import (
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

var (
	MinPublicKeyBits = 1024
)

type PublicKey []byte

// Given a string, return a new PublicKey object.
// This function also performs error checking to make sure the key is valid.
func NewPublicKey(pkRaw []byte) (PublicKey, error) {
	if len(pkRaw) < base64.StdEncoding.EncodedLen(MinPublicKeyBits/8) {
		return nil, errors.New("Public Key too short. Try using more bits.")
	}

	pk := PublicKey(pkRaw)

	if _, err := pk.getCryptoKey(); err != nil {
		return nil, err
	}

	return pk, nil
}

// Implements Stringer
func (pk *PublicKey) String() string {
	return string(*pk)
}

// Extract the raw bytes out of the base64 encoded public key
func (pk *PublicKey) GetBytes() ([]byte, error) {
	dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(*pk)))
	n, err := base64.StdEncoding.Decode(dbuf, *pk)
	if err != nil {
		return nil, err
	}
	return dbuf[:n], nil
}

// Parse the PublicKey (which is stored as a base64 string) into a rsa.PublicKey object, ready to be used for crypto functions
func (pk *PublicKey) getCryptoKey() (*rsa.PublicKey, error) {
	rawpk, err := pk.GetBytes()
	if err != nil {
		return nil, err
	}
	pubkey, err := x509.ParsePKIXPublicKey(rawpk)
	if err != nil {
		return nil, err
	}
	return pubkey.(*rsa.PublicKey), nil
}

// Get the corresponding ID, which is the (hex encoded) SHA512 of the (base64 encoded) public key.
// @@TODO this can be more direct in Go 1.2
func (pk *PublicKey) GetSHA512() []byte {
	h := sha512.New()
	h.Write([]byte(*pk))
	sha512hex := make([]byte, 128)
	hex.Encode(sha512hex, h.Sum(nil))
	return sha512hex
}
