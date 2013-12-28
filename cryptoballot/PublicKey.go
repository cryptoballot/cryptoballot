package cryptoballot

import (
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
)

// A DER encoded public key
type PublicKey []byte

// Create a new PublicKey from a base64 encoded item, as we would get in a PUT or POST request
// This function also performs error checking to make sure the key is valid.
func NewPublicKey(base64PublicKey []byte) (PublicKey, error) {
	dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(base64PublicKey)))
	n, err := base64.StdEncoding.Decode(dbuf, base64PublicKey)
	if err != nil {
		return nil, err
	}
	pk := dbuf[:n]

	return PublicKey(pk), nil
}

// Implements Stringer
func (pk PublicKey) String() string {
	return base64.StdEncoding.EncodeToString(pk)
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

// Get the corresponding ID, which is the (hex encoded) SHA512 of the (base64 encoded) public key.
func (pk PublicKey) GetSHA512() []byte {
	h := sha512.New()
	h.Write([]byte(pk.String()))
	sha512hex := make([]byte, 128)
	hex.Encode(sha512hex, h.Sum(nil))
	return sha512hex
}

func (pk PublicKey) IsEmpty() bool {
	if len(pk) == 0 {
		return true
	} else {
		return false
	}
}
