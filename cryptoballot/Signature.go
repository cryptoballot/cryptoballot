package cryptoballot

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"errors"
)

// An RSA signature. Raw bytes.
type Signature []byte

// Create a new signature from a base64 encoded item, as we would get in a PUT or POST request
//@@TEST: Make sure "Signature too short" is working as expected
func NewSignature(Base64Signature []byte) (Signature, error) {
	dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(Base64Signature)))
	n, err := base64.StdEncoding.Decode(dbuf, Base64Signature)
	if err != nil {
		return nil, err
	}
	if n < 128 {
		return nil, errors.New("Signature too short")
	}
	sig := dbuf[:n]

	return Signature(sig), nil
}

// Implements Stringer. Returns a base64 encoded string.
func (sig Signature) String() string {
	return base64.StdEncoding.EncodeToString(sig)
}

// Get the signature as an array of bytes
func (sig Signature) Bytes() []byte {
	return []byte(sig)
}

func (sig Signature) VerifySignature(pk PublicKey, message []byte) error {
	pubkey, err := pk.GetCryptoKey()
	if err != nil {
		return err
	}

	hash := sha512.New()
	hash.Write(message)
	return rsa.VerifyPKCS1v15(pubkey, crypto.SHA512, hash.Sum(nil), sig.Bytes())
}
