package cryptoballot

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"errors"
)

type Signature []byte

// Create a new signature from a base64 encoded item, as we would get in a PUT or POST request
//@@TODO: Make sure "Signature too short" is working as expected
func NewSignature(rawSignature []byte) (Signature, error) {
	if len(rawSignature) < base64.StdEncoding.EncodedLen(128) {
		return nil, errors.New("Signature too short")
	}
	sig := Signature(rawSignature)
	if _, err := sig.GetBytes(); err != nil {
		return nil, err
	}
	return sig, nil
}

// Create a new signature from unencoded raw bytes
func NewSignatureFromBytes(rawSignature []byte) (Signature, error) {
	encodedSignature := make([]byte, base64.StdEncoding.EncodedLen(len(rawSignature)))
	base64.StdEncoding.Encode(encodedSignature, rawSignature)
	return NewSignature(encodedSignature)
}

// Implements Stringer
func (sig Signature) String() string {
	return string(sig)
}

// Extract the raw bytes out of the base64 encoded signature
func (sig Signature) GetBytes() ([]byte, error) {
	dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(sig)))
	n, err := base64.StdEncoding.Decode(dbuf, sig)
	if err != nil {
		return nil, err
	}
	return dbuf[:n], nil
}

func (sig Signature) VerifySignature(pk PublicKey, message []byte) error {
	sigBytes, err := sig.GetBytes()
	if err != nil {
		return err
	}

	pubkey, err := pk.GetCryptoKey()
	if err != nil {
		return err
	}

	hash := sha512.New()
	hash.Write(message)
	return rsa.VerifyPKCS1v15(pubkey, crypto.SHA512, hash.Sum(nil), sigBytes)
}
