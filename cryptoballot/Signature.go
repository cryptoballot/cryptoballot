package cryptoballot

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"github.com/phayes/errors"
)

// An RSA signature. Raw bytes.
type Signature []byte

var (
	ErrSignatureBase64   = errors.New("Invalid Signature. Could not read base64 encoded bytes")
	ErrSignatureTooShort = errors.New("Invalid Signature. Signature too short")
	ErrSignatureVerify   = errors.New("Could not cryptographically verify signature")
)

// Create a new signature from a base64 encoded item, as we would get in a PUT or POST request
//@@TODO: Test to make sure "Signature too short" is working as expected
func NewSignature(Base64Signature []byte) (Signature, error) {
	dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(Base64Signature)))
	n, err := base64.StdEncoding.Decode(dbuf, Base64Signature)
	if err != nil {
		return nil, errors.Wrap(err, ErrSignatureBase64)
	}
	if n < 128 {
		return nil, ErrSignatureTooShort
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

// Verify that the signature crytpographically signs the given message using the given public key
func (sig Signature) VerifySignature(pk PublicKey, message []byte) error {
	pubkey, err := pk.GetCryptoKey()
	if err != nil {
		return errors.Wrap(err, ErrSignatureVerify)
	}

	hash := sha256.New()
	hash.Write(message)
	err = rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, hash.Sum(nil), sig.Bytes())
	if err != nil {
		return errors.Wrap(err, ErrSignatureVerify)
	}
	return err
}

// Verify that the signature crytpographically signs the given message using the given public key
// This message does not verify using a hash function or padding but verifies using naive RSA verification
func (sig Signature) VerifyRawSignature(pk PublicKey, message []byte) error {
	pubkey, err := pk.GetCryptoKey()
	if err != nil {
		return errors.Wrap(err, ErrSignatureVerify)
	}

	err = rsa.VerifyPKCS1v15(pubkey, 0, message, sig.Bytes())
	if err != nil {
		return errors.Wrap(err, ErrSignatureVerify)
	}
	return err
}
