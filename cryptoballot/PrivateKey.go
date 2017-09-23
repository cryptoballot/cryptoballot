package cryptoballot

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/cryptoballot/rsablind"
	"github.com/phayes/errors"
)

// PrivateKey is a DER encoded private key
type PrivateKey []byte

var (
	ErrPrivatKeyInvalidPEM = errors.New("Could not decode Prviate Key PEM Block")
	ErrPrivatKeyWrongType  = errors.New("Could not find RSA PRIVATE KEY block")
	ErrPrivatKeyGenerate   = errors.New("Could not generate new PrivateKey")
	ErrPrivatKeyCryptoKey  = errors.New("Could not create from rsa.CryptoKey from PrivateKey. Could not parse PrivateKey bytes")
	ErrPrivatKeySign       = errors.New("PrivateKey could not sign bytes")
	ErrPrivateKeySHA256    = errors.New("Invalid SHA256 Hash checksum")
	ErrPrivateKeyLen       = errors.New("Could not determine private key length")
)

// NewPrivateKey creates a new PrivateKey from a PEM Block bytes
func NewPrivateKey(PEMBlockBytes []byte) (PrivateKey, error) {
	PEMBlock, _ := pem.Decode(PEMBlockBytes)
	if PEMBlock == nil {
		return nil, ErrPrivatKeyInvalidPEM
	}
	return NewPrivateKeyFromBlock(PEMBlock)
}

// NewPrivateKeyFromBlock creates a new PrivateKey from a pem.Block
// This function also performs error checking to make sure the key is valid.
func NewPrivateKeyFromBlock(PEMBlock *pem.Block) (PrivateKey, error) {
	if PEMBlock.Type != "RSA PRIVATE KEY" {
		return nil, errors.Wraps(ErrPrivatKeyWrongType, "Found "+PEMBlock.Type)
	}

	_, err := x509.ParsePKCS1PrivateKey(PEMBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(ErrPrivatKeyInvalidPEM, err)
	}

	return PrivateKey(PEMBlock.Bytes), nil
}

// Create a new PrivateKey from an rsa.PrivateKey struct
func NewPrivateKeyFromCryptoKey(priv *rsa.PrivateKey) PrivateKey {
	return PrivateKey(x509.MarshalPKCS1PrivateKey(priv))
}

// Generate a new PrivateKey
func GeneratePrivateKey(keySize int) (PrivateKey, error) {
	cryptoKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, errors.Wrap(err, ErrPrivatKeyGenerate)
	}
	return NewPrivateKeyFromCryptoKey(cryptoKey), nil
}

// Extract the bytes out of the private key
func (pk PrivateKey) Bytes() []byte {
	return []byte(pk)
}

// Parse the PrivateKey (which is stored as a der encoded key) into a rsa.PrivateKey object, ready to be used for crypto functions
func (pk PrivateKey) GetCryptoKey() (*rsa.PrivateKey, error) {
	privkey, err := x509.ParsePKCS1PrivateKey(pk.Bytes())
	if err != nil {
		return nil, errors.Wrap(err, ErrPrivatKeyCryptoKey)
	}
	return privkey, nil
}

// Check if the private key is empty of any bytes
func (pk PrivateKey) IsEmpty() bool {
	if len(pk) == 0 {
		return true
	} else {
		return false
	}
}

// Sign the given item and return a Signature
func (pk PrivateKey) Sign(item fmt.Stringer) (Signature, error) {
	bytes := []byte(item.String())
	return pk.SignBytes(bytes)
}

// SignBytes signs the given bytes and return a Signature
// This will use SHA256 as the signing hash function
func (pk PrivateKey) SignBytes(bytes []byte) (Signature, error) {
	h := sha256.New()
	h.Write(bytes)
	cryptoKey, err := pk.GetCryptoKey()
	if err != nil {
		return nil, errors.Wrap(err, ErrPrivatKeySign)
	}
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, cryptoKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return nil, errors.Wrap(err, ErrPrivatKeySign)
	}
	return Signature(rawSignature), nil
}

// SignString signs the given string and return a Signature
func (pk PrivateKey) SignString(str string) (Signature, error) {
	return pk.SignBytes([]byte(str))
}

// SignRawBytes signs the given bytes using naive RSA signing (no hash or padding) and return a Signature using
// This is compatible with blinded messages and blind signatures
//
// WARNING: Only use this method if you understand the dangers of blind signing and are using a full domain hash.
func (pk PrivateKey) SignRawBytes(bytes []byte) (Signature, error) {
	cryptoKey, err := pk.GetCryptoKey()
	if err != nil {
		return nil, errors.Wrap(err, ErrPrivatKeySign)
	}
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, cryptoKey, 0, bytes)
	if err != nil {
		return nil, errors.Wrap(err, ErrPrivatKeySign)
	}
	return Signature(rawSignature), nil
}

// BlindSign signs the given bytes using RSA blind signing and returns a Signature.
// The message should be hased as a SHA256 full-domain hash that is half the size of the key.
//
// WARNING: Only use this method if you understand the dangers of blind signing.
// See Caveats: https://godoc.org/github.com/cryptoballot/rsablind
func (pk PrivateKey) BlindSign(messageHash []byte) (Signature, error) {
	cryptoKey, err := pk.GetCryptoKey()
	if err != nil {
		return nil, errors.Wrap(err, ErrPrivatKeySign)
	}

	// Get the key length
	keylen, err := pk.KeyLength()
	if err != nil {
		return nil, errors.Wrap(err, ErrPrivatKeySign)
	}

	// Make sure the size of messageHash is exactly the key size
	if len(messageHash)*8 != keylen {
		return nil, errors.Wraps(ErrPrivatKeySign, "Invalid messageHash size. The message must be full-domain-hashed to exactly half the signing key size.")
	}

	// Blind sign the blinded message
	rawSignature, err := rsablind.BlindSign(cryptoKey, messageHash)
	if err != nil {
		return nil, errors.Wrap(err, ErrPrivatKeySign)
	}

	return Signature(rawSignature), nil
}

// PublicKey get the public key for the private key
func (pk PrivateKey) PublicKey() (PublicKey, error) {
	cryptoKey, err := pk.GetCryptoKey()
	if err != nil {
		return nil, err
	}
	return NewPublicKeyFromCryptoKey(&cryptoKey.PublicKey)
}

// String implements Stringer
func (pk PrivateKey) String() string {
	pemBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pk.Bytes(),
	}
	return string(pem.EncodeToMemory(&pemBlock))
}

// KeyLength get the number of bits in the key
func (pk PrivateKey) KeyLength() (int, error) {
	privkey, err := pk.GetCryptoKey()
	if err != nil {
		return 0, errors.Wrap(err, ErrPrivateKeyLen)
	}
	return privkey.N.BitLen(), nil
}
