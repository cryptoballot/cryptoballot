package cryptoballot

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/phayes/errors"
)

// A DER encoded private key
type PrivateKey []byte

var (
	ErrPrivatKeyInvalidPEM = errors.New("Could not decode Prviate Key PEM Block")
	ErrPrivatKeyWrongType  = errors.New("Could not find RSA PRIVATE KEY block")
	ErrPrivatKeyGenerate   = errors.New("Could not generate new PrivateKey")
	ErrPrivatKeyCryptoKey  = errors.New("Could not create from rsa.CryptoKey from PrivateKey. Could not parse PrivateKey bytes")
	ErrPrivatKeySign       = errors.New("PrivateKey could not sign bytes")
	ErrPrivateKeySHA256    = errors.New("Invalid SHA256 Hash checksum")
)

// Create a new PrivateKey from a PEM Block bytes
func NewPrivateKey(PEMBlockBytes []byte) (PrivateKey, error) {
	PEMBlock, _ := pem.Decode(PEMBlockBytes)
	if PEMBlock == nil {
		return nil, ErrPrivatKeyInvalidPEM
	}
	return NewPrivateKeyFromBlock(PEMBlock)
}

// Create a new PrivateKey from a pem.Block
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

// Sign the given bytes and return a Signature
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

// Sign the given string and return a Signature
func (pk PrivateKey) SignString(str string) (Signature, error) {
	return pk.SignBytes([]byte(str))
}

// Sign the given bytes using naive RSA signing (no hash or padding) and return a Signature using
// This is compatible with blinded messages and blind signatures
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

// Sign the given hex-endcoded hash checksum and return a Signature
// @@TODO Remove this -- undeeded
func (pk PrivateKey) SignSHA256(hexbytes []byte) (Signature, error) {
	if hex.DecodedLen(len(hexbytes)) != sha256.Size {
		return nil, ErrPrivateKeySHA256
	}

	// Decode hex bytes into raw bytes
	decodedBytes := make([]byte, hex.DecodedLen(len(hexbytes)))
	_, err := hex.Decode(decodedBytes, hexbytes)
	if err != nil {
		return nil, errors.Wrap(err, ErrPrivateKeySHA256)
	}

	// Get the rsa cryptokey for signing
	cryptoKey, err := pk.GetCryptoKey()
	if err != nil {
		return nil, errors.Wrap(err, ErrPrivatKeySign)
	}

	// Compute the signature and return the results
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, cryptoKey, crypto.SHA256, decodedBytes)
	if err != nil {
		return nil, errors.Wrap(err, ErrPrivatKeySign)
	}
	return Signature(rawSignature), nil
}

// Get the public key
func (pk PrivateKey) PublicKey() (PublicKey, error) {
	cryptoKey, err := pk.GetCryptoKey()
	if err != nil {
		return nil, err
	}
	return NewPublicKeyFromCryptoKey(&cryptoKey.PublicKey)
}

// Implements Stringer
func (pk PrivateKey) String() string {
	pemBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pk.Bytes(),
	}
	return string(pem.EncodeToMemory(&pemBlock))
}
