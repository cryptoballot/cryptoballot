package cryptoballot

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// A DER encoded private key
type PrivateKey []byte

// Create a new PrivateKey from a PEM Block bytes

func NewPrivateKey(PEMBlockBytes []byte) (PrivateKey, error) {
	PEMBlock, _ := pem.Decode(PEMBlockBytes)
	if PEMBlock == nil {
		return nil, errors.New("Could not decode PEM Block for user")
	}
	return NewPrivateKeyFromBlock(PEMBlock)
}

// Create a new PrivateKey from a pem.Block
// This function also performs error checking to make sure the key is valid.
func NewPrivateKeyFromBlock(PEMBlock *pem.Block) (PrivateKey, error) {
	if PEMBlock.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("Could not find RSA PRIVATE KEY block")
	}

	_, err := x509.ParsePKCS1PrivateKey(PEMBlock.Bytes)
	if err != nil {
		return nil, err
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
		return nil, err
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
		return nil, err
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
func (pk PrivateKey) SignBytes(bytes []byte) (Signature, error) {
	h := sha256.New()
	h.Write(bytes)
	cryptoKey, err := pk.GetCryptoKey()
	if err != nil {
		return nil, err
	}
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, cryptoKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	return Signature(rawSignature), nil
}

// Sign the given string and return a Signature
func (pk PrivateKey) SignString(str string) (Signature, error) {
	return pk.SignBytes([]byte(str))
}

// Sign the given hex-endcoded hash checksum and return a Signature
func (pk PrivateKey) SignSHA256(hexbytes []byte) (Signature, error) {
	if hex.DecodedLen(len(hexbytes)) != sha256.Size {
		return nil, errors.New("Invalid SHA256 Hash checksum")
	}
	cryptoKey, err := pk.GetCryptoKey()
	if err != nil {
		return nil, err
	}

	// Decode hex bytes into raw bytes
	decodedBytes := make([]byte, hex.DecodedLen(len(hexbytes)))
	_, err = hex.Decode(decodedBytes, hexbytes)
	if err != nil {
		return nil, err
	}

	// Compute the signature and return the results
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, cryptoKey, crypto.SHA256, decodedBytes)
	if err != nil {
		return nil, err
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
