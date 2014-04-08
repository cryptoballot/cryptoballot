package cryptoballot

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
)

type User struct {
	UserID     []byte            // SHA512 (hex) of base64 encoded public-key
	PublicKey  PublicKey         // base64 encoded PEM formatted public-key
	Perms      []string          // List of permissions. @@TODO: Maybe this shouldn't be a string but should be an enumeration
	Properties map[string]string // List of all key->value properties
}

func NewUser(PEMBlockBytes []byte) (*User, error) {
	PEMBlock, _ := pem.Decode(PEMBlockBytes)
	if PEMBlock.Type != "PUBLIC KEY" {
		return nil, errors.New("Could not find PUBLIC KEY block for user")
	}

	return NewUserFromBlock(PEMBlock)
}

func NewUserFromBlock(PEMBlock *pem.Block) (*User, error) {
	var (
		err       error
		userID    []byte
		publicKey PublicKey
		perms     []string
	)

	publicCryptoKey, err := x509.ParsePKIXPublicKey(PEMBlock.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, err = NewPublicKeyFromCryptoKey(publicCryptoKey.(*rsa.PublicKey))
	if err != nil {
		return nil, err
	}

	_, ok := PEMBlock.Headers["userid"]
	if !ok {
		return nil, errors.New("userid not specified for user")
	}
	userID = []byte(PEMBlock.Headers["userid"])
	if !bytes.Equal(userID, publicKey.GetSHA512()) {
		return nil, errors.New("Invalid User ID. A User ID must be the (hex encoded) SHA512 of the user's public key.")
	}

	permString, ok := PEMBlock.Headers["perms"]
	if !ok || permString == "" {
		return nil, errors.New("No permissions specified for user")
	}
	permsRaw := strings.Split(permString, ",")
	for _, val := range permsRaw {
		trimmed := strings.TrimSpace(val)
		if trimmed == "" {
			return nil, errors.New("Could not parse user permissions")
		}
		perms = append(perms, trimmed)
	}

	// All checks pass
	return &User{
		userID,
		publicKey,
		perms,
		PEMBlock.Headers,
	}, nil
}

// Implements Stringer
func (user User) String() string {
	pemBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: user.Properties,
		Bytes:   user.PublicKey.Bytes(),
	}
	return string(pem.EncodeToMemory(&pemBlock))
}
