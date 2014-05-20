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

type UserSet []User

func NewUser(PEMBlockBytes []byte) (*User, error) {
	PEMBlock, _ := pem.Decode(PEMBlockBytes)
	if PEMBlock == nil {
		return nil, errors.New("Could not decode PEM Block for user")
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

	if PEMBlock.Type != "PUBLIC KEY" {
		return nil, errors.New("Could not find PUBLIC KEY block for user")
	}

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

func (user *User) HasPerm(checkperm string) bool {
	for _, perm := range user.Perms {
		if checkperm == perm {
			return true
		}
	}
	return false
}

// Implements Stringer
func (user *User) String() string {
	pemBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: user.Properties,
		Bytes:   user.PublicKey.Bytes(),
	}
	return string(pem.EncodeToMemory(&pemBlock))
}

// Given a set of PEM Block bytes (for example from a file that contains user data in PEM format), get a UserSet of multiple users
func NewUserSet(PEMBlockBytes []byte) (UserSet, error) {
	var userset UserSet
	for {
		var PEMBlock *pem.Block
		PEMBlock, PEMBlockBytes = pem.Decode(PEMBlockBytes)
		if PEMBlock == nil {
			PEMBlockBytes = []byte(strings.TrimSpace(string(PEMBlockBytes))) // Trim remaining whitespace
			if len(PEMBlockBytes) == 0 {
				break // We're done
			} else {
				// There's still data to be processed, but we can't make sense of it
				return nil, errors.New("Could not parse PEM Blocks")
			}
		}
		if PEMBlock.Type != "PUBLIC KEY" {
			return nil, errors.New("Found unexpected " + PEMBlock.Type + " when processing PEM Blocks")
		}
		user, err := NewUserFromBlock(PEMBlock)
		if err != nil {
			return nil, err
		}
		err = userset.Add(user)
		if err != nil {
			return nil, err
		}
	}
	return userset, nil
}

// Add a user to a UserSet. Returns an error if a user with the same public-key or with the same ID already exists
func (userset *UserSet) Add(user *User) error {
	for _, checkuser := range *userset {
		if bytes.Equal(checkuser.UserID, user.UserID) {
			return errors.New("Could not add user. User already exists with the same user-id")
		}
		if bytes.Equal(checkuser.PublicKey.Bytes(), user.PublicKey.Bytes()) {
			return errors.New("Could not add user. User already exists with the same public-key")
		}
	}

	*userset = append(*userset, *user)
	return nil
}

// Removes a user from a UserSet. Returns an error if the user cannot be found or nil on success.
func (userset *UserSet) Remove(userID []byte) error {
	for i, user := range *userset {
		if bytes.Equal(userID, user.UserID) {
			*userset = append((*userset)[:i], (*userset)[i+1:]...)
			return nil
		}
	}
	return errors.New("Could not find user with userID " + string(userID))
}

// Given a UserID, get the corresponding user from the UserSet. Returns nil if no user is found
func (userset UserSet) GetUser(userID []byte) *User {
	for _, user := range userset {
		if bytes.Equal(userID, user.UserID) {
			return &user
		}
	}
	return nil
}

// Given a Public Key, get the corresponding user from the UserSet. Returns nil if no user is found
func (userset UserSet) GetUserByKey(publicKey PublicKey) *User {
	for _, user := range userset {
		if bytes.Equal(publicKey.Bytes(), user.PublicKey.Bytes()) {
			return &user
		}
	}
	return nil
}

// Implements Stringer
func (userset UserSet) String() string {
	var s string
	for i, user := range userset {
		if i != 0 {
			s += "\n"
		}
		s += user.String()
	}
	return s
}
