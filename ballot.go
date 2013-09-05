package main

// NOTES
// See https://bitbucket.org/bumble/bumble-golang-common/src/master/key/publickey.go

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

type Ballot struct {
	BallotID  BallotID  // SHA512 (hex) of base64 encoded public-key
	PublicKey PublicKey // base64 encoded PEM formatted public-key
	Vote      Vote      // Ordered list of choices
	TagSet    TagSet
	Signature Signature // Crypto signature for the ballot
}

type BallotID string

// Given a string, return a new BallotID object.
// This function also performs error checking to make sure the BallotID is 128 characters long and base64 encoded
func NewBallotID(bidstr string) (BallotID, error) {
	// SHA512 is 128 characters long and is a valid hex
	if len(bidstr) != 128 {
		return "", errors.New("Ballot ID must be 128 characters long. It is the SHA512 of the base64 encoded public key.")
	}
	if _, err := hex.DecodeString(bidstr); err != nil {
		return "", errors.New("Ballot ID must be hex encoded. It is the SHA512 of the base64 encoded public key.")
	}
	return BallotID(bidstr), nil
}

type PublicKey string

// Given a string, return a new PublicKey object.
// This function also performs error checking to make sure the key is valid.
// @@TODO: Reject keys that are under 2048 bits in size
func NewPublicKey(pkstr string) (PublicKey, error) {
	if pkstr == "" {
		return "", errors.New("No public key provided")
	}

	pk := PublicKey(pkstr)

	if _, err := pk.getCryptoKey(); err != nil {
		return "", err
	}

	return pk, nil
}

// Extract the raw bytes out of the base64 encoded public key
func (pk PublicKey) GetBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(pk))
}

// Parse the PublicKey (which is stored as a base64 string) into a rsa.PublicKey object, ready to be used for crypto functions
func (pk PublicKey) getCryptoKey() (*rsa.PublicKey, error) {
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

// Get the corresponding BallotID, which is the (hex encoded) SHA512 of the (base64 encoded) public key.
func (pk PublicKey) GetBallotID() BallotID {
	// @@TODO this can be more direct in Go 1.2
	h := sha512.New()
	h.Write([]byte(pk))
	return BallotID(hex.EncodeToString(h.Sum(nil)))
}

type Vote []string // Ordered list of choices represented by git addresses

type TagSet []Tag

type Tag struct {
	Key   string
	Value string
}

type Signature string

func NewSignature(sigstr string) (Signature, error) {
	if sigstr == "" {
		return "", errors.New("Signature not provided")
	}
	sig := Signature(sigstr)
	if _, err := sig.GetBytes(); err != nil {
		return "", err
	}
	return sig, nil
}

// Extract the raw bytes out of the base64 encoded signature
func (sig Signature) GetBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(sig))
}

func (sig Signature) VerifySignature(pk PublicKey, message []byte) error {
	sigBytes, err := sig.GetBytes()
	if err != nil {
		return err
	}

	pubkey, err := pk.getCryptoKey()
	if err != nil {
		return err
	}

	hash := sha512.New()
	hash.Write(message)
	return rsa.VerifyPKCS1v15(pubkey, crypto.SHA512, hash.Sum(nil), sigBytes)
}
