package main

import (
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

type Vote []string // Ordered list of choices represented by git addresses

type Tag struct {
	Key   string
	Value string
}

type TagSet []Tag
