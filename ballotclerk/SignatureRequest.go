package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	//"github.com/davecgh/go-spew/spew"
	_ "github.com/lib/pq"
	"strconv"
	"strings"
)

type SignatureRequest struct {
	ElectionID string
	RequestID         // SHA512 (hex) of base64 encoded public-key
	PublicKey         // base64 encoded PEM formatted public-key
	Ballot     []byte // base64 encoded ballot blob, it could be either blinded or unblinded.
	Signature         // Voter signature for the ballot request
}

type RequestID []byte

type PublicKey []byte

type Signature []byte

// Given a raw ballot-string (as a []byte) (see documentation for format), return a new Ballot.
// Generally the ballot-string is coming from a client in a PUT body.
// This will also verify the signature on the ballot and return an error if the ballot does not pass crypto verification
func NewSignatureRequest(rawSignatureRequest []byte) (SignatureRequest, error) {
	var (
		hasTags    bool
		err        error
		electionID string
		requestID  RequestID
		publicKey  PublicKey
		vote       Vote
		tagSet     TagSet
		signature  Signature
	)

	parts := bytes.Split(rawBallot, []byte("\n\n"))

	if len(parts) == 5 {
		hasTags = false
	} else if len(parts) == 6 {
		hasTags = true
	} else {
		return Ballot{}, errors.New("Cannot read ballot. Invalid ballot format")
	}

	electionID = string(parts[0])

	ballotID, err = NewBallotID(parts[1])
	if err != nil {
		return Ballot{}, err
	}

	publicKey, err = NewPublicKey(parts[2])
	if err != nil {
		return Ballot{}, err
	}

	vote, err = NewVote(parts[3])
	if err != nil {
		return Ballot{}, err
	}

	if hasTags {
		tagSet, err = NewTagSet(parts[4])
		if err != nil {
			return Ballot{}, err
		}
	} else {
		tagSet = nil
	}

	if hasTags {
		signature, err = NewSignature(parts[5])
	} else {
		signature, err = NewSignature(parts[4])
	}
	if err != nil {
		return Ballot{}, err
	}

	ballot := Ballot{
		electionID,
		ballotID,
		publicKey,
		vote,
		tagSet,
		signature,
	}

	// Verify the signature
	if err = ballot.VerifySignature(); err != nil {
		return Ballot{}, err
	}

	// All checks pass
	return ballot, nil
}

func (ballot *Ballot) VerifySignature() error {
	s := []string{
		ballot.ElectionID,
		ballot.BallotID.String(),
		ballot.PublicKey.String(),
		ballot.Vote.String(),
		ballot.TagSet.String(),
	}

	return ballot.Signature.VerifySignature(ballot.PublicKey, []byte(strings.Join(s, "\n\n")))
}

func (ballot *Ballot) String() string {
	s := []string{
		ballot.ElectionID,
		ballot.BallotID.String(),
		ballot.PublicKey.String(),
		ballot.Vote.String(),
		ballot.TagSet.String(),
		ballot.Signature.String(),
	}
	return strings.Join(s, "\n\n")
}

func (ballot *Ballot) SaveToDB() error {
	// The most complicated thing about this query is dealing with the tagSet, which needs to be inserted into an hstore column
	var tagKeyHolders, tagValHolders []string
	for i := 4; i < len(ballot.TagSet)+4; i++ {
		tagKeyHolders = append(tagKeyHolders, "$"+strconv.Itoa(i))
		tagValHolders = append(tagValHolders, "$"+strconv.Itoa(i+len(ballot.TagSet)))
	}
	query := "INSERT INTO ballots (ballot_id, public_key, ballot, tags) VALUES ($1, $2, $3, hstore(ARRAY[" + strings.Join(tagKeyHolders, ", ") + "], ARRAY[" + strings.Join(tagValHolders, ", ") + "]))"
	// golang's use of variadics is entirely too stringent, so you get crap like this
	values := append([]string{ballot.BallotID.String(), ballot.PublicKey.String(), ballot.String()}, append(ballot.TagSet.KeyStrings(), ballot.TagSet.ValueStrings()...)...)
	// Convert []string to []interface{}
	insertValues := make([]interface{}, len(values))
	for i, v := range values {
		insertValues[i] = interface{}(v)
	}

	_, err := db.Exec(query, insertValues...)
	return err
}

type BallotID []byte

// Given a string, return a new BallotID object.
// This function also performs error checking to make sure the BallotID is 128 characters long and base64 encoded
func NewBallotID(rawBallotID []byte) (BallotID, error) {
	// SHA512 is 128 characters long and is a valid hex
	if len(rawBallotID) != 128 {
		return nil, errors.New("Ballot ID must be 128 characters long. It is the SHA512 of the base64 encoded public key.")
	}
	if _, err := hex.Decode(make([]byte, hex.DecodedLen(len(rawBallotID))), rawBallotID); err != nil {
		return nil, errors.New("Ballot ID must be hex encoded. It is the SHA512 of the base64 encoded public key.")
	}
	return BallotID(rawBallotID), nil
}

func (ballotID BallotID) String() string {
	return string(ballotID)
}
