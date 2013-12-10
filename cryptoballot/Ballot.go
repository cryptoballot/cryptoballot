package cryptoballot

import (
	"bytes"
	"encoding/hex"
	"errors"
	//"github.com/davecgh/go-spew/spew"
	_ "github.com/lib/pq"
	"strconv"
	"strings"
)

var (
	// election-id (max 128 bytes) + base64-of-a-8096-bit-public-key + SHA512-BallotID + (64 vote preferences) + (64 tags) + signature + line-seperators
	maxTagKeySize   = 64
	maxTagValueSize = 256
	maxBallotSize   = (128) + (1352) + (128) + (64 * 256 * 2) + (64 * (maxTagKeySize + maxTagValueSize + 1)) + (128 + (172)) + (18 + 64 + 64)
)

type Ballot struct {
	ElectionID string
	BallotID   // SHA512 (hex) of base64 encoded public-key
	PublicKey  // base64 encoded PEM formatted public-key
	Vote       // Ordered list of choices
	TagSet     // Arbitrary key-value store
	Signature  // Crypto signature for the ballot
}

// Given a raw ballot-string (as a []byte) (see documentation for format), return a new Ballot.
// Generally the ballot-string is coming from a client in a PUT body.
// This will also verify the signature on the ballot and return an error if the ballot does not pass crypto verification
func NewBallot(rawBallot []byte) (Ballot, error) {
	var (
		hasTags    bool
		err        error
		electionID string
		ballotID   BallotID
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

// Load a ballot from the backend postgres database - returns a pointer to a ballot.
func LoadBallotFromDB(ElectionID string, BallotID BallotID) (*Ballot, error) {

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

type Vote [][]byte // Ordered list of choices represented by git addresses

func NewVote(rawVote []byte) (Vote, error) {
	return Vote(bytes.Split(rawVote, []byte("\n"))), nil
}

func (vote *Vote) String() string {
	var output string
	for i, voteItem := range *vote {
		output += string(voteItem)
		if i != len(*vote)-1 {
			output += "\n"
		}
	}
	return output
}

type Tag struct {
	Key   []byte
	Value []byte
}

func NewTag(rawTag []byte) (Tag, error) {
	parts := bytes.SplitN(rawTag, []byte("="), 2)
	if len(parts) != 2 {
		return Tag{}, errors.New("Malformed tag")
	}
	if len(parts[0]) > maxTagKeySize {
		return Tag{}, errors.New("Tag key too long")
	}
	if len(parts[1]) > maxTagValueSize {
		return Tag{}, errors.New("Tag value too long")
	}

	return Tag{
		parts[0],
		parts[1],
	}, nil
}

func (tag *Tag) String() string {
	return string(tag.Key) + "=" + string(tag.Value)
}

type TagSet []Tag

func NewTagSet(rawTagSet []byte) (TagSet, error) {
	parts := bytes.Split(rawTagSet, []byte("\n"))
	tagSet := TagSet(make([]Tag, len(parts)))
	for i, rawTag := range parts {
		tag, err := NewTag(rawTag)
		if err != nil {
			return TagSet{}, err
		}
		tagSet[i] = tag
	}
	return tagSet, nil
}

func (tagSet *TagSet) Keys() [][]byte {
	output := make([][]byte, len(*tagSet), len(*tagSet))
	for i, tag := range *tagSet {
		output[i] = tag.Key
	}
	return output
}

func (tagSet *TagSet) KeyStrings() []string {
	output := make([]string, len(*tagSet), len(*tagSet))
	for i, tag := range *tagSet {
		output[i] = string(tag.Key)
	}
	return output
}

func (tagSet *TagSet) Values() [][]byte {
	output := make([][]byte, len(*tagSet), len(*tagSet))
	for i, tag := range *tagSet {
		output[i] = tag.Value
	}
	return output
}

func (tagSet *TagSet) ValueStrings() []string {
	output := make([]string, len(*tagSet), len(*tagSet))
	for i, tag := range *tagSet {
		output[i] = string(tag.Value)
	}
	return output
}

func (tagSet *TagSet) String() string {
	var output string
	for i, tag := range *tagSet {
		output += tag.String()
		if i != len(*tagSet)-1 {
			output += "\n"
		}
	}
	return output
}
