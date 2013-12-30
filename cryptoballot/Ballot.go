package cryptoballot

import (
	"bytes"
	"errors"
	//"github.com/davecgh/go-spew/spew"
	"regexp"
	"strings"
)

const (
	maxTagKeySize   = 64
	maxTagValueSize = 256
)

var (
	// election-id (max 128 bytes) + BallotID + (64 vote preferences) + (64 tags) + signature + line-seperators
	maxBallotSize = (128) + (1352) + (128) + (64 * 256 * 2) + (64 * (maxTagKeySize + maxTagValueSize + 1)) + (128 + (172)) + (18 + 64 + 64)
	validBallotID = regexp.MustCompile(`^[0-9a-zA-Z\-\.\[\]_~:/?#@!$&'()*+,;=]+$`)
)

type Ballot struct {
	ElectionID string
	BallotID   string // Random user-selected string. Valid characters are as per RFC 3986, sec 2: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=
	Vote              // Ordered list of choice
	TagSet            // Arbitrary key-value store
	Signature         // Crypto signature for the ballot (signed by ballot-clerk server)
}

// Given a raw ballot-string (as a []byte) (see documentation for format), return a new Ballot.
// Generally the ballot-string is coming from a client in a PUT body.
// This will also verify the signature on the ballot and return an error if the ballot does not pass crypto verification
func NewBallot(rawBallot []byte) (*Ballot, error) {
	var (
		hasTags bool
		//hasSign    bool
		err        error
		electionID string
		ballotID   string
		vote       Vote
		tagSet     TagSet
		signature  Signature
	)

	parts := bytes.Split(rawBallot, []byte("\n\n"))

	// Determine what components exist
	numParts := len(parts)
	switch {
	case numParts == 3:
		//hasSign = false
		hasTags = false
	case numParts == 4:
		hasTags = false
		// We need to determine if it's a tag or a signature
	case numParts == 5:
		hasTags = true
		//hasSign = true
	default:
		return &Ballot{}, errors.New("Cannot read ballot. Invalid ballot format")
	}

	electionID = string(parts[0])

	ballotID = string(parts[1])
	if len(ballotID) > 512 {
		return &Ballot{}, errors.New("Ballot ID is too large. Maximumber 512 characters")
	}
	if !validBallotID.MatchString(ballotID) {
		return &Ballot{}, errors.New("Ballot ID contains illigal characters. Valid characters are as per RFC 3986, sec 2: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=")
	}

	vote, err = NewVote(parts[2])
	if err != nil {
		return &Ballot{}, err
	}

	if hasTags {
		tagSet, err = NewTagSet(parts[3])
		if err != nil {
			return &Ballot{}, err
		}
	} else {
		tagSet = nil
	}

	if hasTags {
		signature, err = NewSignature(parts[4])
	} else {
		signature, err = NewSignature(parts[3])
	}
	if err != nil {
		return &Ballot{}, err
	}

	ballot := Ballot{
		electionID,
		ballotID,
		vote,
		tagSet,
		signature,
	}

	// All checks pass
	return &ballot, nil
}

func (ballot *Ballot) VerifySignature(pk PublicKey) error {
	var s []string
	if ballot.HasTagSet() {
		s = []string{
			ballot.ElectionID,
			ballot.BallotID,
			ballot.Vote.String(),
			ballot.TagSet.String(),
		}
	} else {
		s = []string{
			ballot.ElectionID,
			ballot.BallotID,
			ballot.Vote.String(),
		}
	}
	return ballot.Signature.VerifySignature(pk, []byte(strings.Join(s, "\n\n")))
}

func (ballot *Ballot) String() string {
	var s []string
	if ballot.HasTagSet() {
		s = []string{
			ballot.ElectionID,
			ballot.BallotID,
			ballot.Vote.String(),
			ballot.TagSet.String(),
			ballot.Signature.String(),
		}
	} else {
		s = []string{
			ballot.ElectionID,
			ballot.BallotID,
			ballot.Vote.String(),
			ballot.Signature.String(),
		}
	}

	return strings.Join(s, "\n\n")
}

func (ballot *Ballot) HasTagSet() bool {
	return ballot.TagSet != nil
}

func (ballot *Ballot) HasSignature() bool {
	return ballot.Signature != nil
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
