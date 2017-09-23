package cryptoballot

import (
	"encoding/base64"

	"github.com/phayes/errors"
)

// BlindBallot is a blinded representation of the ballot
// It is a blinded SHA256 full-domian-hash of the ballot, expanded to half the size of the signing authority's key.
type BlindBallot []byte

var (
	ErrBlindBallotBase64 = errors.New("Invalid Blind Ballot. Could not read base64 encoded bytes")
)

// NewBlindBallot creates a new blind ballot from a base64 encoded item
func NewBlindBallot(Base64BlindBallot []byte) (BlindBallot, error) {
	dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(Base64BlindBallot)))
	n, err := base64.StdEncoding.Decode(dbuf, Base64BlindBallot)
	if err != nil {
		return nil, errors.Wrap(err, ErrBlindBallotBase64)
	}
	blindballot := dbuf[:n]

	return BlindBallot(blindballot), nil
}

// Implements Stringer interface. Returns a base64 encoded string.
func (bb BlindBallot) String() string {
	return base64.StdEncoding.EncodeToString(bb)
}

// Bytes gets the blind ballot as an slice of bytes
func (bb BlindBallot) Bytes() []byte {
	return []byte(bb)
}
