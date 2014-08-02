package cryptoballot

import (
	"bytes"
	"github.com/phayes/errors"
	"regexp"
	"time"
)

const (
	MaxElectionIDSize = 32 // Votes are stored in a postgres table named votes_<electon-id> so we need to limit the election ID size.
)

var (
	ValidElectionID = regexp.MustCompile(`^[0-9a-z_]+$`) // Regex for valid characters. We use this ID to construct the name of a table, so we need to limit allowed characters.

	ErrElectionIDTooBig      = errors.Newf("Invalid ElectionID. Too many characters. Maximum is %i characters", MaxElectionIDSize)
	ErrEelectionInvalid      = errors.New("Cannot parse election. Invalid format")
	ErrElectionIDInvalid     = errors.New("ElectionID contains illigal characters. Only lowercase alpha-numeric characters allowed")
	ErrElectionStartInvalid  = errors.New("Invalid election start time")
	ErrElectionEndInvalid    = errors.New("Invalid election end time")
	ErrElectionInvalidTagSet = errors.New("Cannot parse TagSet in election")
	ErrElectionInvalidKey    = errors.New("Cannot parse PublicKey in election")
	ErrElectionInvalidSig    = errors.New("Cannot parse Signature in election")
	ErrEletionSigNotFound    = errors.New("Could not verify election signature: Signature does not exist")
)

type Election struct {
	ElectionID string
	Start      time.Time // Start date & time (RFC-1123 format with a numeric timezone)
	End        time.Time // End date & time (RFC-1123 format with a numeric timezone)
	TagSet               // Optional key-value tag-set
	PublicKey            // The public key of the admin that created this election
	Signature            // The signature used to create this election
}

func NewElection(rawElection []byte) (*Election, error) {
	var (
		tagsSec    int
		keySec     int
		signSec    int
		err        error
		electionID string
		start      time.Time
		end        time.Time
		publicKey  PublicKey
		tagSet     TagSet
		signature  Signature
	)

	// Split the election into parts seperated by a double linebreak
	parts := bytes.Split(rawElection, []byte("\n\n"))

	// Determine what components exist
	numParts := len(parts)
	switch numParts {
	case 6:
		tagsSec = 3
		keySec = 4
		signSec = 5
	case 5:
		// We need to determine if the signature is missing or if the tagset is missing
		// We do this by looking at the 4th element (index 3) and checking to see if it's a tagset or the public key
		if bytes.Contains(parts[3], []byte{'\n'}) {
			// If it contains a linebreak, it's a tagset. The signature is missing.
			tagsSec = 3
			keySec = 4
		} else {
			// It's a public-key. There is a signature but no tagset.
			keySec = 3
			signSec = 4
		}
	case 4:
		keySec = 3
	default:
		return &Election{}, ErrEelectionInvalid
	}

	electionID = string(parts[0])
	if len(electionID) > MaxElectionIDSize {
		return &Election{}, ErrElectionIDTooBig
	}
	if !ValidElectionID.MatchString(electionID) {
		return &Election{}, ErrElectionIDInvalid
	}

	start, err = time.Parse(time.RFC1123Z, string(parts[1]))
	if err != nil {
		return &Election{}, errors.Wrap(err, ErrElectionStartInvalid)
	}

	end, err = time.Parse(time.RFC1123Z, string(parts[2]))
	if err != nil {
		return &Election{}, errors.Wrap(err, ErrElectionEndInvalid)
	}

	if tagsSec != 0 {
		tagSet, err = NewTagSet(parts[tagsSec])
		if err != nil {
			return &Election{}, errors.Wrap(err, ErrElectionInvalidTagSet)
		}
	} else {
		tagSet = nil
	}

	publicKey, err = NewPublicKey(parts[keySec])
	if err != nil {
		return &Election{}, errors.Wrap(err, ErrElectionInvalidKey)
	}

	if signSec != 0 {
		signature, err = NewSignature(parts[signSec])
		if err != nil {
			return &Election{}, errors.Wrap(err, ErrElectionInvalidSig)
		}
	} else {
		signature = nil
	}

	// All checks pass, create and return the election
	election := Election{
		electionID,
		start,
		end,
		tagSet,
		publicKey,
		signature,
	}
	return &election, nil
}

// Verify that the election has been property cryptographically signed
func (election *Election) VerifySignature() error {
	if !election.HasSignature() {
		return ErrEletionSigNotFound
	}
	s := election.ElectionID + "\n\n" + election.Start.Format(time.RFC1123Z) + "\n\n" + election.End.Format(time.RFC1123Z)
	if election.HasTagSet() {
		s += "\n\n" + election.TagSet.String()
	}
	s += "\n\n" + election.PublicKey.String()
	return election.Signature.VerifySignature(election.PublicKey, []byte(s))
}

// TagSets are optional, check to see if this election has them
func (election *Election) HasTagSet() bool {
	return election.TagSet != nil
}

// Signatures are generally required, but are sometimes optional (for example, when working with an Election before it is signed by the admin)
// This function checks to see if the Election has been signed. It does not verify the signature, but merely checks to see if it exists.
func (election *Election) HasSignature() bool {
	return election.Signature != nil
}

// Implements Stringer. Returns the string that would be expected in a PUT request to create the election
// The returned string is the same format as expected by NewElection
func (election Election) String() string {
	s := election.ElectionID + "\n\n" + election.Start.Format(time.RFC1123Z) + "\n\n" + election.End.Format(time.RFC1123Z)

	if election.HasTagSet() {
		s += "\n\n" + election.TagSet.String()
	}

	s += "\n\n" + election.PublicKey.String()

	if election.HasSignature() {
		s += "\n\n" + election.Signature.String()
	}

	return s
}
