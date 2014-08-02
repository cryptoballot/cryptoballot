package cryptoballot

import (
	"github.com/phayes/errors"
	"strings"
)

// Votes are an ordered list of choices. You may change MaxVoteOptions to set the maximum number of choices.
// For a standard first-past-the-post election this would be set to 1
const MaxVoteOptions = 64

// You may set the maximum number of bytes per vote-option here.
const MaxVoteBytes = 256

// The total maximum vote-size is options*chracters + seperator characters
var maxVoteSize = (MaxVoteOptions * MaxVoteBytes) + MaxVoteOptions

// A Vote is an ordered list of choices as strings
// It's up to the counting / tallying applications to assign meaning to these strings
type Vote []string

var (
	ErrVoteTooBig         = errors.Newf("Vote has too many bytes. A vote may have a maximum of %i characters, including seperators", maxVoteSize)
	ErrVoteTooManyOptions = errors.Newf("Vote has too many options")
	ErrVoteOptionTooBig   = errors.Newf("Vote option has too many characters")
)

// Given a raw slice of bytes, construct a Vote
// @@TODO: A custom splitter that checks for errors as it goes might be faster than splitting the whole thing and then looping the results to check for errors.
func NewVote(rawVote []byte) (Vote, error) {
	if len(rawVote) > maxVoteSize {
		return Vote{}, ErrVoteTooBig
	}
	vote := Vote(strings.Split(string(rawVote), "\n"))
	if len(vote) > MaxVoteOptions {
		return Vote{}, errors.Wrapf(ErrVoteTooManyOptions, "A vote may have a maximum of %i option lines", MaxVoteOptions)
	}
	for i, voteItem := range vote {
		if len(voteItem) > MaxVoteBytes {
			return Vote{}, errors.Wrapf(ErrVoteOptionTooBig, "Vote item as position %i is too large. Each vote-item line may have a maximum of %i bytes", i, MaxVoteBytes)
		}
	}
	return vote, nil
}

// Get the string representation of a Vote
func (vote Vote) String() string {
	var output string
	for i, voteItem := range vote {
		output += voteItem
		if i != len(vote)-1 {
			output += "\n"
		}
	}
	return output
}
