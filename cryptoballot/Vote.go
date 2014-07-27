package cryptoballot

import (
	"errors"
	"strconv"
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

// Given a raw slice of bytes, construct a Vote
// @@TODO: A custom splitter that checks for errors as it goes might be faster than splitting the whole thing and then looping the results to check for errors.
func NewVote(rawVote []byte) (Vote, error) {
	if len(rawVote) > maxVoteSize {
		return Vote{}, errors.New("Vote has too many bytes. A vote may have a maximum of " + strconv.Itoa(maxVoteSize) + " characters, including seperators.")
	}
	vote := Vote(strings.Split(string(rawVote), "\n"))
	if len(vote) > MaxVoteOptions {
		return Vote{}, errors.New("Vote has too many options. A vote may have a maximum of " + strconv.Itoa(MaxVoteOptions) + " option lines.")
	}
	for i, voteItem := range vote {
		if len(voteItem) > MaxVoteBytes {
			return Vote{}, errors.New("Vote item as position " + strconv.Itoa(i) + " is too large. Each vote-item line may have a maximu of " + strconv.Itoa(MaxVoteBytes) + " bytes.")
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
