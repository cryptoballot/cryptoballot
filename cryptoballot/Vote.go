package cryptoballot

import (
	"strings"
)

type Vote []string // Ordered list of choices represented by git addresses

func NewVote(rawVote []byte) (Vote, error) {
	return Vote(strings.Split(string(rawVote), "\n")), nil
}

func (vote *Vote) String() string {
	var output string
	for i, voteItem := range *vote {
		output += voteItem
		if i != len(*vote)-1 {
			output += "\n"
		}
	}
	return output
}
