package cryptoballot

import (
	"bytes"
)

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
