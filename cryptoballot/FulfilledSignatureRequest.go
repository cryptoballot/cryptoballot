package cryptoballot

import (
	"strings"
)

type FulfilledSignatureRequest struct {
	SignatureRequest
	BallotSignature Signature // BallotClerk signature signing off on the validity of the ballot
}

func (fulfilled *FulfilledSignatureRequest) String() string {
	s := []string{
		fulfilled.SignatureRequest.String(),
		fulfilled.BallotSignature.String(),
	}
	return strings.Join(s, "\n\n")
}
