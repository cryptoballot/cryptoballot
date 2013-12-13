package cryptoballot

import (
	"strings"
)

type FulfilledSignatureRequest struct {
	SignatureRequest
	BallotSignature Signature // BallotClerk signature signing off on the validity of the ballot
}

func NewFulfilledSignatureRequest(sigReq SignatureRequest, sig Signature) *FulfilledSignatureRequest {
	return &FulfilledSignatureRequest{
		sigReq,
		sig,
	}
}

func (fulfilled *FulfilledSignatureRequest) String() string {
	s := []string{
		fulfilled.SignatureRequest.String(),
		fulfilled.BallotSignature.String(),
	}
	return strings.Join(s, "\n\n")
}
