package cryptoballot

import (
	"bytes"
	"github.com/phayes/errors"
)

type FulfilledSignatureRequest struct {
	SignatureRequest
	BallotSignature Signature // ElectionClerk signature signing off on the validity of the ballot
}

var (
	ErrFulfilledSignatureRequestInvalid = errors.New("Cannot read Fulfilled Signature Request. Invalid format")
)

// Given the raw bytes of a Fulfilled Signature Request, get a FulfilledSignatureRequest object
func NewFulfilledSignatureRequest(rawBytes []byte) (*FulfilledSignatureRequest, error) {
	parts := bytes.Split(rawBytes, []byte("\n\n"))

	if len(parts) != 6 {
		return &FulfilledSignatureRequest{}, ErrFulfilledSignatureRequestInvalid
	}

	signatureRequest, err := NewSignatureRequest(bytes.Join(parts[:5], []byte("\n\n")))
	if err != nil {
		return &FulfilledSignatureRequest{}, err
	}
	ballotSignature, err := NewSignature(parts[5])
	if err != nil {
		return &FulfilledSignatureRequest{}, err
	}

	return &FulfilledSignatureRequest{
		*signatureRequest,
		ballotSignature,
	}, nil
}

// Construct a FulfilledSignatureRequest from a SignatureRequest and a clerk Signature
func NewFulfilledSignatureRequestFromParts(sigReq SignatureRequest, sig Signature) *FulfilledSignatureRequest {
	return &FulfilledSignatureRequest{
		sigReq,
		sig,
	}
}

// Implements Stringer
func (fulfilled FulfilledSignatureRequest) String() string {
	return fulfilled.SignatureRequest.String() + "\n\n" + fulfilled.BallotSignature.String()
}
