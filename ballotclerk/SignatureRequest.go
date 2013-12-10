package main

import (
	"bytes"
	"errors"
	. "github.com/wikiocracy/cryptoballot/cryptoballot"
	//"github.com/davecgh/go-spew/spew"
	"encoding/base64"
	"strings"
)

type SignatureRequest struct {
	ElectionID string
	RequestID  []byte // SHA512 (hex) of base64 encoded public-key
	PublicKey         // base64 encoded PEM formatted public-key
	Ballot     []byte // base64 encoded ballot blob, it could be either blinded or unblinded.
	Signature         // Voter signature for the ballot request
}

// Given a raw SignatureRequest-string (as a []byte) (see documentation for format), return a new SignatureRequest.
// Generally the SignatureRequest-string is coming from a client in a POST body.
// This will also verify the signature on the SignatureRequest and return an error if the request does not pass crypto verification
func NewSignatureRequest(rawSignatureRequest []byte) (*SignatureRequest, error) {
	var (
		err        error
		electionID string
		requestID  []byte
		publicKey  PublicKey
		ballot     []byte
		signature  Signature
	)

	parts := bytes.Split(rawSignatureRequest, []byte("\n\n"))

	if len(parts) != 5 {
		return &SignatureRequest{}, errors.New("Cannot read Signature Request. Invalid format")
	}

	electionID = string(parts[0])

	publicKey, err = NewPublicKey(parts[2])
	if err != nil {
		return &SignatureRequest{}, err
	}

	requestID = parts[1]
	if !bytes.Equal(requestID, publicKey.GetSHA512()) {
		return &SignatureRequest{}, errors.New("Invalid Request ID. A Request ID must be the (hex encoded) SHA512 of the voters public key.")
	}

	ballot = parts[3]
	if _, err := base64.Decode(make([]byte, base64.DecodedLen(len(ballot))), ballot); err != nil {
		return &SignatureRequest{}, errors.New("Ballot must be base64 encoded.")
	}

	signature, err = NewSignature(parts[4])
	if err != nil {
		return &SignatureRequest{}, err
	}

	sigReq := SignatureRequest{
		electionID,
		requestID,
		publicKey,
		ballot,
		signature,
	}

	// Verify the signature
	if err = signatureRequest.VerifySignature(); err != nil {
		return &SignatureRequest{}, err
	}

	// All checks pass
	return &sigReq, nil
}

func (sigReq *SignatureRequest) VerifySignature() error {
	s := []string{
		sigReq.ElectionID,
		sigReq.RequestID,
		sigReq.PublicKey.String(),
		sigReq.ballot,
	}

	return sigReq.Signature.VerifySignature(sigReq.PublicKey, []byte(strings.Join(s, "\n\n")))
}

func (sigReq *SignatureRequest) String() string {
	s := []string{
		sigReq.ElectionID,
		sigReq.RequestID,
		ballot.PublicKey.String(),
		ballot.ballot,
		ballot.Signature.String(),
	}
	return strings.Join(s, "\n\n")
}
