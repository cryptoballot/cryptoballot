package cryptoballot

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
)

type SignatureRequest struct {
	ElectionID string
	RequestID  []byte // SHA512 (hex) of base64 encoded public-key
	PublicKey         // base64 encoded PEM formatted public-key
	BallotHash []byte // SHA512 (hex-encoded) of the ballot. This would generally be blinded.
	Signature         // Voter signature for the ballot request
}

// Given a raw Signature Request string (as a []byte -- see documentation for format), return a new SignatureRequest object.
// Generally the Signature Request string is coming from a voter in a POST body.
// This will also verify the signature on the SignatureRequest and return an error if the request does not pass crypto verification
func NewSignatureRequest(rawSignatureRequest []byte) (*SignatureRequest, error) {
	var (
		err        error
		electionID string
		requestID  []byte
		publicKey  PublicKey
		ballotHash []byte
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

	ballotHash = parts[3]
	n, err := hex.Decode(make([]byte, hex.DecodedLen(len(ballotHash))), ballotHash)
	if err != nil {
		return &SignatureRequest{}, errors.New("Ballot hash must be hex encoded.")
	}
	if n != sha512.Size {
		return &SignatureRequest{}, errors.New("You must provide exactly 512 bits for the blinded SHA512 ballot hash")
	}

	signature, err = NewSignature(parts[4])
	if err != nil {
		return &SignatureRequest{}, err
	}

	sigReq := SignatureRequest{
		electionID,
		requestID,
		publicKey,
		ballotHash,
		signature,
	}

	// Verify the signature
	if err = sigReq.VerifySignature(); err != nil {
		return &SignatureRequest{}, errors.New("Invalid signature. The signature provided does not cryptographically sign this Signature Request or does not match the public-key provided. " + err.Error())
	}

	// All checks pass
	return &sigReq, nil
}

// Verify the voter's signature attached to the SignatureRequest
func (sigReq *SignatureRequest) VerifySignature() error {
	s := []string{
		sigReq.ElectionID,
		string(sigReq.RequestID),
		sigReq.PublicKey.String(),
		string(sigReq.BallotHash),
	}

	return sigReq.Signature.VerifySignature(sigReq.PublicKey, []byte(strings.Join(s, "\n\n")))
}

// Implements Stringer. Outputs the same text representation we are expecting the voter to POST in their Signature Request.
func (sigReq *SignatureRequest) String() string {
	s := []string{
		sigReq.ElectionID,
		string(sigReq.RequestID),
		sigReq.PublicKey.String(),
		string(sigReq.BallotHash),
		sigReq.Signature.String(),
	}
	return strings.Join(s, "\n\n")
}

// Sign the blinded ballot hash attached to the Signature Request. It is the hex-encoded blinded SHA512 hash of the ballot.
func (sigReq *SignatureRequest) SignBallot(key *rsa.PrivateKey) (Signature, error) {
	rawBytes := make([]byte, hex.DecodedLen(len(sigReq.BallotHash))) //@@TODO: Make this a straight 64 bytes (512 bits)
	_, err := hex.Decode(rawBytes, sigReq.BallotHash)
	if err != nil {
		return Signature{}, err
	}

	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, rawBytes)
	if err != nil {
		return Signature{}, err
	}

	signature := Signature(rawSignature)
	return signature, nil
}
