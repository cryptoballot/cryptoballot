package cryptoballot

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

type SignatureRequest struct {
	ElectionID string
	RequestID  []byte // SHA256 (hex) of base64 encoded public-key
	PublicKey         // base64 encoded PEM formatted public-key
	BallotHash []byte // SHA256 (hex-encoded) of the ballot. This would generally be blinded.
	Signature         // Voter signature for the ballot request
}

// Given a raw Signature Request string (as a []byte -- see documentation for format), return a new SignatureRequest object.
// Generally the Signature Request string is coming from a voter in a POST body.
// This will also verify the signature on the SignatureRequest and return an error if the request does not pass crypto verification
func NewSignatureRequest(rawSignatureRequest []byte) (*SignatureRequest, error) {
	var (
		err        error
		hasSign    bool
		electionID string
		requestID  []byte
		publicKey  PublicKey
		ballotHash []byte
		signature  Signature
	)

	// The SignatureRequest is composed of individual components seperated by double linebreaks
	parts := bytes.Split(rawSignatureRequest, []byte("\n\n"))

	numParts := len(parts)
	switch {
	case numParts == 4:
		hasSign = false
	case numParts == 5:
		hasSign = true
	default:
		return &SignatureRequest{}, errors.New("Cannot read Signature Request. Invalid format")
	}

	electionID = string(parts[0])

	publicKey, err = NewPublicKey(parts[2])
	if err != nil {
		return &SignatureRequest{}, err
	}

	requestID = parts[1]
	if !bytes.Equal(requestID, publicKey.GetSHA256()) {
		return &SignatureRequest{}, errors.New("Invalid Request ID. A Request ID must be the (hex encoded) SHA256 of the voters public key.")
	}

	ballotHash = parts[3]
	n, err := hex.Decode(make([]byte, hex.DecodedLen(len(ballotHash))), ballotHash)
	if err != nil {
		return &SignatureRequest{}, errors.New("Ballot hash must be hex encoded.")
	}
	if n != sha256.Size {
		return &SignatureRequest{}, errors.New("You must provide exactly 256 bits for the blinded SHA256 ballot hash")
	}

	if hasSign {
		signature, err = NewSignature(parts[4])
		if err != nil {
			return &SignatureRequest{}, err
		}
	} else {
		signature = nil
	}

	sigReq := SignatureRequest{
		electionID,
		requestID,
		publicKey,
		ballotHash,
		signature,
	}

	// All checks pass
	return &sigReq, nil
}

// Verify the voter's signature attached to the SignatureRequest
func (sigReq *SignatureRequest) VerifySignature() error {
	if !sigReq.HasSignature() {
		return errors.New("Could not verify signature: Signature does not exist")
	}
	s := sigReq.ElectionID + "\n\n" + string(sigReq.RequestID) + "\n\n" + sigReq.PublicKey.String() + "\n\n" + string(sigReq.BallotHash)

	return sigReq.Signature.VerifySignature(sigReq.PublicKey, []byte(s))
}

// Sign the blinded ballot hash attached to the Signature Request. It is the hex-encoded blinded SHA256 hash of the ballot.
func (sigReq *SignatureRequest) SignBallot(key *rsa.PrivateKey) (Signature, error) {
	rawBytes := make([]byte, hex.DecodedLen(len(sigReq.BallotHash))) //@@TODO: Make this a straight 32 bytes (256 bits)
	_, err := hex.Decode(rawBytes, sigReq.BallotHash)
	if err != nil {
		return Signature{}, err
	}

	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, rawBytes)
	if err != nil {
		return Signature{}, err
	}

	signature := Signature(rawSignature)
	return signature, nil
}

// Signatures are generally required, but are sometimes optional (for example, for working with the SignatureRequest before it is signed by the voter)
// This function checks to see if the SignatureRequest has been signed by the voter
func (sigReq *SignatureRequest) HasSignature() bool {
	return sigReq.Signature != nil
}

// Implements Stringer. Outputs the same text representation we are expecting the voter to POST in their Signature Request.
// This is also the same format that is expected in NewSignatureRequest
func (sigReq SignatureRequest) String() string {
	s := sigReq.ElectionID + "\n\n" + string(sigReq.RequestID) + "\n\n" + sigReq.PublicKey.String() + "\n\n" + string(sigReq.BallotHash)
	if sigReq.HasSignature() {
		s += "\n\n" + sigReq.Signature.String()
	}
	return s
}
