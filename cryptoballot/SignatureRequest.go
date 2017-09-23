package cryptoballot

import (
	"bytes"

	"github.com/phayes/errors"
)

type SignatureRequest struct {
	ElectionID  string
	RequestID   []byte // SHA256 (hex) of base64 encoded public-key
	PublicKey          // base64 encoded PEM formatted public-key
	BlindBallot        // Blinded ballot (blinded full-domain-hash of the ballot).
	Signature          // Voter signature for the ballot request
}

var (
	ErrSignatureRequestInvalid    = errors.New("Cannot read Signature Request. Invalid format")
	ErrSignatureRequestPublicKey  = errors.New("Cannot read Signature Request. Invalid Public Key")
	ErrSignatureRequestID         = errors.New("Invalid SignatureRequest ID. A SignatureRequest ID must be the (hex encoded) SHA256 of the voters public key.")
	ErrSignatureRequestBallotHash = errors.New("Invalid Signature Request. Ballot hash must be hex encoded.")
	ErrSignatureRequestHashBits   = errors.New("Invalid Signature Request. You must provide exactly 256 bits for the blinded SHA256 ballot hash")
	ErrSignatureRequestSigInvalid = errors.New("Invalid Signature Request. Could not parse voter signature")
	ErrSignatureRequestSigNotFoud = errors.New("Could not verify voter signature on Signature Request: voter-signature does not exist")
	ErrSignatureRequestSignBallot = errors.New("Could not sign ballot")
)

// Given a raw Signature Request string (as a []byte -- see documentation for format), return a new SignatureRequest object.
// Generally the Signature Request string is coming from a voter in a POST body.
// This will also verify the signature on the SignatureRequest and return an error if the request does not pass crypto verification
func NewSignatureRequest(rawSignatureRequest []byte) (*SignatureRequest, error) {
	var (
		err         error
		hasSign     bool
		electionID  string
		requestID   []byte
		publicKey   PublicKey
		blindBallot BlindBallot
		signature   Signature
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
		return &SignatureRequest{}, ErrSignatureRequestInvalid
	}

	electionID = string(parts[0])

	publicKey, err = NewPublicKey(parts[2])
	if err != nil {
		return &SignatureRequest{}, errors.Wrap(err, ErrSignatureRequestPublicKey)
	}

	requestID = parts[1]
	if !bytes.Equal(requestID, publicKey.GetSHA256()) {
		return &SignatureRequest{}, ErrSignatureRequestID
	}

	blindBallot, err = NewBlindBallot(parts[3])
	if err != nil {
		return &SignatureRequest{}, errors.Wrap(err, ErrSignatureRequestBallotHash)
	}

	if hasSign {
		signature, err = NewSignature(parts[4])
		if err != nil {
			return &SignatureRequest{}, errors.Wrap(err, ErrSignatureRequestSigInvalid)
		}
	} else {
		signature = nil
	}

	sigReq := SignatureRequest{
		electionID,
		requestID,
		publicKey,
		blindBallot,
		signature,
	}

	// All checks pass
	return &sigReq, nil
}

// Verify the voter's signature attached to the SignatureRequest
func (sigReq *SignatureRequest) VerifySignature() error {
	if !sigReq.HasSignature() {
		return ErrSignatureRequestSigNotFoud
	}
	s := sigReq.StringWithoutSignature()

	return sigReq.Signature.VerifySignature(sigReq.PublicKey, []byte(s))
}

// Signatures are generally required, but are sometimes optional (for example, for working with the SignatureRequest before it is signed by the voter)
// This function checks to see if the SignatureRequest has been signed by the voter
func (sigReq *SignatureRequest) HasSignature() bool {
	return sigReq.Signature != nil
}

// Implements Stringer. Outputs the same text representation we are expecting the voter to POST in their Signature Request.
// This is also the same format that is expected in NewSignatureRequest
func (sigReq SignatureRequest) String() string {
	s := sigReq.StringWithoutSignature()
	if sigReq.HasSignature() {
		s += "\n\n" + sigReq.Signature.String()
	}
	return s
}

// StringWithoutSignature returns the SignatureRequest as a string, without the signature of the requesting client.
func (sigReq SignatureRequest) StringWithoutSignature() string {
	s := sigReq.ElectionID + "\n\n" + string(sigReq.RequestID) + "\n\n" + sigReq.PublicKey.String() + "\n\n" + sigReq.BlindBallot.String()
	return s
}
