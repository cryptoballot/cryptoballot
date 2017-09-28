package main

import (
	"fmt"
	"io/ioutil"
	"net/http"

	. "github.com/cryptoballot/cryptoballot/cryptoballot"
)

// Handle a signature-request coming from a user
func signHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed. Only POST is allowed here.", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	signatureRequest, err := NewSignatureRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err = signatureRequest.VerifySignature(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// @@TODO: Check the validity of the voter with the voter-list server.
	// @@TODO: Check that this voter has not already retreived a fulfilled signature request.

	// Sign the ballot
	ballotSig, err := conf.signingKey.BlindSign(signatureRequest.BlindBallot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a fulfilled signature request
	fulfilled := &FulfilledSignatureRequest{
		SignatureRequest: *signatureRequest,
		BallotSignature:  ballotSig,
	}

	//@@TODO: store the fulfilledsignatureRequest in the database

	fmt.Fprint(w, fulfilled.String())
	return
}
