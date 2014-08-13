package main

import (
	"fmt"
	. "github.com/cryptoballot/cryptoballot/cryptoballot"
	"io/ioutil"
	"net/http"
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

	signatureReqest, err := NewSignatureRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err = signatureReqest.VerifySignature(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// @@TODO: Check the validity of the voter with the voter-list server.
	// @@TODO: Check that this voter has not already retreived a fulfilled signature request.

	// Sign the ballot
	ballotSig, err := signatureReqest.SignBallot(conf.signingKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fulfilledsignatureRequest := NewFulfilledSignatureRequestFromParts(*signatureReqest, ballotSig)

	//@@TODO: store the fulfilledsignatureRequest in the database

	fmt.Fprint(w, fulfilledsignatureRequest)
	return
}
