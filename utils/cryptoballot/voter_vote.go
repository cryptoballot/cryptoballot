package main

import (
	"io/ioutil"
	"log"

	"github.com/cryptoballot/cryptoballot/cryptoballot"
	"github.com/urfave/cli"
)

func actionVoterVote(c *cli.Context) error {
	filename := c.Args().First()

	if filename == "" {
		log.Fatal("Please specify an balliot file to PUT to the ballotbox server")
	}

	if PrivateKey == nil {
		log.Fatal("Please specify a private key pem file with --key (eg: `--key=path/to/mykey.pem`)")
	}

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	ballot, err := cryptoballot.NewBallot(content)
	if err != nil {
		log.Fatal(err)
	}

	// Get public key from ballotclerk server
	clerkPublicKey, err := BallotClerkClient.GetPublicKey()
	if err != nil {
		log.Fatal(err)
	}

	// Blind the ballot
	blindBallot, unblinder, err := ballot.Blind(clerkPublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Create a signature request
	signatureRequest := &cryptoballot.SignatureRequest{
		ElectionID:  ballot.ElectionID,
		RequestID:   PublicKey.GetSHA256(),
		PublicKey:   PublicKey.Bytes(),
		BlindBallot: blindBallot,
	}
	signatureRequest.Signature, err = PrivateKey.SignString(signatureRequest.String())
	if err != nil {
		log.Fatal(err)
	}

	// Do the signature request
	fulfilled, err := BallotClerkClient.PostSignatureRequest(signatureRequest, PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Unblind the ballot using the FulfilledSignatureRequest
	err = ballot.Unblind(clerkPublicKey, fulfilled.BallotSignature, unblinder)
	if err != nil {
		log.Fatal(err)
	}

	// PUT the ballot
	err = BallotBoxClient.PutBallot(ballot)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}
