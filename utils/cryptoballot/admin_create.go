package main

import (
	"io/ioutil"
	"log"

	"github.com/cryptoballot/cryptoballot/cryptoballot"
	"github.com/urfave/cli"
)

func actionAdminCreate(c *cli.Context) error {
	filename := c.Args().First()

	if filename == "" {
		log.Fatal("Please specify an election file to PUT to the ballotclerk server")
	}

	if PrivateKey == nil {
		log.Fatal("Please specify a private key pem file with --key (eg: `--key=path/to/mykey.pem`)")
	}

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	election, err := cryptoballot.NewElection(content)
	if err != nil {
		log.Fatal(err)
	}

	// Sign election if needed
	if !election.HasSignature() {
		election.Signature, err = PrivateKey.SignString(election.String())
		if err != nil {
			log.Fatal(err)
		}
	}

	// Verify the election was signed correctly
	err = election.VerifySignature()
	if err != nil {
		log.Fatal(err)
	}

	// PUT the election to the Election Clerk server
	err = BallotClerkClient.PutElection(election, PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	return nil
}
