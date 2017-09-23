package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	. "github.com/cryptoballot/cryptoballot/cryptoballot"
)

func main() {
	var noNewLine bool
	flag.BoolVar(&noNewLine, "n", false, "do not output the trailing newline")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println(`cryptoballot-signature-request generates a SignatureRequest from a Ballot stored in a file (or piped from stdin).

USAGE:
cryptoballot-signature-request <path-to-private-key.pem> <path-to-signing-public-key.pem> <path-to-ballot-file>
echo "full ballot string" | cryptoballot-signature-request <path-to-private-key.pem> <path-to-signing-public-key.pem>`)
		return
	}

	// Read in the private-key
	rawPEM, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	cryptoKey, err := NewPrivateKey(rawPEM)
	if err != nil {
		log.Fatal(err)
	}

	// Generate the public-key from the private-key
	voterPub, err := cryptoKey.PublicKey()
	if err != nil {
		log.Fatal(err)
	}

	// Read in the signing public key
	rawPEM, err = ioutil.ReadFile(flag.Arg(1))
	if err != nil {
		log.Fatal(err)
	}
	signingPub, err := NewPublicKey(rawPEM)
	if err != nil {
		log.Fatal(err)
	}

	// Read-in the ballot
	var inStream io.Reader
	if flag.NArg() == 3 {
		inStream, err = os.Open(flag.Arg(2))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		inStream = os.Stdin
	}
	rawBallot, err := ioutil.ReadAll(inStream)
	if err != nil {
		log.Fatal(err)
	}
	ballot, err := NewBallot(rawBallot)
	if err != nil {
		log.Fatal(err)
	}

	blindBallot, unblinder, err := ballot.Blind(signingPub)
	if err != nil {
		log.Fatal(err)
	}

	// Print the unblinder to stderr
	os.Stderr.WriteString(hex.EncodeToString(unblinder))

	// Create unsigned SignatureRequest
	signatureReq := SignatureRequest{
		ElectionID:  ballot.ElectionID,
		RequestID:   voterPub.GetSHA256(),
		PublicKey:   voterPub,
		BlindBallot: blindBallot,
	}

	// Sign the Signature Request with the voter's key
	signatureReq.Signature, err = cryptoKey.Sign(signatureReq)
	if err != nil {
		log.Fatal(err)
	}

	// Print the final SignatureRequest
	if noNewLine {
		fmt.Print(signatureReq)
	} else {
		fmt.Println(signatureReq)
	}
}
