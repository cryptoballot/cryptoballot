package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	. "github.com/wikiocracy/cryptoballot/cryptoballot"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	var noNewLine bool
	flag.BoolVar(&noNewLine, "n", false, "do not output the trailing newline")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println(`cryptoballot-signature-request generates a SignatureRequest from a Ballot stored in a file (or piped from stdin).

USAGE:
cryptoballot-signature-request <path-to-private-key.pem> <path-to-ballot-file>
echo "full ballot string" | cryptoballot-signature-request <path-to-private-key.pem>`)
		return
	}

	// Read in the private-key
	rawPEM, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	var i int
	var PEMBlock *pem.Block
	var cryptoKey *rsa.PrivateKey
	for {
		PEMBlock, rawPEM = pem.Decode(rawPEM)
		if PEMBlock == nil {
			break
		}
		if PEMBlock.Type != "RSA PRIVATE KEY" {
			continue
		}

		cryptoKey, err = x509.ParsePKCS1PrivateKey(PEMBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		i++
	}
	if i == 0 {
		log.Fatal("Could not find RSA PRIVATE KEY block in " + flag.Arg(0))
	}

	// Generate the public-key from the private-key
	voterPub, err := NewPublicKeyFromCryptoKey(&cryptoKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Read-in the ballot
	var inStream io.Reader
	if flag.NArg() == 2 {
		inStream, err = os.Open(flag.Arg(1))
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

	// Create unsigned SignatureRequest
	signatureReq := SignatureRequest{
		ElectionID: ballot.ElectionID,
		RequestID:  voterPub.GetSHA256(),
		PublicKey:  voterPub,
		BallotHash: ballot.GetSHA256(),
	}

	// Sign the Signature Request with the voter's key
	h := sha256.New()
	h.Write([]byte(signatureReq.String()))
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, cryptoKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		log.Fatal(err)
	}
	signatureReq.Signature = Signature(rawSignature)

	// Print the final SignatureRequest
	if noNewLine {
		fmt.Print(signatureReq)
	} else {
		fmt.Println(signatureReq)
	}
}
