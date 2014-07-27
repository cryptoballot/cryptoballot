package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/wikiocracy/cryptoballot/cryptoballot"
	"io/ioutil"
	"log"
)

func main() {
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println(`cryptoballot-getid prints the ID of a public-key to be used as part of a SignatureRequest or User.

To ensure that unique IDs are well formed, cryptoballot requires that the IDs of a SignatureRequest or a User (administrator or auditor)
correspond one-to-one with their public keys. Specifically, an ID must be the hex-encoded SHA256 of the base64 encoded public key. 
This ID can be generated manually using openssl, but to save time and frustration, this utility will do it for you.

USAGE:
cryptoballot-getid <path-to-public-key.pem>

The same thing can be accomplished with OpenSSL like so: openssl rsa -pubin -in <path-to-public-key.pem> -outform DER | base64 | tr -d '\n' | openssl sha -sha256`)
		return
	}

	rawPEM, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	var i int
	var PEMBlock *pem.Block
	for {
		PEMBlock, rawPEM = pem.Decode(rawPEM)
		if PEMBlock == nil {
			break
		}
		if PEMBlock.Type != "PUBLIC KEY" {
			continue
		}

		cryptoKey, err := x509.ParsePKIXPublicKey(PEMBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}

		publicKey, err := cryptoballot.NewPublicKeyFromCryptoKey(cryptoKey.(*rsa.PublicKey))
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(string(publicKey.GetSHA256()))
		i++
	}

	if i == 0 {
		log.Fatal("Could not find PUBLIC KEY block in " + flag.Arg(0))
	}
}
