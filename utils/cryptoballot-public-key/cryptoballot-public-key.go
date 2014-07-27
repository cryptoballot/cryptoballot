package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	. "github.com/wikiocracy/cryptoballot/cryptoballot"
	"io/ioutil"
	"log"
)

func main() {
	var noNewLine bool
	flag.BoolVar(&noNewLine, "n", false, "do not output the trailing newline")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println(`cryptoballot-public-key prints the public key associated with the provided private key.

USAGE:
cryptoballot-public-key <path-to-private-key.pem>

The same thing can be accomplished by OpenSSL like so: openssl rsa -in <path-to-private-key.pem> -pubout -outform DER | base64`)
		return
	}

	rawPEM, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	var publicKeys []PublicKey
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
		pk, err := NewPublicKeyFromCryptoKey(&cryptoKey.PublicKey)
		if err != nil {
			log.Fatal(err)
		}
		publicKeys = append(publicKeys, pk)
	}
	if len(publicKeys) == 0 {
		log.Fatal("Could not find RSA PRIVATE KEY block in " + flag.Arg(0))
	}

	for i, publicKey := range publicKeys {
		if noNewLine && i == len(publicKeys)-1 {
			fmt.Print(publicKey)
		} else {
			fmt.Println(publicKey)
		}
	}
}
