package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/wikiocracy/cryptoballot/cryptoballot"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println(`cryptoballot-sign prints the cryptographically signed signature of a file (or piped from stdin).

USAGE:
cryptoballot-sign <path-to-private-key.pem> <path-to-file-to-sign>
echo -n "string to sign" | cryptoballot-sign <path-to-private-key.pem>

The same thing can be accomplished by OpenSSL like so: echo -n "string to sign" | openssl dgst -sha512 -sign <path-to-private-key.pem> | base64 `)
		return
	}

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

	var inStream io.Reader
	if flag.NArg() == 2 {
		inStream, err = os.Open(flag.Arg(1))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		inStream = os.Stdin
	}

	hash := sha512.New()
	_, err = io.Copy(hash, inStream)
	if err != nil {
		log.Fatal(err)
	}

	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, cryptoKey, crypto.SHA512, hash.Sum(nil))
	if err != nil {
		log.Fatal(err)
	}

	signature := cryptoballot.Signature(rawSignature)
	fmt.Println(signature)
}
