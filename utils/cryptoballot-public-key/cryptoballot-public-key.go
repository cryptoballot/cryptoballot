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
	"github.com/wikiocracy/cryptoballot/cryptoballot"
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

	// Read the source
	target, err := ioutil.ReadAll(inStream)
	if err != nil {
		log.Fatal(err)
	}

	// Check for the commen error of there being a trailing newline (0A) character.
	lastByte := target[len(target)-1]
	if lastByte == 0x0A {
		if trimNewLine {
			target = target[0 : len(target)-1]
		} else {
			log.Println("Warning: Your input contains a trailing newline character (0A). You may want to run this again with the -d flag.")
		}
	}

	// Compute the signature
	hash := sha256.New()
	hash.Write(target)
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, cryptoKey, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		log.Fatal(err)
	}

	signature := cryptoballot.Signature(rawSignature)
	if noNewLine {
		fmt.Print(signature)
	} else {
		fmt.Println(signature)
	}
}
