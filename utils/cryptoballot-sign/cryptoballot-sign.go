package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	. "github.com/cryptoballot/cryptoballot/cryptoballot"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	var noNewLine bool
	var trimNewLine bool
	var naiveSign bool
	var SHA256 bool
	flag.BoolVar(&noNewLine, "n", false, "do not output the trailing newline")
	flag.BoolVar(&trimNewLine, "d", false, "trim the linux newline character (0A) from the end of the input")
	flag.BoolVar(&naiveSign, "naive", false, "Naively sign the message without any padding or hashing")
	flag.BoolVar(&SHA256, "sha256", false, "Apply a SHA256 hash before naive signing. Only used in combination with --naive. ")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println(`cryptoballot-sign prints the cryptographically signed signature of a file (or piped from stdin). 
You should pass the --naive and --sha256 options to simulate an election-clerk signing a ballot.

USAGE EXAMPLES:
cryptoballot-sign <path-to-private-key.pem> <path-to-file-to-sign>
echo "string to sign" | cryptoballot-sign -d <path-to-private-key.pem>
cryptoballot-sign --naive --sha256 -d <path-to-clerk-private-key.pem> <path-to-ballot-to-sign>

The same thing can be accomplished by OpenSSL like so: echo -n "string to sign" | openssl dgst -sha256 -sign <path-to-private-key.pem> | base64 `)
		return
	}

	if SHA256 && !naiveSign {
		log.Fatal("You passed the --sha256 option without the --naive option. This is not allowed. By default normal non-naive signing automatically applies a SHA256 hash and as part of the RSA signing process.")
	}

	rawPEM, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	cryptoKey, err := NewPrivateKey(rawPEM)
	if err != nil {
		log.Fatal(err)
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
	var signature Signature
	if naiveSign {
		if SHA256 {
			hash := sha256.New()
			hash.Write(target)
			target = hash.Sum(nil)
		}
		// Compute the signature naively
		signature, err = cryptoKey.SignRawBytes(target)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// Compute the signature normally
		signature, err = cryptoKey.SignBytes(target)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Print results
	if noNewLine {
		fmt.Print(signature)
	} else {
		fmt.Println(signature)
	}
}
