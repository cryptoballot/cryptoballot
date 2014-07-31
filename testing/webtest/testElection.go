package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	. "github.com/wikiocracy/cryptoballot/cryptoballot"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func testElection() {
	// Load admin user
	PEMData, err := ioutil.ReadFile("../data/admins-public.pem")
	if err != nil {
		Fail(err)
	}
	adminUser, err := NewUser(PEMData)
	if err != nil {
		Fail(err)
	}

	// Load admin key
	PEMData, err = ioutil.ReadFile("../data/admin-private.1.key")
	if err != nil {
		Fail(err)
	}
	PEMBlock, _ := pem.Decode(PEMData)
	if PEMBlock == nil {
		Fail("Failed to parse PEMBLock for ../data/admin-private.1.key")
	}
	adminKey, err := x509.ParsePKCS1PrivateKey(PEMBlock.Bytes)
	if err != nil {
		Fail(err)
	}

	// Create an election
	election := Election{
		ElectionID: "12345",
		Start:      time.Now(),
		End:        time.Now().Add(24 * time.Hour),
		PublicKey:  adminUser.PublicKey,
	}

	// Sign the election with the admin's key
	h := sha256.New()
	h.Write([]byte(election.String()))
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, adminKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		Fail(err)
	}
	election.Signature = Signature(rawSignature)

	// PUT the election to the Election Clerk server
	req, err := http.NewRequest("PUT", "http://localhost:8000/election/"+election.ElectionID, strings.NewReader(election.String()))
	if err != nil {
		Fail(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		Fail(err)
	}
	if resp.StatusCode != 200 {
		Fail("Got server error", resp.Status)
	}
}
