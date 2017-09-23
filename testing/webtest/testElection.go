package webtest

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	. "github.com/cryptoballot/cryptoballot/cryptoballot"
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
	adminPrivateKey, err := NewPrivateKey(PEMData)
	if err != nil {
		Fail(err)
	}

	// Sanity check
	checkPublicKey, err := adminPrivateKey.PublicKey()
	if err != nil {
		Fail(err)
	}
	if checkPublicKey.String() != adminUser.PublicKey.String() {
		Fail("Private and Public keys do not match")
	}

	// Create an election
	election := Election{
		ElectionID: "12345",
		Start:      time.Now(),
		End:        time.Now().Add(24 * time.Hour),
		PublicKey:  adminUser.PublicKey,
	}

	// Sign the election with the admin's key
	election.Signature, err = adminPrivateKey.Sign(election)
	if err != nil {
		Fail(err)
	}

	// Prepare to PUT the election to the Election Clerk server
	req, err := http.NewRequest("PUT", "http://localhost:8000/election/"+election.ElectionID, strings.NewReader(election.String()))
	if err != nil {
		Fail(err)
	}
	reqSig, err := adminPrivateKey.SignString("PUT /election/" + election.ElectionID)
	if err != nil {
		Fail(err)
	}
	req.Header.Add("X-Public-Key", adminUser.PublicKey.String())
	req.Header.Add("X-Signature", reqSig.String())

	// Do the request and handle the result
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		Fail(err)
	}
	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Print(string(body))
		Fail("Got server error: ", resp.Status)
	}
}
