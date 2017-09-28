package webtest

import (
	"io/ioutil"
	"time"

	"github.com/cryptoballot/cryptoballot/clients/ballotbox"
	"github.com/cryptoballot/cryptoballot/clients/ballotclerk"
	. "github.com/cryptoballot/cryptoballot/cryptoballot"
)

func testEndToEnd() {

	// Boot up the election-clerk
	electionclerkCmd = runCommand("./electionclerk", "--config=electionclerk.conf")
	time.Sleep(2 * time.Second) // Give the electionclerk time to boot-up

	// Create an electionClerk client
	ballotclerkClient := ballotclerk.NewClient("http://localhost:8000")

	// Load admin user
	PEMData, err := ioutil.ReadFile("../data/admins-public.pem")
	if err != nil {
		Fail(err)
	}
	adminUser, err := NewUser(PEMData)
	if err != nil {
		Fail(err)
	}
	if adminUser == nil {
		Fail("adminUser == nil")
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

	// Get public key from ballotclerk server
	clerkPublicKey, err := ballotclerkClient.GetPublicKey()
	if err != nil {
		Fail(err)
	}

	// Load the voter's private and public key
	PEMData, err = ioutil.ReadFile("../data/voter-private.pem")
	if err != nil {
		Fail(err)
	}
	voterPrivateKey, err := NewPrivateKey(PEMData)
	if err != nil {
		Fail(err)
	}
	voterPublicKey, err := voterPrivateKey.PublicKey()
	if err != nil {
		Fail(err)
	}

	// Admin creates election
	election := Election{
		ElectionID: "testelection",
		Start:      time.Now(),
		End:        time.Now().Add(time.Hour),
		PublicKey:  adminUser.PublicKey,
	}

	// Admin signs elections
	electionSignature, err := adminPrivateKey.SignString(election.String())
	if err != nil {
		Fail(err)
	}
	election.Signature = electionSignature

	// Verify the election was signed correctly
	err = election.VerifySignature()
	if err != nil {
		Fail(err)
	}

	// PUT the election to the Election Clerk server
	err = ballotclerkClient.PutElection(&election, adminPrivateKey)
	if err != nil {
		Fail(err)
	}

	// GET the election back again just to make sure it's correct
	election2, err := ballotclerkClient.GetElection(election.ElectionID)
	if err != nil {
		Fail(err)
	}
	if election.ElectionID != election2.ElectionID {
		Fail("election.ElectionID != election2.ElectionID")
	}

	// Create a ballot for the election.
	ballot := &Ballot{
		ElectionID: election.ElectionID,
		Vote:       Vote{"Santa Clause", "Tooth Fairy", "Krampus"},
		BallotID:   "7djfgy83hf92f93hf93hdhajdf",
	}

	// Blind the ballot
	blindBallot, unblinder, err := ballot.Blind(clerkPublicKey)
	if err != nil {
		Fail(err)
	}

	// Create a signature request
	signatureRequest := &SignatureRequest{
		ElectionID:  election.ElectionID,
		RequestID:   voterPublicKey.GetSHA256(),
		PublicKey:   voterPublicKey.Bytes(),
		BlindBallot: blindBallot,
	}
	signatureRequest.Signature, err = voterPrivateKey.SignString(signatureRequest.String())
	if err != nil {
		Fail(err)
	}

	// Do the signature request
	fulfilled, err := ballotclerkClient.PostSignatureRequest(signatureRequest, voterPrivateKey)
	if err != nil {
		Fail(err)
	}

	// Unblind the ballot using the FulfilledSignatureRequest
	err = ballot.Unblind(clerkPublicKey, fulfilled.BallotSignature, unblinder)
	if err != nil {
		Fail(err)
	}

	// Boot up the ballot-box
	ballotboxCmd = runCommand("./ballotbox", "--config=ballotbox.conf")
	time.Sleep(2 * time.Second) // Give the ballotbox time to boot-up

	// Create ballotbox client
	ballotboxClient := ballotbox.NewClient("http://localhost:8001")

	// PUT the ballot
	err = ballotboxClient.PutBallot(ballot)
	if err != nil {
		Fail(err)
	}

	// Get all the ballots
	allBallots, err := ballotboxClient.GetAllBallots(election.ElectionID)
	if err != nil {
		Fail(err)
	}

	// Verify all the ballots
	for _, ballot := range allBallots {
		err = ballot.VerifyBlindSignature(clerkPublicKey)
		if err != nil {
			Fail(err)
		}
	}

}
