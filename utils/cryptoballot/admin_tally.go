package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/Sam-Izdat/govote"
	"github.com/urfave/cli"
)

func actionAdminTally(c *cli.Context) error {
	electionid := c.Args().First()

	// Get public key from ballotclerk server
	clerkPublicKey, err := BallotClerkClient.GetPublicKey()
	if err != nil {
		log.Fatal(err)
	}

	// Get all the ballots
	allBallots, err := BallotBoxClient.GetAllBallots(electionid)
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signature on all ballots
	for _, ballot := range allBallots {
		err = ballot.VerifyBlindSignature(clerkPublicKey)
		if err != nil {
			log.Fatal(err)
		}
	}

	// TODO: Verify that no two ballots have the same ID

	// TODO: Verify all fulfilledSignatureRequests (if has sufficient permission)

	// Get a list of all candidates
	candidatesmap := map[string]bool{}
	for _, ballot := range allBallots {
		for _, vote := range ballot.Vote {
			candidatesmap[vote] = true
		}
	}
	candidates := []string{}
	for candidate := range candidatesmap {
		candidates = append(candidates, candidate)
	}

	// Create a schulze poll
	schulze, err := govote.Schulze.New(candidates)
	if err != nil {
		log.Fatal(err)
	}

	// Add ballots to the poll
	for _, ballot := range allBallots {
		schulze.AddBallot(ballot.Vote)
	}

	// Calculate result using schulze (condorcet)
	result, _, err := schulze.Evaluate()
	if err != nil {
		log.Fatal(err)
	}

	if len(result) == 0 {
		log.Fatal("No election result")
	}

	// Print the winner
	fmt.Println("winner: ", strings.Join(result, ", "))

	return nil
}
