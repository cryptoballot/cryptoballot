package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/lib/pq/hstore"
	. "github.com/wikiocracy/cryptoballot/cryptoballot"
	"io/ioutil"
	"net/http"
	"strings"
)

// Main vote handler. A user may GET a single vote, a list of all votes, or PUT (cast) their vote
func voteHandler(w http.ResponseWriter, r *http.Request) {
	electionID, ballotID, err := parseVoteRequest(r)
	if err != nil {
		http.Error(w, err.Error(), err.(parseError).Code)
		return
	}

	// If there is no ballotID and we are GETing, just return the full-list of votes for the electionID
	if ballotID == "" {
		if r.Method == "GET" {
			handleGETVoteBatch(w, r, electionID)
			return
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	// We are dealing with an individual vote
	switch r.Method {
	case "GET":
		handleGETVote(w, r, electionID, ballotID)
	case "PUT":
		handlePUTVote(w, r, electionID, ballotID)
	case "HEAD":
		handleHEADVote(w, r, electionID, ballotID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// returns electionID, BallotID, publicKey (base64 encoded) and an error
func parseVoteRequest(r *http.Request) (electionID string, ballotID string, err error) {
	// Parse URL and route
	urlparts := strings.Split(r.RequestURI, "/")

	// Check for the correct number of request parts
	if len(urlparts) < 3 || len(urlparts) > 4 {
		err = parseError{"Invalid number of url parts. 404 Not Found.", http.StatusNotFound}
		return
	}

	// Get the electionID
	electionID = urlparts[2]
	if len(electionID) > MaxElectionIDSize || !ValidElectionID.MatchString(electionID) {
		err = parseError{"Invalid Election ID. 404 Not Found.", http.StatusNotFound}
		return
	}

	// If we are only length 3, that's it, we are asking for a full report / ballot roll for an election
	if len(urlparts) == 3 || urlparts[3] == "" {
		return
	}

	// Get the ballotID (hex encoded SHA512 of base64 encoded public-key)
	ballotID = urlparts[3]
	if len(ballotID) > MaxBallotIDSize || !ValidBallotID.MatchString(ballotID) {
		err = parseError{"Invalid Ballot ID. 404 Not Found.", http.StatusNotFound}
	}

	// If the user has provided a signature of the request in the headers, verify it
	if r.Header.Get("X-Voteflow-Signature") != "" {
		// Verify the signature headers, do a cryptographic check to make sure the header and Method / URL request is signed
		if suberr := verifySignatureHeaders(r); suberr != nil {
			err = parseError{suberr.Error(), http.StatusBadRequest}
			return
		}
	}

	// All checks pass
	return
}

func handleGETVote(w http.ResponseWriter, r *http.Request, electionID string, ballotID string) {
	// Check to make sure the Election exists
	if exists, err := electionExists(electionID); !exists {
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			http.Error(w, "Election not found", http.StatusNotFound)
		}
		return
	}

	var ballotString []byte
	err := db.QueryRow("select ballot from ballots_ "+electionID+" where ballot_id = $1", ballotID).Scan(&ballotString)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Ballot not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
	w.Write(ballotString)
}

func handlePUTVote(w http.ResponseWriter, r *http.Request, electionID string, ballotID string) {
	// Check to make sure the Election exists
	if exists, err := electionExists(electionID); !exists {
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			http.Error(w, "Election not found", http.StatusNotFound)
		}
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ballot, err := NewBallot(body)
	if err != nil {
		http.Error(w, "Error reading ballot. "+err.Error(), http.StatusBadRequest)
		return
	}

	// Verify the signature
	err = verifyBallotSignature(ballot)
	if err != nil {
		http.Error(w, "Error verifying ballot signature. "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Check the database to see if the ballot already exists
	err = db.QueryRow("select 1 from ballots_"+electionID+" where ballot_id = $1", ballot.BallotID).Scan()
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Ballot with this ID already exists", http.StatusForbidden)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	err = saveBallotToDB(ballot)
	if err != nil {
		http.Error(w, "Error saving ballot. "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleHEADVote(w http.ResponseWriter, r *http.Request, electionID string, ballotID string) {
	w.Write([]byte("Not implemented yet!"))
}

func handleGETVoteBatch(w http.ResponseWriter, r *http.Request, electionID string) {
	// First check to make sure the election exists
	if exists, err := electionExists(electionID); !exists {
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			http.Error(w, "Election not found", http.StatusNotFound)
		}
		return
	}

	var ballotString sql.RawBytes
	rows, err := db.Query("select ballot from ballots+_" + electionID)
	if err != nil {
		http.Error(w, "Database query error. "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&ballotString)
		if err != nil {
			http.Error(w, "\n\nDatabase error. "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(ballotString)
		w.Write([]byte("\n\n\n"))
	}
	err = rows.Err()
	if err != nil {
		http.Error(w, "\n\nDatabase error. "+err.Error(), http.StatusInternalServerError)
	}
}

func verifyBallotSignature(ballot *Ballot) error {
	// First we need to get the public key we will be using the verify the ballot.
	//@@TODO: One public key per election

	// First we need to load the public key from the ballotClerk server if this value has not already been set
	if ballotClerkKey.IsEmpty() {
		resp, err := http.Get(conf.ballotclerkURL + "/publickey")
		if err != nil {
			return errors.New("Error fetching public key from Ballot Clerk Server. " + err.Error())
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.New("Error fetching public key from Ballot Clerk Server. " + err.Error())
		}

		PEMBlock, _ := pem.Decode(body)
		if PEMBlock == nil || PEMBlock.Type != "RSA PUBLIC KEY" {
			return errors.New("Error fetching public key from Ballot Clerk Server. Could not find an RSA PUBLIC KEY block")
		}
		publicKey, err := NewPublicKey([]byte(base64.StdEncoding.EncodeToString(PEMBlock.Bytes)))
		if err != nil {
			return errors.New("Error fetching public key from Ballot Clerk Server. " + err.Error())
		}
		ballotClerkKey = publicKey
	}

	// Verify the ballot
	return ballot.VerifySignature(ballotClerkKey)
}

// Load a ballot from the backend postgres database - returns a pointer to a ballot.
func loadBallotFromDB(ElectionID string, ballotID string) (*Ballot, error) {
	return nil, errors.New("Not implemented")
}

func saveBallotToDB(ballot *Ballot) error {
	// Frist transform the tagset into an hstore
	var tags hstore.Hstore
	tags.Map = make(map[string]sql.NullString, len(ballot.TagSet))
	for key, value := range ballot.TagSet.Map() {
		tags.Map[key] = sql.NullString{value, true}
	}

	_, err := db.Exec("INSERT INTO ballots_"+ballot.ElectionID+" (ballot_id, ballot, tags) VALUES ($1, $2, $3)", ballot.BallotID, ballot.String(), tags)
	return err
}
