package main

import (
	"database/sql"
	. "github.com/cryptoballot/cryptoballot/cryptoballot"
	"github.com/lib/pq/hstore"
	"io/ioutil"
	"net/http"
	"strings"
)

func electionHandler(w http.ResponseWriter, r *http.Request) {
	// Parse URL and route
	urlparts := strings.Split(r.RequestURI, "/")

	// If the user is asking for `/election` or `/election/` then give them all the elections
	if r.RequestURI == "/election" || r.RequestURI == "/election/" {
		handleGETAllElections(w, r)
		return
	}

	// Check for the correct number of request parts
	if len(urlparts) != 3 {
		http.Error(w, "Invalid URL. 404 Not Found.", http.StatusNotFound)
		return
	}

	// Get the electionID
	electionID := urlparts[2]

	// Check for valid election ID
	if len(electionID) > MaxElectionIDSize || !ValidElectionID.MatchString(electionID) {
		http.Error(w, "Invalid Election ID. 404 Not Found.", http.StatusNotFound)
		return
	}

	switch r.Method {
	case "GET":
		handleGETElection(w, r, electionID)
	case "PUT":
		handlePUTElection(w, r, electionID)
	case "HEAD":
		//@@TODO: handleHEADElection(w, r, electionID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handlePUTElection(w http.ResponseWriter, r *http.Request, electionID string) {
	err := verifySignatureHeaders(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	election, err := NewElection(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if election.ElectionID != electionID {
		http.Error(w, "Election ID mismatch between body and URL", http.StatusBadRequest)
		return
	}
	if election.PublicKey.String() != r.Header.Get("X-Public-Key") {
		http.Error(w, "Public Key mismatch between headers and body", http.StatusBadRequest)
		return
	}

	// Verify the signature on the election
	err = election.VerifySignature()
	if err != nil {
		http.Error(w, "Error verifying election signature. "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check to make sure this admin exists and has permission to administer elections
	admin := conf.adminUsers.GetUser(election.PublicKey)
	if admin == nil {
		http.Error(w, "Could not find admin with the provided public key of "+election.PublicKey.String(), http.StatusForbidden)
		return
	}
	if !admin.HasPerm("election-admin") {
		http.Error(w, "This user does not have the `election-admin` permission", http.StatusForbidden)
		return
	}

	// All checks pass. Save the election
	err = saveElectionToDB(election)
	if err != nil {
		http.Error(w, "Error saving election: "+err.Error(), http.StatusInternalServerError)
	}
}

func saveElectionToDB(election *Election) error {
	// Frist transform the tagset into an hstore
	var tags hstore.Hstore
	tags.Map = make(map[string]sql.NullString, len(election.TagSet))
	for key, value := range election.TagSet.Map() {
		tags.Map[key] = sql.NullString{String: value, Valid: true}
	}

	_, err := db.Exec("INSERT INTO elections (election_id, election, startdate, enddate, tags) VALUES ($1, $2, $3, $4, $5)", election.ElectionID, election.String(), election.Start, election.End, tags)
	if err != nil {
		return err
	}

	// Create the sigreqa table for storing signature requests
	_, err = db.Exec(strings.Replace(sigreqsQuery, "<election-id>", election.ElectionID, -1))
	if err != nil {
		return err
	}

	//@@TODO - tell ballotbox database about election

	return nil
}

func handleGETElection(w http.ResponseWriter, r *http.Request, electionID string) {
	var rawElection []byte
	err := db.QueryRow("SELECT election FROM elections WHERE election_id = $1", electionID).Scan(&rawElection)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Could not find election with ID "+electionID, http.StatusNotFound)
		} else {
			http.Error(w, "Error reading election from database: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	w.Write(rawElection)
	return
}

func handleGETAllElections(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT election FROM elections")
	if err != nil {
		http.Error(w, "Error reading elections from database: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(w) // Will this work? Can I scan into a io.Writer?
		if err != nil {
			http.Error(w, "Error reading elections from database: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	return
}
