package main

import (
	"database/sql"
	"errors"
	"fmt"
	. "github.com/cryptoballot/cryptoballot/cryptoballot"
	"log"
	"net/http"
	"strconv"
	"strings"
)

const (
	ballotsQuery = `CREATE EXTENSION IF NOT EXISTS hstore;
					CREATE TABLE ballots_<election-id> (
					  ballot_id char(128) NOT NULL, --@@TODO: change to 64 on move to SHA256
					  tags hstore, 
					  ballot text NOT NULL
					);
					CREATE INDEX ballot_id_idx_<election-id> ON ballots_<election-id> (ballot_id);
					CREATE INDEX tags_idx_<election-id> on ballots_<election-id> (tags);`
)

var (
	db             *sql.DB
	ballotClerkKey PublicKey // Used to verify signatures on ballots
	admins         UserSet   // Admin requests must be signed by an admin. We publish the public keys of all admin users
	conf           config
)

type config struct {
	configFilePath string
	database       struct {
		host               string
		port               int
		user               string
		password           string
		dbname             string
		sslmode            string
		maxIdleConnections int
	}
	port             int                 // Listen port -- generally it should be 443
	readmePath       string              // Path to the readme file
	readme           []byte              // Static content for serving to the root readme (at "/")
	electionclerkURL string              // URL for electionclerk
	adminUsers       UserSet             // Admin users. Pulled from electionclerk server on bootstrap
	clerkKey         PublicKey           // Election Clerk public key. Pulled from electionclerk server on bootstrap
	elections        map[string]Election // List of valid elections. Pulled from electionclerk server on bootstrap, updated by data pushed from electionclerk.
}

type parseError struct {
	Err  string
	Code int
}

func (err parseError) Error() string {
	return err.Err
}

func main() {
	bootstrap()

	// Bootstrap is complete, let's serve some REST
	//@@TODO BEAST AND CRIME protection
	//@@TODO SSL only

	http.HandleFunc("/vote/", voteHandler) // Casting votes and viewing votes. See vote-handler.go

	log.Println("Listning on port " + strconv.Itoa(conf.port))

	err := http.ListenAndServe(":"+strconv.Itoa(conf.port), nil)

	if err != nil {
		log.Fatal("Error starting http server: ", err)
	}
}

// When a voter or an admin makes a priviledged request that requires verification
// of their public-key, they are required to include the following HTTP headers:
// 1. X-Public-Key: The user's base64 encoded public key.
// 2. X-Signature: Signature for this request. The user should sign the HTTP request string which includes
//    the method and the path (for example PUT /vote/1234/939fhdsjkksdkl0903f). This signature should be
//    base64 encoded
// This function verifies that these headers are constructed properly and that the signature
// cryptographically signs the request. This function does not check the cryptographic veracity of the body.
func verifySignatureHeaders(r *http.Request) error {
	rawpk := r.Header.Get("X-Public-Key")
	if rawpk == "" {
		return errors.New("Missing X-Public-Key header. ")
	}
	pk, err := NewPublicKey([]byte(rawpk))
	if err != nil {
		return errors.New("Error parsing X-Public-Key header. " + err.Error())
	}

	rawsig := r.Header.Get("X-Signature")
	if rawsig == "" {
		return errors.New("Missing X-Signature header. ")
	}
	sig, err := NewSignature([]byte(rawsig))
	if err != nil {
		return errors.New("Error parsing X-Signature header. " + err.Error())
	}

	// Verify the signature against the request string. For example PUT /vote/1234/939fhdsjkksdkl0903f...
	err = sig.VerifySignature(pk, []byte(r.Method+" "+r.RequestURI))
	if err != nil {
		return errors.New("Cryptographic verification of X-Signature header failed. " + err.Error())
	}

	return nil
}

// Sync Elections to database tables
// This will create database tables for any election that doesn't already have one
// If a database table is found starting with `ballots_` that doesn't correspond to a
// an Election an error will occur.
func syncElectionToDB(elections map[string]Election) error {
	// Build a list of elections found in the database
	electionsInDB := make(map[string]bool)
	rows, err := db.Query("SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'ballots_'")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tablename string
		err := rows.Scan(tablename)
		if err != nil {
			return err
		}
		electionID := strings.TrimPrefix(tablename, "ballots_")
		electionsInDB[electionID] = true
	}

	// Compare elections in the database to elections passes in
	// Create any missing tables
	for electionID, _ := range elections {
		if electionsInDB[electionID] {
			// Election matches - mark as false to denote that it has been processed and is OK
			electionsInDB[electionID] = false
		} else {
			// Create missing table
			_, err = db.Exec(strings.Replace(ballotsQuery, "<election-id>", electionID, -1))
			if err != nil {
				return err
			}
		}
	}

	// Check for extrenous elections in the database. If any remaining items in the map are TRUE we have an extraneous table
	for tablename, extra := range electionsInDB {
		if extra {
			return fmt.Errorf("Found extraneous %s table in database. This table does not correspond to any existing election.", tablename)
		}
	}

	// Success
	return nil
}
