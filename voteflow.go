package main

// NOTES
// See https://bitbucket.org/bumble/bumble-golang-common/src/master/key/publickey.go

import (
	"bytes"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"github.com/bmizerany/pq"
	//"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	db   *sql.DB
	conf Config
)

const (
	minPublicKeyBits = 1024
)

type parseError struct {
	Err  string
	Code int
}

func (err parseError) Error() string {
	return err.Err
}

func bootstrap() {
	config_path_opt := flag.String("config", "./test.conf", "Path to config file. The config file must be owned by and only readable by this user.")
	set_up_opt := flag.Bool("set-up-db", false, "Set up fresh database tables and schema. This should be run once before normal operations can occur.")
	flag.Parse()

	//@@TODO Check to make sure the config file is readable only by this user (unless the user passed --insecure)
	err := conf.loadFromFile(*config_path_opt)
	if err != nil {
		log.Fatal("Error parsing config file. ", err)
	}

	//@@TODO: Check to make sure the sslmode is set to "verify-full" (unless the user passed --insecure)
	//        See pq package documentation

	// Connect to the database and set-up
	db, err = sql.Open("postgres", conf.voteDBConnectionString())
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	// Set the maximum number of idle connections in the connection pool. `-1` means default (2 idle connections in the pool)
	if conf.voteDB.maxIdleConnections != -1 {
		db.SetMaxIdleConns(conf.voteDB.maxIdleConnections)
	}

	// If we are in 'set-up' mode, set-up the database and exit
	// @@TODO: schema.sql should be found in some path that is configurable by the user (voteflow-path environment variable?)
	if *set_up_opt {
		schema_sql, err := ioutil.ReadFile("./schema.sql")
		if err != nil {
			log.Fatal("Error loading database schema: ", err)
		}
		_, err = db.Exec(string(schema_sql))
		if err != nil {
			log.Fatal("Error loading database schema: ", err.(pq.PGError).Get('M'))
		}
		fmt.Println("Database set-up complete. Please run again without --set-up-db")
		os.Exit(0)
	}
}

func voteHandler(w http.ResponseWriter, r *http.Request) {
	//@@TODO: Check r.TLS

	electionID, ballotID, err := parseVoteRequest(r)
	if err != nil {
		http.Error(w, err.Error(), err.(parseError).Code)
		return
	}

	// If there is no ballotID and we are GETing, just return the full-list of votes for the electionID
	if ballotID == nil {
		if r.Method == "GET" {
			handleGETVoteBatch(w, r, electionID)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	// We are dealing with an individual vote
	if r.Method == "GET" {
		handleGETVote(w, r, electionID, ballotID)
	} else if r.Method == "PUT" {
		handlePUTVote(w, r, electionID, ballotID)
	} else if r.Method == "DELETE" {
		handleDELETEVote(w, r, electionID, ballotID)
	} else if r.Method == "HEAD" {
		handleHEADVote(w, r, electionID, ballotID)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func handleGETVote(w http.ResponseWriter, r *http.Request, electionID string, ballotID BallotID) {
	w.Write([]byte("OK, let's GET a vote!"))
}

func handlePUTVote(w http.ResponseWriter, r *http.Request, electionID string, ballotID BallotID) {
	// If X-Voteflow-Public-Key was passed, it's already been verified, so we just need to check that it exists
	pk := r.Header.Get("X-Voteflow-Public-Key")
	if pk == "" {
		http.Error(w, "X-Voteflow-Public-Key header required for PUT operations", http.StatusBadRequest)
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

	w.Write([]byte(ballot.String()))
}

func handleDELETEVote(w http.ResponseWriter, r *http.Request, electionID string, ballotID BallotID) {
	// If X-Voteflow-Public-Key was passed, it's already been verified, so we just need to check that it exists
	pk := r.Header.Get("X-Voteflow-Public-Key")
	if pk == "" {
		http.Error(w, "X-Voteflow-Public-Key header required for DELETE operations", http.StatusBadRequest)
		return
	}

	w.Write([]byte("OK, let's DELETE a vote!"))
}

func handleHEADVote(w http.ResponseWriter, r *http.Request, electionID string, ballotID BallotID) {
	w.Write([]byte("OK, let's HEAD a vote!"))
}

func handleGETVoteBatch(w http.ResponseWriter, r *http.Request, electionID string) {
	w.Write([]byte("Full vote batch response to go here"))
}

// returns electionID, BallotID, publicKey (base64 encoded) and an error
func parseVoteRequest(r *http.Request) (electionID string, ballotID BallotID, err error) {
	// Parse URL and route
	urlparts := strings.Split(r.RequestURI, "/")

	// Check for the correct number of request parts
	if len(urlparts) < 3 || len(urlparts) > 4 {
		err = parseError{"Invalid number of request parts", http.StatusNotFound}
		return
	}

	// Get the electionID
	electionID = urlparts[2]

	// If we are only length 3, that's it, we are asking for a full report / ballot roll for an election
	if len(urlparts) == 3 {
		return
	}

	// Get the ballotID (hex encoded SHA512 of base64 encoded public-key)
	ballotID, err = NewBallotID([]byte(urlparts[3]))
	if err != nil {
		err = parseError{"Invalid Ballot ID. " + err.Error(), http.StatusBadRequest}
		return
	}

	// If the user has provided a public key in the header (as an authentication), verify it
	if r.Header.Get("X-Voteflow-Public-Key") != "" {
		pk, suberr := NewPublicKey([]byte(r.Header.Get("X-Voteflow-Public-Key")))
		if suberr != nil {
			err = parseError{"Invalid Public Key. " + suberr.Error(), http.StatusBadRequest}
		}
		// Check to make sure the passed ballotID in the url matches the public key's BallotID
		if !bytes.Equal(pk.GetBallotID(), ballotID) {
			err = parseError{"The signature and public key provided in the header does not match the Ballot ID in the URL", http.StatusBadRequest}
			return
		}

		// Verify the signature headers, do a cryptographic check to make sure the header and Method / URL request is signed
		if suberr := verifySignatureHeaders(r); suberr != nil {
			err = parseError{suberr.Error(), http.StatusBadRequest}
			return
		}

	}

	// All checks pass
	return
}

func verifySignatureHeaders(r *http.Request) error {
	pk, err := NewPublicKey([]byte(r.Header.Get("X-Voteflow-Public-Key")))
	if err != nil {
		return errors.New("Error parsing X-Voteflow-Public-Key header. " + err.Error())
	}

	sig, err := NewSignature([]byte(r.Header.Get("X-Voteflow-Signature")))
	if err != nil {
		return errors.New("Error parsing X-Voteflow-Signature header. " + err.Error())
	}

	// Verify the signature against the request string. For example PUT /vote/1234/939fhdsjkksdkl0903f...
	err = sig.VerifySignature(pk, []byte(r.Method+" "+r.RequestURI))
	if err != nil {
		return errors.New("Error verifying signature. " + err.Error())
	}

	return nil
}

func main() {
	// Bootstrap parses flags and config files, and set's up the database connection.
	bootstrap()

	// Bootstrap is complete, let's serve some REST
	//@@TODO BEAST AND CRIME protection
	//@@TODO SSL only

	http.HandleFunc("/vote/", voteHandler)

	//@@TODO /admin/ adminHandler

	log.Println("Listning on port 8000")

	err := http.ListenAndServe(":8000", nil)

	if err != nil {
		log.Fatal("Error starting http server: ", err)
	}

}
