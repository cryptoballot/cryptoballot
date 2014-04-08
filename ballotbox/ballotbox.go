package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	//"github.com/davecgh/go-spew/spew"
	"github.com/lib/pq"
	"github.com/lib/pq/hstore"
	. "github.com/wikiocracy/cryptoballot/cryptoballot"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	schemaQuery = `CREATE TABLE ballots_<election-id> (
					  ballot_id char(128) NOT NULL, 
					  tags hstore, 
					  ballot text NOT NULL
					);

					CREATE INDEX ballot_id_idx ON ballots_<election-id> (ballot_id);
					CREATE INDEX tags_idx on ballots_<election-id> (tags);`
)

var (
	db             *sql.DB
	ballotClerkKey PublicKey   // Used to verify signatures on ballots
	adminKeys      []PublicKey // Admin requests must be signed by an admin
	adminPEMs      []pem.Block // We publish the public PEMBlocks of all admin users
	conf           Config
)

type parseError struct {
	Err  string
	Code int
}

func (err parseError) Error() string {
	return err.Err
}

func main() {
	// Bootstrap parses flags and config files, and set's up the database connection.
	bootstrap()

	// Bootstrap is complete, let's serve some REST
	//@@TODO BEAST AND CRIME protection
	//@@TODO SSL only

	http.HandleFunc("/vote/", voteHandler)

	//@@TODO /admin/ adminHandler

	log.Println("Listning on port " + strconv.Itoa(conf.port))

	err := http.ListenAndServe(":"+strconv.Itoa(conf.port), nil)

	if err != nil {
		log.Fatal("Error starting http server: ", err)
	}
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

	// Set up the admin public keys
	publicKeyPEM, err := ioutil.ReadFile(conf.adminKeysPath)
	if err != nil {
		return
	}
	for {
		var PEMBlock *pem.Block
		PEMBlock, publicKeyPEM = pem.Decode(publicKeyPEM)
		if PEMBlock == nil {
			break
		}
		if PEMBlock.Type != "PUBLIC KEY" {
			log.Fatal("Found unexpected " + PEMBlock.Type + " in " + conf.adminKeysPath)
		}
		adminPEMs = append(adminPEMs, *PEMBlock)

		adminPublicCryptoKey, err := x509.ParsePKIXPublicKey(PEMBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		adminPublicKey, err := NewPublicKeyFromCryptoKey(adminPublicCryptoKey.(*rsa.PublicKey))
		if err != nil {
			log.Fatal(err)
		}
		adminKeys = append(adminKeys, adminPublicKey)
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
	if r.Method == "GET" {
		handleGETVote(w, r, electionID, ballotID)
	} else if r.Method == "PUT" {
		handlePUTVote(w, r, electionID, ballotID)
	} else if r.Method == "HEAD" {
		handleHEADVote(w, r, electionID, ballotID)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func handleGETVote(w http.ResponseWriter, r *http.Request, electionID string, ballotID string) {
	var ballotString []byte
	err := db.QueryRow("select ballot from ballots where ballot_id = $1", ballotID).Scan(&ballotString)
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
	var count int
	err = db.QueryRow("select count(*) from ballots where ballot_id = $1", ballot.BallotID).Scan(&count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if count != 0 {
		http.Error(w, "Ballot with this ID already exists", http.StatusForbidden)
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
	var ballotString sql.RawBytes
	rows, err := db.Query("select ballot from ballots")
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

	_, err := db.Exec("INSERT INTO ballots (ballot_id, ballot, tags) VALUES ($1, $2, $3)", ballot.BallotID, ballot.String(), tags)
	return err
}
