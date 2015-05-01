package main

import (
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	. "github.com/cryptoballot/cryptoballot/cryptoballot"
	"log"
	"net/http"
	"strconv"
)

const (
	schemaQuery = `	CREATE EXTENSION IF NOT EXISTS hstore;
					CREATE TABLE elections (
					  election_id char(128) UNIQUE NOT NULL,
					  startdate timestamp NOT NULL,
					  enddate timestamp NOT NULL,
					  tags hstore, 
					  election text NOT NULL
					);
					CREATE INDEX elections_id_idx ON elections (election_id);
					CREATE INDEX elections_tags_idx on elections (tags);`

	sigreqsQuery = `CREATE TABLE sigreqs_<election-id> (
					  request_id char(64) NOT NULL,
					  public_key text NOT NULL, 
					  ballot_hash char(64) NOT NULL,
					  signature text NOT NULL,
					  ballot_signature text NOT NULL
					);

					CREATE INDEX request_id_idx ON sigreqs_<election-id> (request_id);`
)

var (
	db   *sql.DB // Global postgres database collection where we store completed FufilledSignatureRequests
	conf Config  // Global config object
)

type Config struct {
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
	port           int        // Listen port -- generally it should be 443
	adminKeysPath  string     // Path to admin-users public-key PEM file. This file will be published at /admins
	adminUsers     UserSet    // Admin users
	readmePath     string     // Path to readme file
	readme         []byte     // Static content for serving to the root readme (at "/")
	signingKeyPath string     // Path to the private key used for signing ballots
	signingKey     PrivateKey // Signing key. @@TODO: For now we have a single key -eventually there should be one key per election
	voterlistURL   string     // URL for the voter-list server
	ballotboxURL   string     // URL for the ballot-box server
}

func main() {
	// Bootstrap parses flags and config files, and set's up the database connection.
	bootstrap()

	// Bootstrap is complete, let's serve some REST
	//@@TODO BEAST AND CRIME protection
	//@@TODO SSL only
	http.HandleFunc("/", rootHandler)               // Displays the readme
	http.HandleFunc("/sign", signHandler)           // Provides the ability to POST new Signature Requests. See signature-handler.go
	http.HandleFunc("/election", electionHandler)   // Send to election handler. Used for getting all elections
	http.HandleFunc("/election/", electionHandler)  // Creating elections and viewing election metadata. See election-handler.go
	http.HandleFunc("/admins", adminsHandler)       // View admins, their public keys and their perms
	http.HandleFunc("/publickey", publicKeyHandler) // Reports this servers public key

	log.Println("Election Clerk server started listening on port", conf.port)

	err := http.ListenAndServe(":"+strconv.Itoa(conf.port), nil)

	if err != nil {
		log.Fatal("Error starting http server: ", err)
	}
}

// When a user accesses "/" display the readme
func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.RequestURI != "/" {
		http.Error(w, "404 Not Found.", http.StatusNotFound)
		return
	}
	_, err := w.Write(conf.readme)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return
}

// Display the public key used to sign ballots when a user asks for "/publickey"
// @@TODO: Cache
func publicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed. Only GET is allowed here.", http.StatusMethodNotAllowed)
		return
	}

	publicKey, err := conf.signingKey.PublicKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pemBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKey.Bytes(),
	}
	pem.Encode(w, &pemBlock)
	return
}

// Display all admin user information when a user asks for "/admins"
func adminsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed. Only GET is allowed here.", http.StatusMethodNotAllowed)
		return
	}

	fmt.Fprint(w, conf.adminUsers)
}

// When a voter or an admin makes a priviledged request that requires verification
// of their public-key, they are required to include the following HTTP headers:
// 1. X-Public-Key: The user's base64 encoded public key.
// 2. X-Signature: Signature for this request. The user should sign the HTTP request string which includes
//    the method and the path (for example PUT /vote/1234/939fhdsjkksdkl0903f). This signature should be
//    base64 encoded. The signature should use SHA256 as the hashing function.
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

// Check to see if the election already exists in the database
func electionExists(electionID string) (bool, error) {
	err := db.QueryRow("select 1 from elections where election_id = $1 limit 1", electionID).Scan()
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		} else {
			return false, err
		}
	}
	return true, nil
}
