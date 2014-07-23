package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/lib/pq"
	. "github.com/wikiocracy/cryptoballot/cryptoballot"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
)

const (
	schemaQuery = `	CREATE EXTENSION IF NOT EXISTS hstore;
					CREATE TABLE elections (
					  election_id char(128) UNIQUE NOT NULL, --@@TODO: change to 64 on move to SHA256
					  startdate timestamp NOT NULL,
					  enddate timestamp NOT NULL,
					  tags hstore, 
					  election text NOT NULL
					);
					CREATE INDEX elections_id_idx ON elections (election_id);
					CREATE INDEX elections_tags_idx on elections (tags);`

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
	spew.Config.DisableMethods = true
	bootstrap()

	// Bootstrap is complete, let's serve some REST
	//@@TODO BEAST AND CRIME protection
	//@@TODO SSL only

	http.HandleFunc("/vote/", voteHandler)         // Casting votes and viewing votes. See vote-handler.go
	http.HandleFunc("/election/", electionHandler) // Creating elections and viewing election metadata. See election-handler.go
	http.HandleFunc("/admins", adminsHandler)      // View admins, their public keys and their perms

	log.Println("Listning on port " + strconv.Itoa(conf.port))

	err := http.ListenAndServe(":"+strconv.Itoa(conf.port), nil)

	if err != nil {
		log.Fatal("Error starting http server: ", err)
	}
}

// Bootstrap parses flags and config files, and set's up the database connection.
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

	// Set up the admin users and register their public keys
	pemdata, err := ioutil.ReadFile(conf.adminKeysPath)
	if err != nil {
		log.Fatal("Error loading admin-keys file: ", err)
	}
	admins, err = NewUserSet(pemdata)
	if err != nil {
		log.Fatal("Error loading admin user data: ", err)
	}

	// If we are in 'set-up' mode, set-up the database and exit
	// @@TODO: schema.sql should be found in some path that is configurable by the user.
	if *set_up_opt {
		_, err = db.Exec(schemaQuery)
		if err != nil {
			log.Fatal("Error creating database schema: ", err.(pq.PGError).Get('M'))
		}
		fmt.Println("Database set-up complete. Please run again without --set-up-db")
		os.Exit(0)
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

// Display all admin user information when a user asks for "/admins"
func adminsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed. Only GET is allowed here.", http.StatusMethodNotAllowed)
		return
	}

	fmt.Fprint(w, admins.String())
}
