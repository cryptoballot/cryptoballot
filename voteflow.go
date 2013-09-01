package main

// NOTES
// See https://bitbucket.org/bumble/bumble-golang-common/src/master/key/publickey.go

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256" //@@TODO: Move both ID and encryption to SHA512
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/bmizerany/pq"
	//"github.com/davecgh/go-spew/spew"
	"github.com/dlintw/goconf"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type Ballot struct {
	PublicKey string // base64 encoded PEM formatted public-key
	ID        string // SHA256 of base64 encoded public-key
	Raw       string // Signed, ordered, and line seperated list git addresses
	Vote      Vote   // Ordered list of choices
}

type Vote []string // Ordered list of choices represented by git addresses

var (
	db   *sql.DB
	conf Config
)

type parseError struct {
	Err  string
	Code int
}

func (err parseError) Error() string {
	return err.Err
}

type Config struct {
	configFile string
	voteDB     struct {
		host               string
		port               int
		user               string
		password           string
		dbname             string
		sslmode            string
		maxIdleConnections int
	}
}

func (config *Config) loadFromFile(filepath string) (err error) {
	config.configFile = filepath

	c, err := goconf.ReadConfigFile(filepath)
	if err != nil {
		return
	}

	config.voteDB.host, err = c.GetString("vote-db", "host")
	if err != nil {
		return
	}

	config.voteDB.port, err = c.GetInt("vote-db", "port")
	if err != nil {
		return
	}

	config.voteDB.user, err = c.GetString("vote-db", "user")
	if err != nil {
		return
	}

	config.voteDB.password, err = c.GetString("vote-db", "password")
	if err != nil {
		return
	}

	config.voteDB.dbname, err = c.GetString("vote-db", "dbname")
	if err != nil {
		return
	}

	config.voteDB.sslmode, err = c.GetString("vote-db", "sslmode")
	if err != nil {
		return
	}

	// For max_idle_connections missing should translates to -1
	if c.HasOption("vote-db", "max_idle_connections") {
		config.voteDB.maxIdleConnections, err = c.GetInt("vote-db", "max_idle_connections")
		if err != nil {
			return
		}
	} else {
		config.voteDB.maxIdleConnections = -1
	}

	return
}

func (config *Config) voteDBConnectionString() (connection string) {
	if config.voteDB.host != "" {
		connection = fmt.Sprint(connection, "host=", config.voteDB.host, " ")
	}
	if config.voteDB.port != 0 {
		connection = fmt.Sprint(connection, "port=", config.voteDB.port, " ")
	}
	if config.voteDB.user != "" {
		connection = fmt.Sprint(connection, "user=", config.voteDB.user, " ")
	}
	if config.voteDB.password != "" {
		connection = fmt.Sprint(connection, "password=", config.voteDB.password, " ")
	}
	if config.voteDB.dbname != "" {
		connection = fmt.Sprint(connection, "dbname=", config.voteDB.dbname, " ")
	}
	if config.voteDB.sslmode != "" {
		connection = fmt.Sprint(connection, "sslmode=", config.voteDB.sslmode)
	}
	return
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

	voteBatchID, ballotID, err := parseVoteRequest(r)
	if err != nil {
		http.Error(w, err.Error(), err.(parseError).Code)
		return
	}

	// If there is no ballotID and we are GETing, just return the full-list of votes for the voteBatchID
	if ballotID == "" {
		if r.Method == "GET" {
			handleGETVoteBatch(w, r, voteBatchID)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	// We are dealing with an individual vote
	if r.Method == "GET" {
		handleGETVote(w, r, voteBatchID, ballotID)
	} else if r.Method == "PUT" {
		handlePUTVote(w, r, voteBatchID, ballotID)
	} else if r.Method == "DELETE" {
		handleDELETEVote(w, r, voteBatchID, ballotID)
	} else if r.Method == "HEAD" {
		handleHEADVote(w, r, voteBatchID, ballotID)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func handleGETVote(w http.ResponseWriter, r *http.Request, voteBatchID int64, ballotID string) {
	w.Write([]byte("OK, let's GET a vote!"))
}

func handlePUTVote(w http.ResponseWriter, r *http.Request, voteBatchID int64, ballotID string) {
	// If X-Voteflow-Public-Key was passed, it's already been verified, so we just need to check that it exists
	pk := r.Header.Get("X-Voteflow-Public-Key")
	if pk == "" {
		http.Error(w, "X-Voteflow-Public-Key header required for PUT operations", http.StatusBadRequest)
		return
	}
	w.Write([]byte("OK, let's PUT a vote!"))
}

func handleDELETEVote(w http.ResponseWriter, r *http.Request, voteBatchID int64, ballotID string) {
	w.Write([]byte("OK, let's DELETE a vote!"))
}

func handleHEADVote(w http.ResponseWriter, r *http.Request, voteBatchID int64, ballotID string) {
	w.Write([]byte("OK, let's DELETE a vote!"))
}

func handleGETVoteBatch(w http.ResponseWriter, r *http.Request, voteBatchID int64) {
	w.Write([]byte("Full vote batch response to go here"))
}

// returns voteBatchID, BallotID, publicKey (base64 encoded) and an error
func parseVoteRequest(r *http.Request) (voteBatchID int64, ballotID string, err error) {
	// Parse URL and route
	urlparts := strings.Split(r.RequestURI, "/")

	// Check for the correct number of request parts
	if len(urlparts) < 3 || len(urlparts) > 4 {
		err = parseError{"Invalid number of request parts", http.StatusNotFound}
		return
	}

	// Get the voteBatchID
	voteBatchID, suberr := strconv.ParseInt(urlparts[2], 10, 64)
	if suberr != nil {
		err = parseError{"Vote Batch ID must be numeric. : " + suberr.Error(), http.StatusBadRequest}
		return
	}

	// If we are only length 3, that's it, we are only asking for a voteBatch
	if len(urlparts) == 3 {
		return
	}

	// Get the ballotID (hex encoded SHA256 of base64 encoded public-key)
	ballotID = urlparts[3]

	// SHA256 is 64 characters long and is a valid hex
	if len(ballotID) != 64 {
		err = parseError{"Invalid Ballot ID. A ballot ID is a hex encoded SHA256 of the base64 encoded public-key.", http.StatusBadRequest}
		return
	}
	if _, suberr := hex.DecodeString(ballotID); suberr != nil {
		err = parseError{"Invalid Ballot ID. " + suberr.Error(), http.StatusBadRequest}
		return
	}

	// If the user has provided a public key in the header (as an authentication), verify it
	pk := r.Header.Get("X-Voteflow-Public-Key")
	if pk != "" {
		// First check to make sure the ballotID and the public-key match (BallotID is SHA256 of public-key)
		// @@TODO this can be more direct in Go 1.2
		h := sha256.New()
		h.Write([]byte(pk))
		pkHash := hex.EncodeToString(h.Sum(nil))
		if pkHash != ballotID {
			err = parseError{"The signature and public key provided in the header does not match the Ballot ID in the URL", http.StatusBadRequest}
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
	pk := r.Header.Get("X-Voteflow-Public-Key")
	sig := r.Header.Get("X-Voteflow-Signature")

	// If we are verifying a signature, we must have both a public key and a signature in the format of "GET /url/path/requested"
	if pk == "" || sig == "" {
		return errors.New("public key or signature header missing")
	}

	publicKey, err := PublicKeyFromString(pk)
	if err != nil {
		return err
	}

	decodedSig, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return err
	}
	err = VerifySignature(publicKey, []byte(r.Method+" "+r.RequestURI), []byte(decodedSig))
	if err != nil {
		return err
	}

	return nil
}

// Given a public key a message and a signature, verify that the message has been signed with the signature
func VerifySignature(pubkey *rsa.PublicKey, message []byte, sig []byte) error {
	hash := sha256.New()
	hash.Write(message)
	return rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, hash.Sum(nil), sig)
}

// Parses a DER encoded public key. These values are typically found in PEM blocks with "BEGIN PUBLIC KEY".
func PublicKeyFromString(pk string) (*rsa.PublicKey, error) {
	rawpk, err := base64.StdEncoding.DecodeString(pk)
	if err != nil {
		return nil, err
	}

	pubkey, err := x509.ParsePKIXPublicKey(rawpk)
	if err != nil {
		return nil, err
	}
	return pubkey.(*rsa.PublicKey), nil
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
