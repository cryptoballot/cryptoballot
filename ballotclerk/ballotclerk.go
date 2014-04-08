package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/knieriem/markdown"
	"github.com/lib/pq"
	. "github.com/wikiocracy/cryptoballot/cryptoballot"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var (
	db   *sql.DB // Global postgres database collection where we store completed FufilledSignatureRequests
	conf Config  // Global config object
)

func main() {
	// Bootstrap parses flags and config files, and set's up the database connection.
	bootstrap()

	// Bootstrap is complete, let's serve some REST
	//@@TODO BEAST AND CRIME protection
	//@@TODO SSL only

	// Displays the readme.md
	http.HandleFunc("/", rootHandler)

	// Provides the ability to POST new Signature Requests
	http.HandleFunc("/sign", signHandler)

	// Reports this servers public key
	http.HandleFunc("/publickey", publicKeyHandler)

	log.Println("Listning on port 8000")

	err := http.ListenAndServe(":8000", nil)

	if err != nil {
		log.Fatal("Error starting http server: ", err)
	}
}

func bootstrap() {
	config_path_opt := flag.String("config", "./example-conf/example.conf", "Path to config file. The config file must be owned by and only readable by this user.")
	set_up_opt := flag.Bool("set-up-db", false, "Set up fresh database tables and schema. This should be run once before normal operations can occur.")
	flag.Parse()

	// Populate the global configuration object with settings from the config file.
	// @@TODO Check to make sure the config file is readable only by this user (unless the user passed --insecure)
	err := conf.loadFromFile(*config_path_opt)
	if err != nil {
		log.Fatal("Error parsing config file. ", err)
	}

	// Connect to the database and set-up
	// @@TODO: Check to make sure the sslmode is set to "verify-full" (unless the user passed --insecure)
	db, err = sql.Open("postgres", conf.databaseConnectionString())
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	// Set the maximum number of idle connections in the connection pool. `-1` means default of 2 idle connections in the pool
	if conf.database.maxIdleConnections != -1 {
		db.SetMaxIdleConns(conf.database.maxIdleConnections)
	}

	// If we are in 'set-up' mode, set-up the database and exit
	// @@TODO: schema.sql should be found in some path that is configurable by the user
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

// When a user accesses "/" display the readme
// @@TODO Cache
func rootHandler(w http.ResponseWriter, r *http.Request) {
	p := markdown.NewParser(&markdown.Extensions{Smart: true})
	out := bufio.NewWriter(w)
	p.Markdown(bytes.NewReader(conf.readme), markdown.ToHTML(out))
	out.Flush()
	return
}

// Handle a signature-request coming from a user
func signHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed. Only POST is allowed here.", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	signatureReqest, err := NewSignatureRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err = signatureReqest.VerifySignature(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// @@TODO: Check the validity of the voter with the voter-list server.
	// @@TODO: Check that this voter has not already retreived a fulfilled signature request.

	// Sign the ballot
	ballotSig, err := signatureReqest.SignBallot(&conf.signingPrivateKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fulfilledsignatureRequest := NewFulfilledSignatureRequest(*signatureReqest, ballotSig)

	//@@TODO: store the fulfilledsignatureRequest in the database

	fmt.Fprint(w, fulfilledsignatureRequest)
	return
}

// Display the public key used to sign ballots when a user asks for "/publickey"
// @@TODO: Cache
func publicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed. Only GET is allowed here.", http.StatusMethodNotAllowed)
		return
	}

	derEncodedPublicKey, err := x509.MarshalPKIXPublicKey(&conf.signingPrivateKey.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pemBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derEncodedPublicKey,
	}
	pem.Encode(w, &pemBlock)
	return
}
