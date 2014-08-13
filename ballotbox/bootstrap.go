package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"flag"
	. "github.com/cryptoballot/cryptoballot/cryptoballot"
	"github.com/dlintw/goconf"
	_ "github.com/lib/pq"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
)

// Bootstrap parses flags and config files, and set's up the database connection.
func bootstrap() {
	configPathOpt := flag.String("config", "./test.conf", "Path to config file. The config file must be owned by and only readable by this user.")
	flag.Parse()

	//@@TODO Check to make sure the config file is readable only by this user (unless the user passed --insecure)
	cnf, err := NewConfig(*configPathOpt)
	if err != nil {
		log.Fatal("Error loading data from config file. ", err)
	}
	conf = *cnf

	//@@TODO: Check to make sure the sslmode is set to "verify-full" (unless the user passed --insecure)
	//        See pq package documentation

	// Connect to the database and set-up
	db, err = sql.Open("postgres", conf.databaseConnectionString())
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	// Set the maximum number of idle connections in the connection pool. `-1` means default (2 idle connections in the pool)
	if conf.database.maxIdleConnections != -1 {
		db.SetMaxIdleConns(conf.database.maxIdleConnections)
	}

	// Sync elections to database tables
	err = syncElectionToDB(conf.elections)
	if err != nil {
		log.Fatal("Error syncing elections to database: ", err)
	}
}

//@@TEST: loading known good config from file
func NewConfig(filepath string) (*config, error) {
	conf := config{
		configFilePath: filepath,
	}

	c, err := goconf.ReadConfigFile(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("Could not find config file. Try using the --config=\"<path-to-config-file>\" option to specify a config file.")
		} else {
			return nil, err
		}
	}

	// Change our working directory to that of the config file so that paths referenced in the config file are relative to that location
	err = os.Chdir(path.Dir(filepath))
	if err != nil {
		return nil, err
	}

	// Parse port
	conf.port, err = c.GetInt("", "port")
	if err != nil {
		return nil, err
	}

	// Parse database
	conf.database.host, err = c.GetString("database", "host")
	if err != nil {
		return nil, err
	}
	conf.database.port, err = c.GetInt("database", "port")
	if err != nil {
		return nil, err
	}
	conf.database.user, err = c.GetString("database", "user")
	if err != nil {
		return nil, err
	}
	conf.database.password, err = c.GetString("database", "password")
	if err != nil {
		return nil, err
	}
	conf.database.dbname, err = c.GetString("database", "dbname")
	if err != nil {
		return nil, err
	}
	conf.database.sslmode, err = c.GetString("database", "sslmode")
	if err != nil {
		return nil, err
	}
	// For max_idle_connections missing should translates to -1
	if c.HasOption("database", "max_idle_connections") {
		conf.database.maxIdleConnections, err = c.GetInt("database", "max_idle_connections")
		if err != nil {
			return nil, err
		}
	} else {
		conf.database.maxIdleConnections = -1
	}

	// Parse election-clerk URL
	conf.electionclerkURL, err = c.GetString("", "electionclerk-url")
	if err != nil {
		return nil, err
	}
	_, err = url.Parse(conf.electionclerkURL)
	if err != nil {
		return nil, err
	}

	// Get the ballot-clerk public key
	body, err := httpGetAll(conf.electionclerkURL + "/publickey")
	if err != nil {
		return nil, err
	}
	PEMBlock, _ := pem.Decode(body)
	if PEMBlock.Type != "PUBLIC KEY" {
		return nil, errors.New("Could not parse Election Clerk Public Key")
	}
	cryptoKey, err := x509.ParsePKIXPublicKey(PEMBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	conf.clerkKey, err = NewPublicKeyFromCryptoKey(cryptoKey.(*rsa.PublicKey))
	if err != nil {
		return nil, err
	}

	// Get the admin users
	body, err = httpGetAll(conf.electionclerkURL + "/admins")
	if err != nil {
		return nil, err
	}
	conf.adminUsers, err = NewUserSet(body)
	if err != nil {
		return nil, err
	}

	// Get the list of elections
	body, err = httpGetAll(conf.electionclerkURL + "/election")
	if err != nil {
		return nil, err
	}
	if len(body) != 0 {
		rawElections := bytes.Split(body, []byte("\n\n\n"))
		for _, rawElection := range rawElections {
			election, err := NewElection(rawElection)
			if err != nil {
				return nil, err
			}
			conf.elections[election.ElectionID] = *election
		}
	}

	// Ingest the readme
	conf.readmePath, err = c.GetString("", "readme")
	if err != nil {
		return nil, err
	}
	conf.readme, err = ioutil.ReadFile(conf.readmePath)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}

// Given a URL, do the request and get the body as a byte slice
func httpGetAll(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (conf *config) databaseConnectionString() (connection string) {
	if conf.database.host != "" {
		connection += "host=" + conf.database.host + " "
	}
	if conf.database.port != 0 {
		connection += "port=" + strconv.Itoa(conf.database.port) + " "
	}
	if conf.database.user != "" {
		connection += "user=" + conf.database.user + " "
	}
	if conf.database.password != "" {
		connection += "password=" + conf.database.password + " "
	}
	if conf.database.dbname != "" {
		connection += "dbname=" + conf.database.dbname + " "
	}
	if conf.database.sslmode != "" {
		connection += "sslmode=" + conf.database.sslmode
	}
	return
}
