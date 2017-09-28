package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strconv"

	. "github.com/cryptoballot/cryptoballot/cryptoballot"
	"github.com/cryptoballot/entropychecker"
	"github.com/dlintw/goconf"
	_ "github.com/lib/pq"
)

// Bootstrap parses flags and config files, and set's up the database connection.
func bootstrap() {

	// If we are on linux, ensure we have sufficient entropy.
	if runtime.GOOS == "linux" {
		err := entropychecker.WaitForEntropy()
		if err != nil {
			log.Fatal(err)
		}
	}

	// Load config file
	configPathOpt := flag.String("config", "./test.conf", "Path to config file. The config file must be owned by and only readable by this user.")
	configEnvOpt := flag.Bool("envconfig", false, "Use environment variables (instead of an ini file) for configuration.")

	flag.Parse()

	//@@TODO Check to make sure the config file is readable only by this user (unless the user passed --insecure)
	if *configEnvOpt {
		c, err := NewConfigFromEnv()
		if err != nil {
			log.Fatal("Error loading environment variables. ", err)
		}
		conf = *c
	} else {
		c, err := NewConfigFromFile(*configPathOpt)
		if err != nil {
			log.Fatal("Error parsing config file. ", err)
		}
		conf = *c
	}

	//@@TODO: Check to make sure the sslmode is set to "verify-full" (unless the user passed --insecure)
	//        See pq package documentation

	// Connect to the database and set-up
	var err error
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
func NewConfigFromFile(filepath string) (*config, error) {
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

	// Ingest the readme
	conf.readmePath, err = c.GetString("", "readme")
	if err != nil {
		return nil, err
	}

	// Process local files
	err = configProcessFiles(&conf)
	if err != nil {
		return nil, err
	}

	// Update From BallotClerk
	err = UpdateConfigFromBallotClerk(&conf)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}

// Process the readme
func configProcessFiles(conf *config) error {
	// Ingest the readme
	var err error
	conf.readme, err = ioutil.ReadFile(conf.readmePath)
	if err != nil {
		return err
	}

	return nil
}

func UpdateConfigFromBallotClerk(conf *config) error {
	// Get the ballot-clerk public key
	body, err := httpGetAll(conf.electionclerkURL + "/publickey")
	if err != nil {
		return err
	}
	PEMBlock, _ := pem.Decode(body)
	if PEMBlock.Type != "PUBLIC KEY" {
		return errors.New("Could not parse Election Clerk Public Key")
	}
	cryptoKey, err := x509.ParsePKIXPublicKey(PEMBlock.Bytes)
	if err != nil {
		return err
	}
	conf.clerkKey, err = NewPublicKeyFromCryptoKey(cryptoKey.(*rsa.PublicKey))
	if err != nil {
		return err
	}

	// Get the admin users
	body, err = httpGetAll(conf.electionclerkURL + "/admins")
	if err != nil {
		return err
	}
	conf.adminUsers, err = NewUserSet(body)
	if err != nil {
		return err
	}

	// Get the list of elections
	body, err = httpGetAll(conf.electionclerkURL + "/election")
	if err != nil {
		return err
	}
	if len(body) != 0 {
		rawElections := bytes.Split(body, []byte("\n\n\n"))
		conf.elections = make(map[string]Election, len(rawElections))

		for _, rawElection := range rawElections {
			election, err := NewElection(rawElection)
			if err != nil {
				return err
			}
			conf.elections[election.ElectionID] = *election
		}
	}

	return nil
}

func NewConfigFromEnv() (*config, error) {
	var err error

	conf := config{
		configFilePath: "",
	}

	// Change our working directory to that of BALLOTBOX_CONFIG_DIR so everything is relative to it
	if config_dir := os.Getenv("BALLOTBOX_CONFIG_DIR"); config_dir != "" {
		err = os.Chdir(path.Dir(config_dir))
		if err != nil {
			return nil, err
		}
	}

	// Parse port
	if port := os.Getenv("BALLOTBOX_PORT"); port != "" {
		conf.port, err = strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("Missing BALLOTBOX_PORT")
	}
	if db_port := os.Getenv("BALLOTBOX_DATABASE_PORT"); db_port != "" {
		conf.database.port, err = strconv.Atoi(db_port)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("Missing BALLOTBOX_DATABASE_PORT")
	}
	conf.database.host = os.Getenv("BALLOTBOX_DATABASE_HOST")
	if conf.database.host == "" {
		return nil, errors.New("Missing BALLOTBOX_DATABASE_HOST")
	}
	conf.database.user = os.Getenv("BALLOTBOX_DATABASE_USER")
	if conf.database.user == "" {
		return nil, errors.New("Missing BALLOTBOX_DATABASE_USER")
	}
	conf.database.password = os.Getenv("BALLOTBOX_DATABASE_PASSWORD")
	if conf.database.password == "" {
		return nil, errors.New("Missing BALLOTBOX_DATABASE_PASSWORD")
	}
	conf.database.dbname = os.Getenv("BALLOTBOX_DATABASE_DBNAME")
	if conf.database.dbname == "" {
		return nil, errors.New("Missing BALLOTBOX_DATABASE_DBNAME")
	}
	conf.database.sslmode = os.Getenv("BALLOTBOX_DATABASE_SSLMODE")
	if conf.database.sslmode == "" {
		return nil, errors.New("Missing BALLOTBOX_DATABASE_SSLMODE")
	}

	if max_idle := os.Getenv("BALLOTBOX_DATABASE_IDLE_CONNECTIONS"); max_idle != "" {
		conf.database.maxIdleConnections, err = strconv.Atoi(max_idle)
		if err != nil {
			return nil, err
		}
	} else {
		conf.database.maxIdleConnections = -1
	}

	// Parse election-clerk URL
	conf.electionclerkURL = os.Getenv("BALLOTBOX_ELECTIONCLERK_URL")
	if conf.electionclerkURL == "" {
		return nil, errors.New("Missing BALLOTBOX_ELECTIONCLERK_URL")
	}
	_, err = url.Parse(conf.electionclerkURL)
	if err != nil {
		return nil, err
	}

	// Readme
	conf.readmePath = os.Getenv("BALLOTBOX_README")
	if conf.readmePath == "" {
		return nil, errors.New("Missing BALLOTBOX_README")
	}

	// Process local files
	err = configProcessFiles(&conf)
	if err != nil {
		return nil, err
	}

	// Update From BallotClerk
	err = UpdateConfigFromBallotClerk(&conf)
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
	if resp.StatusCode != 200 {
		return nil, errors.New("Received " + resp.Status + " from " + url)
	}
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
