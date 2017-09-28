package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"strconv"

	. "github.com/cryptoballot/cryptoballot/cryptoballot"
	"github.com/cryptoballot/entropychecker"
	"github.com/dlintw/goconf"
	"github.com/lib/pq"
	"github.com/phayes/decryptpem"
)

func bootstrap() {

	// If we are on linux, ensure we have sufficient entropy.
	if runtime.GOOS == "linux" {
		err := entropychecker.WaitForEntropy()
		if err != nil {
			log.Fatal(err)
		}
	}

	// Get configuration from file or environment
	configPathOpt := flag.String("config", "./electionclerk.conf", "Path to config file. The config file must be owned by and only readable by this user.")
	configEnvOpt := flag.Bool("envconfig", false, "Use environment variables (instead of an ini file) for configuration.")
	setUpOpt := flag.Bool("set-up-db", false, "Set up fresh database tables and schema. This should be run once before normal operations can occur.")
	flag.Parse()

	if *configEnvOpt {
		config, err := NewConfigFromEnv()
		if err != nil {
			log.Fatal("Error loading environment variables. ", err)
		}
		conf = *config
	} else {
		config, err := NewConfigFromFile(*configPathOpt)
		if err != nil {
			log.Fatal("Error parsing config file. ", err)
		}
		conf = *config
	}

	// Connect to the database and set-up
	// @@TODO: Check to make sure the sslmode is set to "verify-full" (unless the user passed --insecure)
	var err error
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
	if *setUpOpt {
		_, err = db.Exec(schemaQuery)
		if err != nil {
			log.Fatal("Error loading database schema: ", err.(pq.PGError).Get('M'))
		}
		fmt.Println("Database set-up complete. Please run again without --set-up-db")
		os.Exit(0)
	}
}

// @@TODO Check to make sure the config file is readable only by this user (unless the user passed --insecure)
func NewConfigFromFile(filepath string) (*Config, error) {
	config := Config{
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
	config.port, err = c.GetInt("", "port")
	if err != nil {
		return nil, err
	}

	// Parse database config options
	config.database.host, err = c.GetString("database", "host")
	if err != nil {
		return nil, err
	}
	config.database.port, err = c.GetInt("database", "port")
	if err != nil {
		return nil, err
	}
	config.database.user, err = c.GetString("database", "user")
	if err != nil {
		return nil, err
	}
	config.database.password, err = c.GetString("database", "password")
	if err != nil {
		return nil, err
	}
	config.database.dbname, err = c.GetString("database", "dbname")
	if err != nil {
		return nil, err
	}
	config.database.sslmode, err = c.GetString("database", "sslmode")
	if err != nil {
		return nil, err
	}
	if c.HasOption("database", "max_idle_connections") {
		config.database.maxIdleConnections, err = c.GetInt("database", "max_idle_connections")
		if err != nil {
			return nil, err
		}
	} else {
		config.database.maxIdleConnections = -1
	}

	// Ingest the private key into the global config object
	config.signingKeyPath, err = c.GetString("", "signing-key")
	if err != nil {
		return nil, err
	}

	// Ingest administrators
	config.adminKeysPath, err = c.GetString("", "admins")
	if err != nil {
		return nil, err
	}

	// Ingest the readme
	config.readmePath, err = c.GetString("", "readme")
	if err != nil {
		return nil, err
	}

	// Processs files
	err = configProcessFiles(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func NewConfigFromEnv() (*Config, error) {
	var err error

	config := Config{
		configFilePath: "",
	}

	// Change our working directory to that of ELECTIONCLERK_CONFIG_DIR so everything is relative to it
	if config_dir := os.Getenv("ELECTIONCLERK_CONFIG_DIR"); config_dir != "" {
		err := os.Chdir(path.Dir(config_dir))
		if err != nil {
			return nil, err
		}
	}

	// Parse port
	if port := os.Getenv("ELECTIONCLERK_PORT"); port != "" {
		config.port, err = strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("Missing ELECTIONCLERK_PORT")
	}

	// Parse database config options
	if db_port := os.Getenv("ELECTIONCLERK_DATABASE_PORT"); db_port != "" {
		config.database.port, err = strconv.Atoi(db_port)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("Missing ELECTIONCLERK_DATABASE_PORT")
	}
	config.database.host = os.Getenv("ELECTIONCLERK_DATABASE_HOST")
	if config.database.host == "" {
		return nil, errors.New("Missing ELECTIONCLERK_DATABASE_HOST")
	}
	config.database.user = os.Getenv("ELECTIONCLERK_DATABASE_USER")
	if config.database.user == "" {
		return nil, errors.New("Missing ELECTIONCLERK_DATABASE_USER")
	}
	config.database.password = os.Getenv("ELECTIONCLERK_DATABASE_PASSWORD")
	if config.database.password == "" {
		return nil, errors.New("Missing ELECTIONCLERK_DATABASE_PASSWORD")
	}
	config.database.dbname = os.Getenv("ELECTIONCLERK_DATABASE_DBNAME")
	if config.database.dbname == "" {
		return nil, errors.New("Missing ELECTIONCLERK_DATABASE_DBNAME")
	}
	config.database.sslmode = os.Getenv("ELECTIONCLERK_DATABASE_SSLMODE")
	if config.database.sslmode == "" {
		return nil, errors.New("Missing ELECTIONCLERK_DATABASE_SSLMODE")
	}

	if max_idle := os.Getenv("ELECTIONCLERK_DATABASE_IDLE_CONNECTIONS"); max_idle != "" {
		config.database.maxIdleConnections, err = strconv.Atoi(max_idle)
		if err != nil {
			return nil, err
		}
	} else {
		config.database.maxIdleConnections = -1
	}

	// Private Signing Key
	config.signingKeyPath = os.Getenv("ELECTIONCLERK_SIGNING_KEY")
	if config.signingKeyPath == "" {
		return nil, errors.New("Missing ELECTIONCLERK_SIGNING_KEY")
	}

	// Administrators
	config.adminKeysPath = os.Getenv("ELECTIONCLERK_ADMINS")
	if config.signingKeyPath == "" {
		return nil, errors.New("Missing ELECTIONCLERK_ADMINS")
	}

	// Readme
	config.readmePath = os.Getenv("ELECTIONCLERK_README")
	if config.readmePath == "" {
		return nil, errors.New("Missing ELECTIONCLERK_README")
	}

	// Ingest the private key into the global config object
	signingKeyPEM, err := decryptpem.DecryptFileWithPrompt(config.signingKeyPath)
	if err != nil {
		return nil, err
	}
	config.signingKey, err = NewPrivateKeyFromBlock(signingKeyPEM)
	if err != nil {
		return nil, err
	}

	// Ingest administrators
	adminPEMBytes, err := ioutil.ReadFile(config.adminKeysPath)
	if err != nil {
		return nil, err
	}
	config.adminUsers, err = NewUserSet(adminPEMBytes)
	if err != nil {
		return nil, err
	}

	// Ingest the readme
	config.readme, err = ioutil.ReadFile(config.readmePath)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// Process the signing key, admin keys, and the readme
func configProcessFiles(config *Config) error {
	// Ingest the private key into the global config object
	signingKeyPEM, err := decryptpem.DecryptFileWithPrompt(config.signingKeyPath)
	if err != nil {
		return err
	}
	config.signingKey, err = NewPrivateKeyFromBlock(signingKeyPEM)
	if err != nil {
		return err
	}

	// Ingest administrators
	adminPEMBytes, err := ioutil.ReadFile(config.adminKeysPath)
	if err != nil {
		return err
	}
	config.adminUsers, err = NewUserSet(adminPEMBytes)
	if err != nil {
		return err
	}

	// Ingest the readme
	config.readme, err = ioutil.ReadFile(config.readmePath)
	if err != nil {
		return err
	}

	return nil
}

func (config *Config) databaseConnectionString() (connection string) {
	if config.database.host != "" {
		connection += "host=" + config.database.host + " "
	}
	if config.database.port != 0 {
		connection += "port=" + strconv.Itoa(config.database.port) + " "
	}
	if config.database.user != "" {
		connection += "user=" + config.database.user + " "
	}
	if config.database.password != "" {
		connection += "password=" + config.database.password + " "
	}
	if config.database.dbname != "" {
		connection += "dbname=" + config.database.dbname + " "
	}
	if config.database.sslmode != "" {
		connection += "sslmode=" + config.database.sslmode
	}
	return
}
