package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	. "github.com/cryptoballot/cryptoballot/cryptoballot"
	"github.com/dlintw/goconf"
	"github.com/lib/pq"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strconv"
)

func bootstrap() {
	configPathOpt := flag.String("config", "./electionclerk.conf", "Path to config file. The config file must be owned by and only readable by this user.")
	setUpOpt := flag.Bool("set-up-db", false, "Set up fresh database tables and schema. This should be run once before normal operations can occur.")
	flag.Parse()

	// Populate the global configuration object with settings from the config file.
	// @@TODO Check to make sure the config file is readable only by this user (unless the user passed --insecure)
	config, err := NewConfig(*configPathOpt)
	if err != nil {
		log.Fatal("Error parsing config file. ", err)
	}
	conf = *config

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
	if *setUpOpt {
		_, err = db.Exec(schemaQuery)
		if err != nil {
			log.Fatal("Error loading database schema: ", err.(pq.PGError).Get('M'))
		}
		fmt.Println("Database set-up complete. Please run again without --set-up-db")
		os.Exit(0)
	}
}

func NewConfig(filepath string) (*Config, error) {
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
	signingKeyPEM, err := ioutil.ReadFile(config.signingKeyPath)
	if err != nil {
		return nil, err
	}
	config.signingKey, err = NewPrivateKey(signingKeyPEM)
	if err != nil {
		return nil, err
	}

	// Ingest administrators
	config.adminKeysPath, err = c.GetString("", "admins")
	if err != nil {
		return nil, err
	}
	adminPEMBytes, err := ioutil.ReadFile(config.adminKeysPath)
	if err != nil {
		return nil, err
	}
	config.adminUsers, err = NewUserSet(adminPEMBytes)
	if err != nil {
		return nil, err
	}

	// Ingest the readme
	config.readmePath, err = c.GetString("", "readme")
	if err != nil {
		return nil, err
	}
	config.readme, err = ioutil.ReadFile(config.readmePath)
	if err != nil {
		return nil, err
	}

	return &config, nil
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
