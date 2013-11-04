package main

import (
	"github.com/dlintw/goconf"
	"rsa"
)

type Config struct {
	configFile string
	database   struct {
		host               string
		port               int
		user               string
		password           string
		dbname             string
		sslmode            string
		maxIdleConnections int
	}
	signingPrivateKey rsa.PrivateKey // For now we have a single key -- eventually there should be one key per election
	signingPublicKey  rsa.PublicKey
	voterlistURL      string
	auditorPrivateKey rsa.PrivateKey // For accessing the voter-list server, which is only open to auditors
	auditorPublicKey  rsa.PublicKey  // For accessing the voter-list server, which is only open to auditors
}

//@@TEST: loading known good config from file
//@@TODO: transform this into a NewConfig func
//@@TODO: load keys from files
func (config *Config) loadFromFile(filepath string) (err error) {
	config.configFile = filepath

	c, err := goconf.ReadConfigFile(filepath)
	if err != nil {
		return
	}

	config.database.host, err = c.GetString("clerk-db", "host")
	if err != nil {
		return
	}

	config.database.port, err = c.GetInt("clerk-db", "port")
	if err != nil {
		return
	}

	config.database.user, err = c.GetString("clerk-db", "user")
	if err != nil {
		return
	}

	config.database.password, err = c.GetString("clerk-db", "password")
	if err != nil {
		return
	}

	config.database.dbname, err = c.GetString("clerk-db", "dbname")
	if err != nil {
		return
	}

	config.database.sslmode, err = c.GetString("clerk-db", "sslmode")
	if err != nil {
		return
	}

	// For max_idle_connections missing should translates to -1
	if c.HasOption("clerk-db", "max_idle_connections") {
		config.database.maxIdleConnections, err = c.GetInt("clerk-db", "max_idle_connections")
		if err != nil {
			return
		}
	} else {
		config.database.maxIdleConnections = -1
	}

	return
}

func (config *Config) databaseConnectionString() (connection string) {
	if config.database.host != "" {
		connection += "host=" + config.voteDB.host + " "
	}
	if config.voteDB.port != 0 {
		connection += "port=" + " "
	}
	if config.voteDB.user != "" {
		connection += "user=" + config.voteDB.user + " "
	}
	if config.voteDB.password != "" {
		connection += "password=" + config.voteDB.password + " "
	}
	if config.voteDB.dbname != "" {
		connection += "dbname=" + config.voteDB.dbname + " "
	}
	if config.voteDB.sslmode != "" {
		connection += "sslmode=" + config.voteDB.sslmode
	}
	return
}
