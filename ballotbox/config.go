package main

// NOTES
// See https://bitbucket.org/bumble/bumble-golang-common/src/master/key/publickey.go

import (
	"fmt" // @@TODO: Remove this dependacy, just use + operator
	"github.com/dlintw/goconf"
	"net/url"
)

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
	port           int    // Listen port -- generally it should be 443
	readme         []byte // Static content for serving to the root readme (at "/")
	ballotclerkURL string
	adminKeysPath  string
}

//@@TEST: loading known good config from file
func (config *Config) loadFromFile(filepath string) (err error) {
	config.configFile = filepath

	c, err := goconf.ReadConfigFile(filepath)
	if err != nil {
		return
	}

	config.voteDB.host, err = c.GetString("ballot-box-db", "host")
	if err != nil {
		return
	}

	config.voteDB.port, err = c.GetInt("ballot-box-db", "port")
	if err != nil {
		return
	}

	config.voteDB.user, err = c.GetString("ballot-box-db", "user")
	if err != nil {
		return
	}

	config.voteDB.password, err = c.GetString("ballot-box-db", "password")
	if err != nil {
		return
	}

	config.voteDB.dbname, err = c.GetString("ballot-box-db", "dbname")
	if err != nil {
		return
	}

	config.voteDB.sslmode, err = c.GetString("ballot-box-db", "sslmode")
	if err != nil {
		return
	}

	// For max_idle_connections missing should translates to -1
	if c.HasOption("ballot-box-db", "max_idle_connections") {
		config.voteDB.maxIdleConnections, err = c.GetInt("ballot-box-db", "max_idle_connections")
		if err != nil {
			return
		}
	} else {
		config.voteDB.maxIdleConnections = -1
	}

	config.ballotclerkURL, err = c.GetString("ballot-box", "ballot-clerk")
	if err != nil {
		return
	}
	_, err = url.Parse(config.ballotclerkURL)
	if err != nil {
		return
	}

	config.adminKeysPath, err = c.GetString("ballot-box", "admin-keys")
	if err != nil {
		return
	}

	config.port, err = c.GetInt("ballot-box", "port")
	if err != nil {
		return
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
