package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/dlintw/goconf"
	"io/ioutil"
	"strconv"
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

	// Ingest the private key into the global config object
	privateKeyLocation, err := c.GetString("clerk-crypto", "clerk-private-key")
	if err != nil {
		return
	}
	rawPEM, err := ioutil.ReadFile(privateKeyLocation)
	if err != nil {
		return
	}
	PEMBlock, _ := pem.Decode(rawPEM)
	if PEMBlock.Type != "RSA PRIVATE KEY" {
		err = errors.New("Could not find an RSA PRIVATE KEY block in " + privateKeyLocation)
		return
	}
	signingPrivateKey, err := x509.ParsePKCS1PrivateKey(PEMBlock.Bytes)
	if err != nil {
		return
	}
	config.signingPrivateKey = *signingPrivateKey

	return
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
