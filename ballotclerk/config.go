package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/dlintw/goconf"
	. "github.com/wikiocracy/cryptoballot/cryptoballot"
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
	readme            []byte         // Static content for serving to the root readme (at "/")
	signingPrivateKey rsa.PrivateKey // For now we have a single key -- eventually there should be one key per election
	voterlistURL      string
	auditorPrivateKey rsa.PrivateKey // For accessing the voter-list server, which is only open to auditors.
	admins            []User         // List of administrators allowed to create and edit elections on this service.
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

	config.database.host, err = c.GetString("ballot-clerk-db", "host")
	if err != nil {
		return
	}

	config.database.port, err = c.GetInt("ballot-clerk-db", "port")
	if err != nil {
		return
	}

	config.database.user, err = c.GetString("ballot-clerk-db", "user")
	if err != nil {
		return
	}

	config.database.password, err = c.GetString("ballot-clerk-db", "password")
	if err != nil {
		return
	}

	config.database.dbname, err = c.GetString("ballot-clerk-db", "dbname")
	if err != nil {
		return
	}

	config.database.sslmode, err = c.GetString("ballot-clerk-db", "sslmode")
	if err != nil {
		return
	}

	// For max_idle_connections missing should translates to -1
	if c.HasOption("ballot-clerk-db", "max_idle_connections") {
		config.database.maxIdleConnections, err = c.GetInt("ballot-clerk-db", "max_idle_connections")
		if err != nil {
			return
		}
	} else {
		config.database.maxIdleConnections = -1
	}

	// Ingest the private key into the global config object
	privateKeyLocation, err := c.GetString("ballot-clerk", "private-key")
	if err != nil {
		return
	}
	rawKeyPEM, err := ioutil.ReadFile(privateKeyLocation)
	if err != nil {
		return
	}
	PEMBlock, _ := pem.Decode(rawKeyPEM)
	if PEMBlock.Type != "RSA PRIVATE KEY" {
		err = errors.New("Could not find an RSA PRIVATE KEY block in " + privateKeyLocation)
		return
	}
	signingPrivateKey, err := x509.ParsePKCS1PrivateKey(PEMBlock.Bytes)
	if err != nil {
		return
	}
	config.signingPrivateKey = *signingPrivateKey

	// Ingest administrators
	config.admins = make([]User, 0)
	adminPEMLocation, err := c.GetString("ballot-clerk", "admins")
	if err != nil {
		return
	}
	rawAdminPEM, err := ioutil.ReadFile(adminPEMLocation)
	if err != nil {
		return
	}
	var adminPEMBlock *pem.Block
	for {
		adminPEMBlock, rawAdminPEM = pem.Decode(rawAdminPEM)
		if adminPEMBlock == nil {
			break
		}
		if adminPEMBlock.Type != "PUBLIC KEY" {
			err = errors.New("Found unexpected " + adminPEMBlock.Type + " in " + adminPEMLocation)
			return
		}
		user, err := NewUserFromBlock(adminPEMBlock)
		if err != nil {
			return err
		}
		config.admins = append(config.admins, *user)
	}

	// Ingest the readme
	readmeLocation, err := c.GetString("ballot-clerk", "readme")
	if err != nil {
		return
	}
	config.readme, err = ioutil.ReadFile(readmeLocation)
	if err != nil {
		return
	}

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
