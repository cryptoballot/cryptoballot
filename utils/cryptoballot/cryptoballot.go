package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cryptoballot/cryptoballot/clients/ballotbox"
	"github.com/cryptoballot/cryptoballot/clients/ballotclerk"
	"github.com/urfave/cli"
)

// Version specifies the version of this binary
var Version = "0.1"

// BallotClerkClient is used to connect to ballotclerk server
var BallotClerkClient *ballotclerk.Client

// BallotBoxClient is used to connect to ballotbox server
var BallotBoxClient *ballotbox.Client

func main() {
	app := cli.NewApp()
	app.Name = "cryptoballot"

	// Global options
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "ballotclerk",
			Value: "http://localhost:8000",
		},
		cli.StringFlag{
			Name:  "ballotbox",
			Value: "http://localhost:8002",
		},
	}

	// Commands
	app.Commands = []cli.Command{
		{
			Name:  "admin",
			Usage: "perform election administrative operations",
			Subcommands: []cli.Command{
				{
					Name:  "create",
					Usage: "create a new election",
					Action: func(c *cli.Context) error {
						fmt.Println("create: ", c.Args().First())
						return nil
					},
					ArgsUsage: "[electionfile]",
				},
				{
					Name:      "tally",
					Usage:     "Verify and tally election results",
					ArgsUsage: "[election-name]",
					Action: func(c *cli.Context) error {
						fmt.Println("tally: ", c.Args().First())
						return nil
					},
				},
			},
		},
		{
			Name:  "voter",
			Usage: "vote in an election",
			Subcommands: []cli.Command{
				{
					Name:  "vote",
					Usage: "vote in an election",
					Action: func(c *cli.Context) error {
						fmt.Println("create: ", c.Args().First())
						return nil
					},
					ArgsUsage: "[votefile]",
				},
				{
					Name:      "verify",
					Usage:     "Verify that the voters vote has been counted",
					ArgsUsage: "[votefile]",
					Action: func(c *cli.Context) error {
						fmt.Println("verify: ", c.Args().First())
						return nil
					},
				},
			},
		},
		{
			Name:  "version",
			Usage: "print version",
			Action: func(c *cli.Context) error {
				fmt.Println(Version)
				return nil
			},
		},
	}

	// Set up connections to services
	app.Before = func(c *cli.Context) error {

		// ballotclerk
		BallotClerkClient = ballotclerk.NewClient(c.String("ballotclerk"))

		// Connect to A4D Extract
		BallotBoxClient = ballotbox.NewClient(c.String("ballotbox"))

		return nil
	}

	app.Version = Version
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
