package webtest

import (
	"testing"
	"time"
)

// TestWebElection compiles and runs electionclerk and ballotbox, then tests a small election using botyh
func TestWebElection(m *testing.T) {

	// Do cleanup on panic
	defer func() {
		if r := recover(); r != nil {
			Fail("Panic: ", r)
		}
	}()

	runCommandSync("go", "build", "-race", "../../electionclerk")
	runCommandSync("go", "build", "-race", "../../ballotbox")
	runCommandSync("createdb", "--host=localhost", "--username=postgres", "--port=9856", "cryptoballot_webtest_electionclerk")
	runCommandSync("createdb", "--host=localhost", "--username=postgres", "--port=9856", "cryptoballot_webtest_ballotbox")
	runCommandSync("./electionclerk", "--config=electionclerk.conf", "--set-up-db")

	// Boot up the election-clerk
	electionclerkCmd = runCommand("./electionclerk", "--config=electionclerk.conf")
	time.Sleep(2 * time.Second) // Give the electionclerk time to boot-up

	// Boot up the ballot-box
	ballotboxCmd = runCommand("./ballotbox", "--config=ballotbox.conf")
	time.Sleep(2 * time.Second) // Give the ballotbox time to boot-up

	// Test election creation etc.
	testElection()

	// We're done
	Success()
}
