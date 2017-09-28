package webtest

import (
	"testing"
)

// TestWebElection compiles and runs electionclerk and ballotbox, then tests a small election using botyh
func TestWebElection(m *testing.T) {

	// Do cleanup on panic
	defer func() {
		if r := recover(); r != nil {
			Fail("Panic: ", r)
		}
	}()

	runCommandSync("go", "build", "-race", "../../servers/electionclerk")
	runCommandSync("go", "build", "-race", "../../servers/ballotbox")
	runCommandSync("createdb", "--host=localhost", "--username=postgres", "--port=9856", "cryptoballot_webtest_electionclerk")
	runCommandSync("createdb", "--host=localhost", "--username=postgres", "--port=9856", "cryptoballot_webtest_ballotbox")
	runCommandSync("./electionclerk", "--config=electionclerk.conf", "--set-up-db")

	// Test end-to-end
	testEndToEnd()

	// We're done
	Success()
}
