package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"
)

var (
	electionclerkCmd *exec.Cmd
	ballotboxCmd     *exec.Cmd
	once             sync.Once
)

func main() {

	// Do cleanup on panic
	defer func() {
		if r := recover(); r != nil {
			Fail("Panic: ", r)
		}
	}()

	runCommandSync("go", "build", "../../electionclerk")
	runCommandSync("go", "build", "../../ballotbox")
	runCommandSync("createdb", "cryptoballot_webtest_electionclerk")
	runCommandSync("createdb", "cryptoballot_webtest_ballotbox")
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

// Fail cleans up then calls log.Fatal
func Fail(v ...interface{}) {
	once.Do(func() {
		Cleanup()
		log.Fatal(v...)
	})
}

func Success() {
	time.Sleep(2 * time.Second) // Give running processes a little time to fail before we declare victory
	fmt.Println("Success!")
	once.Do(func() {
		Cleanup()
		os.Exit(0)
	})
}

func Cleanup() {
	// Kill long-running processes
	if electionclerkCmd != nil {
		electionclerkCmd.Process.Kill()
	}
	if ballotboxCmd != nil {
		ballotboxCmd.Process.Kill()
	}

	// Run the cleanup script
	cmd := exec.Command("sh", "cleanup.sh")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Print(err)
	}
}

// Run a command, piping the results to stderr and stdout.
// Fatally fail if the command fails in any way
// This function will return before the command finishes running
func runCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		Fail(err)
	}
	go func() {
		err = cmd.Wait()
		if err != nil {
			Fail(err)
		}
	}()
	return cmd
}

func runCommandSync(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		Fail(err)
	}
}
