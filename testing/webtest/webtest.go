package webtest

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

// Fail cleans up then calls log.Fatal
func Fail(v ...interface{}) {
	once.Do(func() {
		Cleanup()
		log.Fatal(v...)
	})
}

// Success is called when we've successfully completed the test
func Success() {
	time.Sleep(2 * time.Second) // Give running processes a little time to fail before we declare victory
	fmt.Println("Success!")
	once.Do(func() {
		Cleanup()
	})
}

// Cleanup kills electionclerk and ballotbox processes, deletes databases, and removes compiled binaries.
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

// runCommandSync runs a command syncronously, waiting until it is done.
func runCommandSync(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		Fail(err)
	}
}
