package ballotbox

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/cryptoballot/cryptoballot/cryptoballot"
	"github.com/phayes/errors"
)

var (
	ErrPutBallot = errors.New("ballotbox: Unable to PUT ballot")
	ErrGetBallot = errors.New("ballotbox: Unable to GET ballot")
)

// Client provides access to the ballotclerk REST service
type Client struct {
	BaseURL    string
	HTTPClient http.Client
}

// NewClient creates a new atomx.Client for working with the extract Service
func NewClient(baseurl string) *Client {
	return &Client{BaseURL: baseurl, HTTPClient: http.Client{}}
}

// PutBallot PUTs a single ballot into the ballotbox
func (c *Client) PutBallot(ballot *cryptoballot.Ballot) error {
	req, err := http.NewRequest("PUT", c.BaseURL+"/vote/"+ballot.ElectionID+"/"+ballot.BallotID, strings.NewReader(ballot.String()))
	if err != nil {
		return errors.Wrap(err, ErrPutBallot)
	}

	// Do the request
	resp, err := c.HTTPClient.Do(req)
	defer ResponseDrainAndClose(resp)
	if err != nil {
		return errors.Wrap(err, ErrPutBallot)
	}

	// Handle errors
	if resp.StatusCode != 200 {
		details, _ := ioutil.ReadAll(resp.Body)
		return errors.Appendf(ErrPutBallot, "ballotbox: %s - %s", resp.Status, details)
	}

	// Success
	return nil
}

// GetBallot gets a single ballot from the ballotbox
func (c *Client) GetBallot(electionID string, ballotID string) (*cryptoballot.Ballot, error) {
	url := c.BaseURL + "/vote/" + electionID + "/" + ballotID
	resp, err := c.HTTPClient.Get(url)
	defer ResponseDrainAndClose(resp)
	if err != nil {
		return nil, errors.Wrap(err, ErrGetBallot)
	}

	if resp.StatusCode != 200 {
		details, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Appendf(ErrGetBallot, "ballotbox: %s - %s", resp.Status, details)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, ErrGetBallot)
	}

	election, err := cryptoballot.NewBallot(body)
	if err != nil {
		return nil, errors.Wrap(err, ErrGetBallot)
	}

	return election, nil
}

// GetAllBallots gets all ballots for an election
func (c *Client) GetAllBallots(electionID string) ([]*cryptoballot.Ballot, error) {
	url := c.BaseURL + "/vote/" + electionID
	resp, err := c.HTTPClient.Get(url)
	defer ResponseDrainAndClose(resp)
	if err != nil {
		return nil, errors.Wrap(err, ErrGetBallot)
	}

	if resp.StatusCode != 200 {
		details, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Appendf(ErrGetBallot, "ballotbox: %s - %s", resp.Status, details)
	}

	// There could be a large number of ballots, parse them as they come in.
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(scanBallots)

	ballots := []*cryptoballot.Ballot{}
	for scanner.Scan() {
		bytes := scanner.Bytes()
		ballot, err := cryptoballot.NewBallot(bytes)
		if err != nil {
			return nil, err
		}
		ballots = append(ballots, ballot)
	}

	return ballots, nil
}

// ResponseDrainAndClose drains a response of it's body and closes it
// It should be used in a defer statement when doing an HTTP request
func ResponseDrainAndClose(resp *http.Response) {
	if resp != nil {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// scanBallots takes a stream of data and splits the ballots by '\n\n\n', so that ballots can be parsed while streaming
// For use in a bufio.Scanner
func scanBallots(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, []byte("\n\n\n")); i >= 0 {
		// We have a full triple-newline terminated line.
		return i + 3, dropCR(data[0:i]), nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), dropCR(data), nil
	}
	// Request more data.
	return 0, nil, nil
}

// dropCR drops a terminal \r from the data.
func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[0 : len(data)-1]
	}
	return data
}
