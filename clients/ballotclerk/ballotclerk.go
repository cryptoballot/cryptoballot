package ballotclerk

import (
	"encoding/pem"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/phayes/errors"

	"github.com/cryptoballot/cryptoballot/cryptoballot"
)

var (
	ErrGetPublicKey         = errors.New("ballotclerk: Unable to GET public signing key")
	ErrMisingPEMBLock       = errors.New("ballotclerk: Missing PEM Block")
	ErrPutElection          = errors.New("ballotclerk: Unable to PUT election")
	ErrGetElection          = errors.New("ballotclerk: Unable to GET election")
	ErrPostSignatureRequest = errors.New("ballotclerk: Unable to POST signature request")
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

// GetPublicKey gets public signing key for the ballot clerk
func (c *Client) GetPublicKey() (cryptoballot.PublicKey, error) {
	url := c.BaseURL + "/publickey"
	resp, err := c.HTTPClient.Get(url)
	defer ResponseDrainAndClose(resp)
	if err != nil {
		return nil, errors.Wrap(err, ErrGetPublicKey)
	}

	if resp.StatusCode != 200 {
		details, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Appendf(ErrGetPublicKey, "ballotclerk: %v - %v", resp.Status, details)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, ErrGetPublicKey)
	}

	pemBlock, _ := pem.Decode(body)
	if pemBlock == nil {
		return nil, errors.Wrap(ErrMisingPEMBLock, ErrGetPublicKey)
	}

	pubKey, err := cryptoballot.NewPublicKeyFromBlock(pemBlock)
	if err != nil {
		return nil, errors.Wrap(err, ErrGetPublicKey)
	}

	return pubKey, nil
}

// PutElection creates a new election
func (c *Client) PutElection(election *cryptoballot.Election, privKey cryptoballot.PrivateKey) error {
	// Prepare to PUT the election to the Election Clerk server
	req, err := http.NewRequest("PUT", c.BaseURL+"/election/"+election.ElectionID, strings.NewReader(election.String()))
	if err != nil {
		return errors.Wrap(err, ErrPutElection)
	}
	reqSig, err := privKey.SignString("PUT /election/" + election.ElectionID)
	if err != nil {
		return errors.Wrap(err, ErrPutElection)
	}
	pubKey, err := privKey.PublicKey()
	if err != nil {
		return errors.Wrap(err, ErrPutElection)
	}

	// Add authentication headers
	req.Header.Add("X-Public-Key", pubKey.String())
	req.Header.Add("X-Signature", reqSig.String())

	// Do the request
	resp, err := c.HTTPClient.Do(req)
	defer ResponseDrainAndClose(resp)
	if err != nil {
		return errors.Wrap(err, ErrPutElection)
	}

	// Handle errors
	if resp.StatusCode != 200 {
		details, _ := ioutil.ReadAll(resp.Body)
		return errors.Newf("ballotclerk: %v - %v", resp.Status, details)
	}

	// Success
	return nil
}

// GetElection gets an election from the ballotclerk
func (c *Client) GetElection(electionID string) (*cryptoballot.Election, error) {
	url := c.BaseURL + "/election/" + electionID
	resp, err := c.HTTPClient.Get(url)
	defer ResponseDrainAndClose(resp)
	if err != nil {
		return nil, errors.Wrap(err, ErrGetElection)
	}

	if resp.StatusCode != 200 {
		details, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Appendf(ErrGetElection, "ballotclerk: %v - %v", resp.Status, details)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, ErrGetElection)
	}

	election, err := cryptoballot.NewElection(body)
	if err != nil {
		return nil, errors.Wrap(err, ErrGetElection)
	}

	return election, nil
}

// PostSignatureRequest POSTs a signature request and returns a FulfulledSignatureRequest
func (c *Client) PostSignatureRequest(signatureRequest *cryptoballot.SignatureRequest, privKey cryptoballot.PrivateKey) (*cryptoballot.FulfilledSignatureRequest, error) {
	// Prepare to POST the signature request to the Election Clerk server
	req, err := http.NewRequest("POST", c.BaseURL+"/sign", strings.NewReader(signatureRequest.String()))
	if err != nil {
		return nil, errors.Wrap(err, ErrPostSignatureRequest)
	}
	reqSig, err := privKey.SignString("POST /sign")
	if err != nil {
		return nil, errors.Wrap(err, ErrPostSignatureRequest)
	}
	pubKey, err := privKey.PublicKey()
	if err != nil {
		return nil, errors.Wrap(err, ErrPostSignatureRequest)
	}

	// Add authentication headers
	req.Header.Add("X-Public-Key", pubKey.String())
	req.Header.Add("X-Signature", reqSig.String())

	// Do the request
	resp, err := c.HTTPClient.Do(req)
	defer ResponseDrainAndClose(resp)
	if err != nil {
		return nil, errors.Wrap(err, ErrPostSignatureRequest)
	}

	// Handle errors
	if resp.StatusCode != 200 {
		details, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.Appendf(ErrPostSignatureRequest, "ballotclerk: %v - %v", resp.Status, details)
	}

	// Parse the fulfilled signature request
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, ErrPostSignatureRequest)
	}

	fulfilledReq, err := cryptoballot.NewFulfilledSignatureRequest(body)
	if err != nil {
		return nil, errors.Wrap(err, ErrPostSignatureRequest)
	}

	// Success
	return fulfilledReq, nil
}

// ResponseDrainAndClose drains a response of it's body and closes it
// It should be used in a defer statement when doing an HTTP request
func ResponseDrainAndClose(resp *http.Response) {
	if resp != nil {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}
