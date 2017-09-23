package cryptoballot

import (
	"bytes"
	"crypto/rsa"
	"testing"
)

var (
	goodPublicKey    = []byte("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA31GRu9r2QRA9PtIzMKyV3vloQlrmxRLYIgiUsNg6bNOmTOJ1og+HNpTY8XOujf3KpPS38F1XM3AAJQi3pUjcJEdeiqroFf8b7t2pas1V+Bg2XAWWbfKctpnMuxeIYuJE52KhUK4y+qGaLXI+53oT09w3V4CdeQNZllVL2a6q+6gjpdZ+/YOPQ+dncHtYCxNHu1Idub0EP/ZMkdcHLwpi/gmuw7qvdpQTeiw54krV3MoiZq50ZTxTFRCjFJ+C+pmrYaPygrkCkv3sj3v1Be8k0EBYsMH8yZoigbyE0/SlCH+RGLSiS1yAV+MHcoVMzPFbXnFv9usI3UNVSXrDSzsxYgiDaeX7KVrraKhJrM/LIypZbJDiKLpLzKFEx+SkSQ/3e8eSsedp7N5RSvcz9GU6K4sUYtvNdiwHZTTakoo7m8pBF7dE9Guxjtcc42vwBSArsYrfstFcMaVwwth1Ohh/vO1W5EmMzzsqqm7DYPCVFapwV7wlveYFyD5e9ZVb/im8s+2NHg6PY5L1ke+JN+zx75M54nGezk+1pJcy05r66a56Wyh85RgMUok1XMPbiVmhA8TVwlCZGnfXetsSsFKgFjAGD+DdLCdkj9TH2tG7pewlEDNjVM+iWJA8Tmt/H+n4tL1LedzGs1KkwEZKEcxZtxDdBxPWFQDK3UloOwaP6y0CAwEAAQ==")
	goodPublicKeySHA = []byte("698274e67a7f9bdb7a19e6b6d12fa07c4b2074b512ce7fa341f865d137e0335a")
	badKey           = []byte("IAMNOTAKEY")
)

func TestGoodPublicKey(t *testing.T) {

	// Set the min public key length to 2048 for testing purposes
	MinPublicKeySize = 2048

	pk, err := NewPublicKey(goodPublicKey)
	if err != nil {
		t.Error(err)
		return
	}

	if pk.IsEmpty() {
		t.Errorf("Valid public key should not be empty")
	}

	if pk.String() != string(goodPublicKey) {
		t.Errorf("Public Key does not survive round trip from string and back")
	}

	_, err = pk.GetCryptoKey()
	if err != nil {
		t.Error(err)
	}

	hash := pk.GetSHA256()
	if !bytes.Equal(hash, goodPublicKeySHA) {
		t.Errorf("BallotID does not match SHA256. Got " + string(hash))
	}
}

func TestBadPublicKey(t *testing.T) {
	pk, err := NewPublicKey(badKey)
	if err == nil {
		t.Errorf("Invalid public key did not return error")
	}
	if !pk.IsEmpty() {
		t.Errorf("Invalid public key should be empty")
	}

	_, err = NewPublicKeyFromCryptoKey(&rsa.PublicKey{})
	if err == nil {
		t.Errorf("Invalid public key did not return error")
	}
}

func TestMinPublicKeyLength(t *testing.T) {
	// It's over 9000!
	MinPublicKeySize = 9000

	_, err := NewPublicKey(goodPublicKey)
	if err == nil {
		t.Errorf("Too small a public key should result in an error.")
	}

	// Put it back
	MinPublicKeySize = 2048
}
