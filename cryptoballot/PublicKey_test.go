package cryptoballot

import (
	"bytes"
	"testing"
)

var (
	goodKey = []byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuf2fxzp6UI2ejqeCf2vtj6k4MpNak4RSo1K02b+5Oi1WPVe6xZjNLDYDm6u6KpgSEhdYyVgigyknKfHALcQLwKbAP79RAmP3xwpv8+ts1r3rYBxooeRV50AXL9AuTb6qSnVHQ2LbixcgAvq+IpHqb6f9IhQLFhTQbCy/6LS1NQQIDAQAB")
	goodSHA = []byte("1d6d8c6965c4a72c35c6bf9ac66483405168578ee503bf4b4a2248b3cd0e2415d9fa2436eab027635819fdc4d458551081b8e0039ab242b08ba7c664633fe923")
	badKey  = []byte("IAMNOTAKEY")
)

func TestGoodPublicKey(t *testing.T) {
	pk, err := NewPublicKey(goodKey)
	if err != nil {
		t.Error(err)
		return
	}

	_, err = pk.GetCryptoKey()
	if err != nil {
		t.Error(err)
	}

	SHA512 := pk.GetSHA512()
	if !bytes.Equal(SHA512, goodSHA) {
		t.Errorf("BallotID does not match SHA512")
	}
}

func TestBadPublicKey(t *testing.T) {
	pk, err := NewPublicKey(badKey)
	if err == nil {
		t.Errorf("Invalid public key did not return error")
	}
	if string(pk) != "" {
		t.Errorf("Invalid public should return empty")
	}
}
