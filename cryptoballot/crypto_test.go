package cryptoballot

import (
	"bytes"
	"encoding/base64"
	"testing"
)

var (
	goodKey = []byte("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuf2fxzp6UI2ejqeCf2vtj6k4MpNak4RSo1K02b+5Oi1WPVe6xZjNLDYDm6u6KpgSEhdYyVgigyknKfHALcQLwKbAP79RAmP3xwpv8+ts1r3rYBxooeRV50AXL9AuTb6qSnVHQ2LbixcgAvq+IpHqb6f9IhQLFhTQbCy/6LS1NQQIDAQAB")
	goodSig = []byte("Nz2xr8Ibn3CPwUrV2Ptr2iCtdtBEzrQ/10vTPlb8KfLF6R4JRryj7g1AlP75l1DwRjuSm90j2MTaNXgFceIQAUOPDvkOubyY7tyvTLY9LxRqw2iynoVZB79KJ2mZ9a2K9811mfQPpCqW0kxXMoFX3svza5arqAvFrwHNjM/K5YE=")
	goodSHA = []byte("1d6d8c6965c4a72c35c6bf9ac66483405168578ee503bf4b4a2248b3cd0e2415d9fa2436eab027635819fdc4d458551081b8e0039ab242b08ba7c664633fe923")
	goodMes = "PUT /vote/12345/" + string(goodSHA)
	badKey  = []byte("IAMNOTAKEY")
	badSig  = []byte("IAMNOTAVALIDSIGNATURE")
	badSHA  = []byte("GoodForNothingSHA")
	badMes  = "GET /bad/message"
)

func TestGoodPublicKey(t *testing.T) {
	pk, err := NewPublicKey(goodKey)
	if err != nil {
		t.Error(err)
	}

	_, err = pk.GetBytes()
	if err != nil {
		t.Error(err)
	}

	_, err = pk.getCryptoKey()
	if err != nil {
		t.Error(err)
	}

	ballotID := pk.GetBallotID()
	if !bytes.Equal(ballotID, goodSHA) {
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

func TestGoodSignature(t *testing.T) {
	sig, err := NewSignature(goodSig)
	if err != nil {
		t.Error(err)
	}

	sigbytes, err := sig.GetBytes()
	if err != nil {
		t.Error(err)
	}

	gooddecode, _ := base64.StdEncoding.DecodeString(string(goodSig))
	if !bytes.Equal(sigbytes, gooddecode) {
		t.Errorf("bas64 decoding for signature is wrong")
	}

	goodpk, _ := NewPublicKey(goodKey)
	err = sig.VerifySignature(goodpk, []byte(goodMes))
	if err != nil {
		t.Error(err)
	}
	err = sig.VerifySignature(goodpk, []byte(badMes))
	if err == nil {
		t.Errorf("Verified bad message as valid")
	}

	badpk, _ := NewPublicKey(badKey)
	err = sig.VerifySignature(badpk, []byte(goodMes))
	if err == nil {
		t.Errorf("Verified bad public key as valid")
	}
	err = sig.VerifySignature(badpk, []byte(badMes))
	if err == nil {
		t.Errorf("Verified bad public key and bad message as valid")
	}
}

func TestBadSignature(t *testing.T) {
	sig, err := NewSignature(badSig)
	if err == nil {
		t.Errorf("Invalid signature did not throw error")
	}

	if string(sig) != "" {
		t.Errorf("Invalid signature should return empty string")
	}

	goodpk, _ := NewPublicKey(goodKey)
	err = sig.VerifySignature(goodpk, []byte(goodMes))
	if err == nil {
		t.Errorf("Invalid signature should not be able to verify")
	}

	emptypk, _ := NewPublicKey([]byte(""))
	err = sig.VerifySignature(emptypk, []byte{})
	if err == nil {
		t.Errorf("Invalid signature should not be able to an empty public-key")
	}
}
