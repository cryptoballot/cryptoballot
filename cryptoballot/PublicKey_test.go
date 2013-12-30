package cryptoballot

import (
	"bytes"
	"testing"
)

var (
	goodKey = []byte("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu4W7ptone8v6Dve2/gRT8nisIStTzDNgHrFrFJUQMIlAzwqHCo4l6ZW5169SRyrCJvjljcEEH+WQgyUGOwUSpYHnCOPSXsKKWD6+X/dduk3oakGeQ6V9CMvyGKKUOZEyUP1uPSS6OH2lVCtc3eU1iMa4pFE75Qq3x54GUeFoJpRFllXhJZv4LF7TahkRYOgsrjRSbb/exUR9VRFVv3+03FB2gpgO6LGw5W7sGBvEjDA/ZKSii1m5Cvs14vYn1zhR7G0J6s+eqgh8yscs6fgaqttABl72Z9dLdmp3lTxRSQMDNJOExZb1TjE0Rr2fywZ19LyCym/8IUSkY1atx3Em/QIDAQAB")
	goodSHA = []byte("cad74457654f86a1da02406b262693976fa94e9f2ad26fcee35a182328cdcdba62ddc40cef1151f70b36a0e61348922a3ae59be8cebc4f1d143dc4d6c92ea630")
	badKey  = []byte("IAMNOTAKEY")
)

func TestGoodPublicKey(t *testing.T) {

	// Set the min public key length to 2048 for testing purposes
	MinPublicKeySize = 2048

	pk, err := NewPublicKey(goodKey)
	if err != nil {
		t.Error(err)
		return
	}

	if pk.IsEmpty() {
		t.Errorf("Valid public key should not be empty")
	}

	if pk.String() != string(goodKey) {
		t.Errorf("Public Key does not survive round trip from string and back")
	}

	_, err = pk.GetCryptoKey()
	if err != nil {
		t.Error(err)
	}

	SHA512 := pk.GetSHA512()
	if !bytes.Equal(SHA512, goodSHA) {
		t.Errorf("BallotID does not match SHA512. Got " + string(SHA512))
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
}
