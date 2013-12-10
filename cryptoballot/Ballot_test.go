package cryptoballot

import (
	"testing"
)

var (
	goodBallot = []byte(`12345

1d6d8c6965c4a72c35c6bf9ac66483405168578ee503bf4b4a2248b3cd0e2415d9fa2436eab027635819fdc4d458551081b8e0039ab242b08ba7c664633fe923

MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuf2fxzp6UI2ejqeCf2vtj6k4MpNak4RSo1K02b+5Oi1WPVe6xZjNLDYDm6u6KpgSEhdYyVgigyknKfHALcQLwKbAP79RAmP3xwpv8+ts1r3rYBxooeRV50AXL9AuTb6qSnVHQ2LbixcgAvq+IpHqb6f9IhQLFhTQbCy/6LS1NQQIDAQAB

/12345/e69de29bb2d1d6434b8b29ae775ad8c2e48c5391
/12345/d16085b3b913e5bc5e351c0a7461051e9973629a

voter=Patrick Hayes
unsealed=true

fGE9hjuFENrOpBvy7A4++oRDQ0cszuhqFm2aMlFwH2HzEF7aJygTxyXmWCEGMIXI5LmEC4SvXXaEmh4R5ZX8qzmVlrg+kvJTEeIkSu8E2bZfPWw1UasrQirNwvGXy902rsPAa1tdUSXjkaRcYk4I4h017k8fcRSTv/R/3mwdVPg=`)
)

func TestGoodBallot(t *testing.T) {
	ballot, err := NewBallot(goodBallot)
	if err != nil {
		t.Error(err)
	}

	if err = ballot.VerifySignature(); err != nil {
		t.Error(err)
	}

	if string(goodBallot) != ballot.String() {
		t.Errorf("Ballot round-trip from string and back again failed.")
	}
}
