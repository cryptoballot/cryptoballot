package cryptoballot

import (
	"reflect"
	"testing"
)

var (
	goodRequest = []byte(`testelection

d727018be6949482ab21cc23cc2ec9b33832965cee2d31b25cc384be9a12c5e8

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`)
)

func TestGoodSignatureRequest(t *testing.T) {
	req, err := NewSignatureRequest(goodRequest)
	if err != nil {
		t.Error(err)
		return
	}

	if string(goodRequest) != req.String() {
		t.Errorf("SignatureRequest round-trip from string and back again failed.")
		return
	}

	key, err := GeneratePrivateKey(4096)
	if err != nil {
		t.Errorf("failed to generate private key")
		return
	}

	// Note that in this test we are using a random private key, so the unblinding wont work.
	sig, err := key.BlindSign(req.BlindBallot)
	if err != nil {
		t.Error(err)
		return
	}

	// Test round-trip FulfilledSignatureRequest to string and back
	fufilledSignReq := NewFulfilledSignatureRequestFromParts(*req, sig)
	fufilledSignReqStr := fufilledSignReq.String()
	checkFufilledSignReq, err := NewFulfilledSignatureRequest([]byte(fufilledSignReqStr))
	if err != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(*checkFufilledSignReq, *fufilledSignReq) {
		t.Errorf("FulfilledSignatureRequest failed string round-trip")
	}
}
