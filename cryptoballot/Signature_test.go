package cryptoballot

import (
	"bytes"
	"encoding/base64"
	"testing"
)

var (
	goodMes = "DELETE /vote/12345/1d6d8c6965c4a72c35c6bf9ac66483405168578ee503bf4b4a2248b3cd0e2415d9fa2436eab027635819fdc4d458551081b8e0039ab242b08ba7c664633fe923"
	badMes  = "BAD"
	goodSig = []byte("iGa4SQCbwCsxGd4w8MX/YliQxjdZtlAsArV0ldEiIEb7d0oqGfRnxaVnPZY/jasaPUrBCjt94k924JXcCVJeT2r1JfOpxx6XKDCWXjrKXQcj5y+rFcKNeQe/rQkkprmskdXCGgqzFwMZ4R3RZ3GM/sC4LzlLdlKT9418WFPdWqJVGZRZFqR+cyvMmRjVFgHyQCkyvevyNb0Pw1jryF/bbttwr61WlFdW6FUTytguTmN7R3Wf0K3Zi9Pt8Co/TAIj+s9+VGQKeoRT3c8h3igGd0fD591fdx4tXnF2PAzWzsWlf763UG5CKWpbKKkpGW5JegqdTL90ScmvEe5sNsVj6w==")
	badSig  = []byte("IAMNOTAVALIDSIGNATURE")
)

func TestGoodSignature(t *testing.T) {
	sig, err := NewSignature(goodSig)
	if err != nil {
		t.Error(err)
		return
	}

	sigbytes := sig.Bytes()
	gooddecode, _ := base64.StdEncoding.DecodeString(string(goodSig))
	if !bytes.Equal(sigbytes, gooddecode) {
		t.Errorf("bas64 decoding for signature is wrong")
	}

	goodpk, err := NewPublicKey(goodKey)
	if err != nil {
		t.Error(err)
		return
	}
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
