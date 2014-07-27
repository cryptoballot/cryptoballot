package cryptoballot

import (
	"bytes"
	"encoding/base64"
	"testing"
)

var (
	goodMes = "DELETE /vote/12345/1d6d8c6965c4a72c35c6bf9ac66483405168578ee503bf4b4a2248b3cd0e2415d9fa2436eab027635819fdc4d458551081b8e0039ab242b08ba7c664633fe923"
	badMes  = "BAD"
	goodSig = []byte(`gk5oTKo8NK0daXWaykT1O8HlngmLHIBnWCFIrZnYPYBzZENpQFfWa0aJ9zDmemid99AtR8CcTE6GYgEiX5EnqENg+eR88fzXvqaUeZa2sjk6tYS6/12nGYkx/FfbZF9StNKswkCNlM/hvmQpC1t49+SOu6aj8G5Y0Vu6/R1+7diTO+RXF0MbccEjz70meLo9JO+Eww5PhabbkfbMPmn9cfQbCTVFp3EWHMlalSkimV9VjkIOu6N1yu+BMLcVSTQSTZd0GBqbPS0ne17YJ4eKuCMMvKw8Vs3o9y3U27WdWRdzuQidAZCNGo9bk1aZa0koj95yc9BJE5gNLDm/ZGGo20+EBRmzshWaM1H58noNmoQye2UdxCGAQCGF4deBn8l02oXgc98ArkFCiKfK4CgZvKTPdWBInAOp8/8xPAZd/QFop8W4Jq40yiWUFIbFWumL5j+cA42eKq7AIvaaaGwkNthD8m5+HaxkyeWrs0jf1S2uk49EWvjnon5DO8qFOxu6339zh4p1fscKZoR1tUFMfvxz6t7dwlyNBYr5F4lNcRw6ylfHwYMD8QLl6HNXQ3vyXS5l9w94PGQiliTChiryPxAv8FmyCiywUdCTgXtt/PzWKaNw2pA5UCuoXYuyTbpQTD+GwK+UUet5so5rrr8ZZj1n2ao6PsYOVOiI5SOH+E4=`)
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

	goodpk, err := NewPublicKey(goodPublicKey)
	if err != nil {
		t.Error(err)
		return
	}

	err = sig.VerifySignature(goodpk, []byte(goodMes))
	if err != nil {
		t.Error(err)
		return
	}
	err = sig.VerifySignature(goodpk, []byte(badMes))
	if err == nil {
		t.Errorf("Verified bad message as valid")
		return
	}

	badpk, _ := NewPublicKey(badKey)
	err = sig.VerifySignature(badpk, []byte(goodMes))
	if err == nil {
		t.Errorf("Verified bad public key as valid")
		return
	}
	err = sig.VerifySignature(badpk, []byte(badMes))
	if err == nil {
		t.Errorf("Verified bad public key and bad message as valid")
		return
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

	goodpk, _ := NewPublicKey(goodPublicKey)
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
