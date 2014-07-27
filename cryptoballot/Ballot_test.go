package cryptoballot

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"reflect"
	"testing"
)

var (
	goodBallot = []byte(`election12345

1d6d8c6965c4a72c35c6bf9ac66483405168578ee503bf4b4a2248b3cd0e2415

Mujica
Obama
Harper
Netanyahu
Putin

voter=Patrick Hayes
unsealed=true

v+dnjFSEtISBC9QHHtabOvzExR5VfwxOCkvrYOSRyevwo5ysAUTCPwZnewn2Liy+CHdox83KEnBTYQHCMTbTqR1jEXE883n6Cxj/6+Qp5Bz9rcOu578xG68a0iDGrvUPaJE7pN0dgAyHezwEFNtfx4/UqKURRfLInu70wL7glGEPuUJjCmjTxqZxIfiXweeIPoYdP5WHQdU5iryFN1vPHab/95lrcz4jrHvMKSSOOXOIav64B4YsCx5KZvGYJEN0WSAhu/ZGlEocHsXcnd9xDQZWi/vmsvw0Xjsn68Zc1wIhzbb5GGjWVb1v4edvGg0N0gvcNRKra7ULY+6hFkESib6IvXGufBbytK+v7tyr0oqIIcNiYuF2VUunpYyqkmLU8Ky5w6vFEcVi3H9ABtEQwcrnXvrLuN9eL6PX3TkhEQahYhVrb3vMsyI9sE6NRWZyp0zGW+E0bTqdtPkLvqRtqSHxVpYiiZLp4+x7mOqyzSCbg0df0XGV6stEXM15Cf1BlVjch0PRT6+pjUrbgDT1k8hkPV3ChD41uOV8R/agpDw3vJXi15fN7jB0H6xIAGexoIh7G8t5Thi5WXWHRYqW7PpaJdbW/hagz42TP4BO0A5L63TKABoLpHsM0tCBwz8GLz8h1YSeCqPN9kntTpLEFdPeUEjn/b14huvJnocMS2M=`)

	goodClerkPublicKey = []byte(`MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwacgxmSwqRtsZaMtxc6O7hSl6Y1vwCwqaRnm3N5LMy52X1FiEW+jbZf3ngC/M9EC1LKz0Sctur0UXA038bJJHY8tHvV6qVjdb60GPK41CupbyhWaiYWps3DGRiUSRhAxROnekOsaThE+4HYWd/QzOeajLja06episY92lnGJ6I37uAhSqNm5GwEgufCtNVu9I8DIIOcV6YpEbmc21ZHMGgOautSfZ/dlw5qkpCWNqxW7WH7XQayuNE/mTKZ615HqIqjSh/+OjTj3jkvPvX32SzzhDmWHrYWOv1c6Qo3z8fNYjYFQMffLoy1QJ9G/KmuDw2rmkLXOc/sClv9Z/gZVW07Wg2Xsgp3y/1cH9J3uOqmb3WOukJGOCK4+E0oAb/qsLkOzIeiUoVEeNg/h8XPVO0cJjblEVnwhQe3jUKBXem7kDC0t9wSBsPOE/6BaXzwVPd8em5Tpuw07nSjiiZvvCUMMuoXvUG5UyTmJh9rEw3ehJACC1AJLfX/HJw+wB/p+TfEhmuNpvtUVegbCPkYTh1wQzFMAbIPjrWog2xWVshLb+L7GJm8CQPDlAkwXG676PcTlYdEIL0rReCVN+S6tr8nVPrQrUFePv7EM5sgyQ9XgfVglf+38wDHnrhFZxyEmaMzfMVDUhqt6NSgpceMo8KCNL0oaH+IdJsn7zXjKqQkCAwEAAQ==`)
)

// Basic test of parsing a good ballot
func TestBallotParsing(t *testing.T) {
	// To speed testing we set the public key size to the mimumum. We don't care about real security during testing.
	MinPublicKeySize = absoluteMinPublicKeySize

	ballot, err := NewBallot(goodBallot)
	if err != nil {
		t.Error(err)
	}

	signingKey, err := NewPublicKey(goodClerkPublicKey)
	if err != nil {
		t.Error(err)
	}

	if err = ballot.VerifySignature(signingKey); err != nil {
		t.Error(err)
	}

	if string(goodBallot) != ballot.String() {
		t.Errorf("Ballot round-trip from string and back again failed.")
	}

	// Test tags
	keys := ballot.TagSet.Keys()
	if string(keys[0]) != "voter" || string(keys[1]) != "unsealed" {
		t.Errorf("Failed to extract proper key value from tagset")
	}
	values := ballot.TagSet.Values()
	if string(values[0]) != "Patrick Hayes" || string(values[1]) != "true" {
		t.Errorf("Failed to extract proper value value from tagset")
	}
	if !reflect.DeepEqual(ballot.TagSet.Map(), map[string]string{"voter": "Patrick Hayes", "unsealed": "true"}) {
		t.Errorf("Failed to extract proper map from tagset")
	}

}

// A more meaningful test that takes us all the way through ballot creation, including creating the ballot and having it signed.
func TestBallotCreation(t *testing.T) {
	// Create a private / public keypair for the voter
	voterPriv, err := rsa.GenerateKey(rand.Reader, absoluteMinPublicKeySize)
	if err != nil {
		t.Error(err)
	}
	voterPub, err := NewPublicKeyFromCryptoKey(&voterPriv.PublicKey)
	if err != nil {
		t.Error(err)
	}
	// Create a public / private keypair for the ballot-clerk
	clerkPriv, err := rsa.GenerateKey(rand.Reader, absoluteMinPublicKeySize)
	if err != nil {
		t.Error(err)
	}
	clerkPub, err := NewPublicKeyFromCryptoKey(&clerkPriv.PublicKey)
	if err != nil {
		t.Error(err)
	}

	// Create an unsigned ballot
	ballot := Ballot{
		ElectionID: "12345",
		BallotID:   "ARandomlyVoterSelectedString",
		Vote:       Vote{"voteserver.com/12345/option1", "voteserver.com/12345/option2"},
	}

	// Create unsigned SignatureRequest
	signatureReq := SignatureRequest{
		ElectionID: "12345",
		RequestID:  voterPub.GetSHA256(),
		PublicKey:  voterPub,
		BallotHash: ballot.GetSHA256(),
	}

	// Sign the Signature Request with the voter's key
	h := sha256.New()
	h.Write([]byte(signatureReq.String()))
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, voterPriv, crypto.SHA256, h.Sum(nil))
	if err != nil {
		t.Error(err)
	}
	signatureReq.Signature = Signature(rawSignature)

	// Verify the SignatureRequest signature
	err = signatureReq.VerifySignature()
	if err != nil {
		t.Error(err)
	}

	// Sign the ballot with the clerk's key
	ballot.Signature, err = signatureReq.SignBallot(clerkPriv)
	if err != nil {
		t.Error(err)
	}

	// Verify the ballot signature
	err = ballot.VerifySignature(clerkPub)
	if err != nil {
		t.Error(err)
	}
}
