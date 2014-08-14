package cryptoballot

import (
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

pPpGyjIl7nDozxnqhMlG0kze+Ln2QQP/k5iU1p6ATtnE1FF3Yo4b4cIfolUp6QFkC7QUOknf3cs01D7dXQ4rhPKDP/YtHJ0x99v11U6NYLtD3eTHAG/Z9yG9pRPoS2CLDirid5kiDv713AZfsag5u8gm8366brRD3/kf+y7SFAVQjwwjqXb3sB7LMWsaVstQpfJUCn8cypdfXn+MS4+KLYV6g9blXjA9IBH8Q+BVPdcWwxlxF5g/b8GTjMkBXFp1hBjWIO2NcO2VXyIl7SSJXn6Dus+JOWbgeYaN9fPX7jYP/yGAAeFFlmCAKLxYSVkZ60AuEqKMflP3CpyLQYdgn14o5ClYCaMZuZ2BkS7D1SCFuMQbq+nb4o0tl2/ijP0jjIZe9bOHYcI/3Sq6pkyDX3KhBOtrXoxmVhsChfiwROEAfzKktq2ULDJlieDzz5pfJ7h4GAxF7FOeK84jsfdAOGN3gqlvyHyTYsqgSabJ76/iFo5Xn8P0MFIVlWWuqvLXfoCqP62tplkv0N/Bpbdw9w6qxDPyCEL5G1Y8hxlxGqbXaG2UR+ZnqlUnmWswFEvWKe964BhbjGB7Jb7RYgl+cAHBH7Qs+4R3byaBcpztNegftEl8edCxGDpEflxJBfhc2RyA8DPDuiyE2Lw8Y9KXUZH8bCqi3k9wV1xY/QdlIlg=`)

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
	voterPriv, err := GeneratePrivateKey(absoluteMinPublicKeySize)
	if err != nil {
		t.Error(err)
	}
	voterPub, err := voterPriv.PublicKey()
	if err != nil {
		t.Error(err)
	}
	// Create a public / private keypair for the ballot-clerk
	clerkPriv, err := GeneratePrivateKey(absoluteMinPublicKeySize)
	if err != nil {
		t.Error(err)
	}
	clerkPub, err := clerkPriv.PublicKey()
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
	signatureReq.Signature, err = voterPriv.Sign(signatureReq)
	if err != nil {
		t.Error(err)
	}

	// Verify the SignatureRequest signature
	err = signatureReq.VerifySignature()
	if err != nil {
		t.Error(err)
	}

	// Sign the ballot with the SignatureRequest, using the clerk's private key
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
