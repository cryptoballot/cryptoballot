package cryptoballot

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"testing"
)

var (
	goodBallot = []byte(`12345

1d6d8c6965c4a72c35c6bf9ac66483405168578ee503bf4b4a2248b3cd0e2415d9fa2436eab027635819fdc4d458551081b8e0039ab242b08ba7c664633fe923

/12345/e69de29bb2d1d6434b8b29ae775ad8c2e48c5391
/12345/d16085b3b913e5bc5e351c0a7461051e9973629a

voter=Patrick Hayes
unsealed=true

NDu0+HUo4WjBnnmw0H5CGc31UEx5Z4bdUHRLiPrABkwT/QsQtbI0m58CAy0yXlShTQtqpx7yYfb88h0/E1Bzcn4SfYapYl0ZozrTRyY77CDqGi3LEnnX28IfW4Q/SuVfdNvxrJja9ay/sxZf0dTON7UZKKLV7zCS/2I5aVhgv5yeP26eCPpDOBlHFxZuPwUBJiXIZhGGU0DxTePgThgYIryGvnF+zdV59c81jec4nXWFDhmBVIR6RB0BAJDfcXv7UUY07deHtH2DAMvvd/CjRriZBbQSFOq5VNsWMd2/bFf3s0n2LhOrnsqVjkM0g8WXYm3tE9Q8kCpmybFCoFNYnv+YV2ZWbcUuwfnShqK1Pyr1Rg+avVun7LAyEuHzf8MoQC/UAUucPwu7t4Wq0ZpK8rM6UNmbPyEA5lF/VP30pmp1vFJlAkskydBdWPga5N9hzfJCRALfSq7Ssz6v8Q8y/WfrvsSt+GoPgneTAd8AHjxP/6/LOLRqZka9TVR2SigCPDlAvM0awpaxoxiulrMAOVdFIPk1E7SuWJHjmhWcS2FEjkXU3wc1qIng2H8Xf8IZXONL1sM2J5o7Vu/P9KKjINTCPVzL+WBea60Og9JAh8w/UlGMhHVm1e/yJcu+4VPPTKYpU/ftCE9n4MrPqxX7ZVI3Fo6kMPJD4QQF2u0/Esk=`)

	goodSigningKey = []byte(`MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwacgxmSwqRtsZaMtxc6O7hSl6Y1vwCwqaRnm3N5LMy52X1FiEW+jbZf3ngC/M9EC1LKz0Sctur0UXA038bJJHY8tHvV6qVjdb60GPK41CupbyhWaiYWps3DGRiUSRhAxROnekOsaThE+4HYWd/QzOeajLja06episY92lnGJ6I37uAhSqNm5GwEgufCtNVu9I8DIIOcV6YpEbmc21ZHMGgOautSfZ/dlw5qkpCWNqxW7WH7XQayuNE/mTKZ615HqIqjSh/+OjTj3jkvPvX32SzzhDmWHrYWOv1c6Qo3z8fNYjYFQMffLoy1QJ9G/KmuDw2rmkLXOc/sClv9Z/gZVW07Wg2Xsgp3y/1cH9J3uOqmb3WOukJGOCK4+E0oAb/qsLkOzIeiUoVEeNg/h8XPVO0cJjblEVnwhQe3jUKBXem7kDC0t9wSBsPOE/6BaXzwVPd8em5Tpuw07nSjiiZvvCUMMuoXvUG5UyTmJh9rEw3ehJACC1AJLfX/HJw+wB/p+TfEhmuNpvtUVegbCPkYTh1wQzFMAbIPjrWog2xWVshLb+L7GJm8CQPDlAkwXG676PcTlYdEIL0rReCVN+S6tr8nVPrQrUFePv7EM5sgyQ9XgfVglf+38wDHnrhFZxyEmaMzfMVDUhqt6NSgpceMo8KCNL0oaH+IdJsn7zXjKqQkCAwEAAQ==`)
)

// Basic test of parsing a good ballot
func TestBallotParsing(t *testing.T) {
	ballot, err := NewBallot(goodBallot)
	if err != nil {
		t.Error(err)
	}

	signingKey, err := NewPublicKey(goodSigningKey)
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
	keyStrings := ballot.TagSet.KeyStrings()
	if keyStrings[0] != "voter" || string(keys[0]) != "voter" || keyStrings[1] != "unsealed" || string(keys[1]) != "unsealed" {
		t.Errorf("Failed to extract proper key value from tagset")
	}
	values := ballot.TagSet.Values()
	valueStrings := ballot.TagSet.ValueStrings()
	if valueStrings[0] != "Patrick Hayes" || string(values[0]) != "Patrick Hayes" || valueStrings[1] != "true" || string(values[1]) != "true" {
		t.Errorf("Failed to extract proper value value from tagset")
	}
}

// A more meaningful test that takes us all the way through ballot creation, including creating the ballot and having it signed.
func TestBallotCreation(t *testing.T) {
	// Create a private / public keypair for the voter
	voterPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Error(err)
	}
	voterPub, err := NewPublicKeyFromCryptoKey(&voterPriv.PublicKey)
	if err != nil {
		t.Error(err)
	}
	// Create a public / private keypair for the ballot-clerk
	clerkPriv, err := rsa.GenerateKey(rand.Reader, 1024)
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

	// A manually created ballot should propely report if it has tagsets or signatures
	if ballot.HasTagSet() {
		t.Errorf("Manually created ballot not properly reporting if it has a taget")
	}
	if ballot.HasSignature() {
		t.Errorf("Manually created ballot not properly reporting if it has a signature")
	}

	// Create unsigned SignatureRequest
	signatureReq := SignatureRequest{
		ElectionID: "12345",
		RequestID:  voterPub.GetSHA512(),
		PublicKey:  voterPub,
		BallotHash: ballot.GetSHA512(),
	}

	// A manually crated SignatureRequest should properly report if it has been signed by the voter
	if signatureReq.HasSignature() {
		t.Errorf("Manually created SignatureRequest not properly reporting if it has a signature")
	}

	// Sign the Signature Request with the voter's key
	h := sha512.New()
	h.Write([]byte(signatureReq.String()))
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, voterPriv, crypto.SHA512, h.Sum(nil))
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
