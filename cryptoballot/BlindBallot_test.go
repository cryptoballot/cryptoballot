package cryptoballot

import (
	"testing"
)

var (
	blindBallotSigningAuthPrivateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA24vYqSbf98icsCYvFB6AqvLxEVsAHRwJuzg7JlBgQkOTpjPR
fs4SuCzQPOT9vKchnz2NGcxqaQY0ED0O1xdsYWKwvPiyuAQtSKIuLG3o75YQLG0I
gxEwLR41YI7OcaqNAKhzgQcfqEBHfYeUigM3wxmVu7B51x52nCRdypQepeliQRF0
Z/WJIIEkzLcCkWzUKnkR1i+eVEWHTC2gPGVL1qjrBYuQzjNsGw2HTo/FqZgSH5yp
o8vlkUwbNCCBRpdDwirSS+oyaBMTR0eBtbVnngV2kkr5mN3wrEMDI24AGKlXJCLZ
90yUVRUREyRNUcYf7k+JmWp3Hbt8Yo6+VwjZMwIDAQABAoIBAAUn1I+sVQgZkuxk
CSj8ymK5T8XrkCYe2W+nE2SD8K69rYLyppHGvxPKIZ28duTuO9DkfiLD9R/AQIq9
FFMivq3Oxn25jWDa4EFbZaAveI/fw0N30AJb7fixQ+mfkOOEcMk6K3Q1OZ4W3Fbr
Tyaqiq2vNR/yNfpCQeDKzdULA2k79ajRBE8Ba7s57ydUG/KEP1pIWQKCSN/kts6n
H/21j7Z8Oy9cRXRIY6ldK197gSkR4OtJBY4Q1U24sNSXtElSIM7rHO+UN8tPN3ov
VJLmfSGTgKX+X+I/MLJNOO0JECZtP/AseGjrEwIWT1CJHe8ei7vjMBJvK2qMJRv/
DrhxMIkCgYEA9yI05eXrYsN5VY88gyHscgEQk56Ec2j3Z5M9xVvW3G0t+fZb860G
GQ0Vi/k2c/eaLeJEPfLI63m8La8nWF9NonROaEsp4PyEGP6xlFc2dRg/sXQCDJ9+
Pjj4fg5qcMQ8kp730Ws0eUpgqIsoz7LKtCvJK994a0WMZg5Aoqh/y5cCgYEA42xD
qvLdSAXsTMjURsZ3QaMNycKubkIJpBHGVCr8USFMFo3cznDhe1muqzbtwWGkZspp
vy4z0elR9PUqQC/o9svLeLE224/8TLjl+k4vGRpgbjSSIu6MnmhTduZwpjQWirqp
hbzrCgxQs+jjSwOKABCNW/WfO6GyY1JylYb2AsUCgYEAvvwhczWPBiFYaGWsdw7F
YokuHVbYtzP8Vn/0scu6rVh2uoDIKPWjC8MPzr+GdHJ6JVGCOXmiClBmu8trlaD5
Jz3IxlKoB6Y+E+7on2ISxMU7m9CyML0lW8K9TvWnDoSo5wqRK7c0szNmpXn9zR04
B6r66bvmnMf/q3MCQnIDaPsCgYASX9nrwumL+yaHYaZ8/WX/QJxJk9giAmXjAqii
fkKaj3UlUVrotwgQvkM1hB+bgzcUMwBuON5o9E/x2akLPJO29OpAmxjSjoSU8k9q
dMyrW400+jxgZCOqXMV5ks7BLu4vUTuHGadnzWzrzEIo+mU48h1ps6Ok3sCZ87xc
RmYz/QKBgQCPubppetbX6kztDbwhPd9ywEmOk9tZDT2TALZNKNvgOOSL6n4Tv3ER
oofx/v7+fsI+xEvjJs1Ga2JD1lY4w3OTV1GK4tJNkqAdgEBu0WDo9rWlkAy5XxTQ
9cLZzlBw7bxoBivUvVoiAUxhWYkEQgp2eoZ1vCUQddRr3jX9ceEa/g==
-----END RSA PRIVATE KEY-----
`)

	blindBallotBallot = []byte(`election12345

1d6d8c6965c4a72c35c6bf9ac66483405168578ee503bf4b4a2248b3cd0e2415

Rinpoche
Gandhi
Mahakashyapa`)
)

func TestBlindUnblind(t *testing.T) {

	ballot, err := NewBallot(blindBallotBallot)
	if err != nil {
		t.Error(err)
		return
	}

	priv, err := NewPrivateKey(blindBallotSigningAuthPrivateKey)
	if err != nil {
		t.Error(err)
		return
	}

	pub, err := priv.PublicKey()
	if err != nil {
		t.Error(err)
		return
	}

	blinded, unblinder, err := ballot.Blind(pub)
	if err != nil {
		t.Error(err)
		return
	}

	// Round trip the blinded ballot
	blindedString := blinded.String()
	blinded, err = NewBlindBallot([]byte(blindedString))
	if err != nil {
		t.Error(err)
		return
	}

	blindSig, err := priv.BlindSign(blinded.Bytes())
	if err != nil {
		t.Error(err)
		return
	}

	err = ballot.Unblind(pub, blindSig, unblinder)
	if err != nil {
		t.Error(err)
		return
	}

	err = ballot.VerifyBlindSignature(pub)
	if err != nil {
		t.Error(err)
		return
	}

	// Run the unblinded ballot through a round-trip
	ballotString := ballot.String()

	ballot2, err := NewBallot([]byte(ballotString))
	if err != nil {
		t.Error(err)
		return
	}

	err = ballot2.VerifyBlindSignature(pub)
	if err != nil {
		t.Error(err)
		return
	}

	if ballot2.String() != ballot.String() {
		t.Error("Round trip ballot does not work")
		return
	}

}

func TestBadBlindBallot(t *testing.T) {

	_, err := NewBlindBallot([]byte("INVALID BLIND BALLOT"))
	if err == nil {
		t.Error("Invalid blind ballot should produce error")
	}

}
