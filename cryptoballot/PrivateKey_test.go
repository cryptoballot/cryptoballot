package cryptoballot

import (
	"crypto"
	"strings"
	"testing"

	"github.com/cryptoballot/fdh"
	"github.com/cryptoballot/rsablind"
)

var (
	goodPrivateKey = []byte(`
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
	badPrivateKey  = []byte("IAMNOTAKEY")
	badPrivateKey2 = []byte("-----BEGIN PRIVATE KEY-----MIIEpAIBAAKCAQE-----END PRIVATE KEY-----")
	badPrivateKey3 = []byte("-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQE-----END RSA PRIVATE KEY-----")
)

func TestGoodPrivateKey(t *testing.T) {

	priv, err := NewPrivateKey(goodPrivateKey)
	if err != nil {
		t.Error(err)
		return
	}

	if priv.IsEmpty() {
		t.Errorf("Valid private key should not be empty")
	}

	if strings.TrimSpace(priv.String()) != strings.TrimSpace(string(goodPrivateKey)) {
		t.Errorf("Private Key does not survive round trip from string and back")
	}

	message := "ATTACK AT DAWN"
	sig, err := priv.SignString(message)
	if err != nil {
		t.Error(err)
		return
	}

	pub, err := priv.PublicKey()
	if err != nil {
		t.Error(err)
		return
	}

	err = sig.VerifySignature(pub, []byte(message))
	if err != nil {
		t.Error(err)
		return
	}
}
func TestBadPrivateKey(t *testing.T) {
	pk, err := NewPrivateKey(badPrivateKey)
	if err == nil {
		t.Errorf("Invalid private key did not return error")
	}

	if !pk.IsEmpty() {
		t.Errorf("Invalid private key should be empty")
	}

	_, err = NewPrivateKey(badPrivateKey2)
	if err == nil {
		t.Errorf("Invalid private key did not return error")
	}

	_, err = NewPrivateKey(badPrivateKey3)
	if err == nil {
		t.Errorf("Invalid private key did not return error")
	}

	// Try to generate a zero length private key
	_, err = GeneratePrivateKey(0)
	if err == nil {
		t.Errorf("Zero sized private key should generate error")
	}
}

func TestBlindSignature(t *testing.T) {

	// Get the private key
	priv, err := NewPrivateKey(goodPrivateKey)
	if err != nil {
		t.Error(err)
		return
	}

	// Get the public key
	pub, err := priv.PublicKey()
	if err != nil {
		t.Error(err)
		return
	}

	// Get the public cryptoKey
	pubcrypt, err := pub.GetCryptoKey()
	if err != nil {
		t.Error(err)
		return
	}

	// Generate the message
	message := []byte("ATTACK AT DAWN")

	// Full-domain-hash that is half the key size
	hashed := fdh.Sum(crypto.SHA256, 1024, message)

	// Blind the message
	blinded, unblinder, err := rsablind.Blind(pubcrypt, hashed)
	if err != nil {
		t.Error(err)
		return
	}

	// Blind sign the blinded message
	sig, err := priv.BlindSign(blinded)
	if err != nil {
		t.Error(err)
		return
	}

	// Test doing a naive PKCS1v15 signature (which adds left padding to the result)
	_, err = priv.SignRawBytes(hashed)
	if err != nil {
		t.Error(err)
		return
	}

	// Unblind the signature
	unblindedSig, err := sig.Unblind(pub, unblinder)
	if err != nil {
		t.Error(err)
		return
	}

	// Verify the blind signature
	err = unblindedSig.VerifyBlindSignature(pub, message)
	if err != nil {
		t.Error(err)
		return
	}

}
