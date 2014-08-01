package cryptoballot

import (
	"reflect"
	"testing"
)

var (
	goodRequest = []byte(`election12345

698274e67a7f9bdb7a19e6b6d12fa07c4b2074b512ce7fa341f865d137e0335a

MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA31GRu9r2QRA9PtIzMKyV3vloQlrmxRLYIgiUsNg6bNOmTOJ1og+HNpTY8XOujf3KpPS38F1XM3AAJQi3pUjcJEdeiqroFf8b7t2pas1V+Bg2XAWWbfKctpnMuxeIYuJE52KhUK4y+qGaLXI+53oT09w3V4CdeQNZllVL2a6q+6gjpdZ+/YOPQ+dncHtYCxNHu1Idub0EP/ZMkdcHLwpi/gmuw7qvdpQTeiw54krV3MoiZq50ZTxTFRCjFJ+C+pmrYaPygrkCkv3sj3v1Be8k0EBYsMH8yZoigbyE0/SlCH+RGLSiS1yAV+MHcoVMzPFbXnFv9usI3UNVSXrDSzsxYgiDaeX7KVrraKhJrM/LIypZbJDiKLpLzKFEx+SkSQ/3e8eSsedp7N5RSvcz9GU6K4sUYtvNdiwHZTTakoo7m8pBF7dE9Guxjtcc42vwBSArsYrfstFcMaVwwth1Ohh/vO1W5EmMzzsqqm7DYPCVFapwV7wlveYFyD5e9ZVb/im8s+2NHg6PY5L1ke+JN+zx75M54nGezk+1pJcy05r66a56Wyh85RgMUok1XMPbiVmhA8TVwlCZGnfXetsSsFKgFjAGD+DdLCdkj9TH2tG7pewlEDNjVM+iWJA8Tmt/H+n4tL1LedzGs1KkwEZKEcxZtxDdBxPWFQDK3UloOwaP6y0CAwEAAQ==

efaa26d44cf32c85b0c4b349bed352eb36ac5d2beb7e19ff6316cce83d5a3e65

Y20CMKv5ZziQAunpCSB2ey9YCPhvm6KrI9X/Hoz8+qp7yCsJewl2we8NOKGsujE/ObFan+Hxgq7PFTrCWNwiJR+KQ/KExquRLbGkaC1BocxMGcLouIEtY1fkivG1/h1z6VXcpjkN/J/B8Z7BGsie+qDJnk1zOjJcl7psvneiy215BI5FIBcE1pQS+S9HI5db5Jw4l4zAtIV8a3R16VViQ5dmCeftnGWJyhJUz+b8GaHDzQirN1dEVvchSxtmZJ0gsCcTOl26iIaT72R9jx0KaODmSf/s6jcR08TXkSG32skP7uT0o4jUZtxVaazpcX7ni55xl85oNiVC5MoXsJJ2PRPr6vvXcHqKZLTOo+26vopbJ8aZiitB61ZSsr1jf+J21ar72AC2ijYHYZr+jBrjB43d3bB724qRGiU6lHxv0lQ03ZOyfclOls6MfgVK5iKU+3tugJG1YhzrLdtcyQqtE18XVLS5rReC3oL0KF8j4To6zopyzjIVjQP5ayx469syQfWqTWAlFbuXxRaVtYAcD6gnXpVoQ9jThf/PK8iKXLyArgNNJgmgW+GANpU+q6ryjnDpgzPG57YMGtOgMfm1DVk4ky3SXP7SKGji/hfKN6kd15wL7LU8hZ7MF0+x7sHziYf69BdoNHihfiTpE5fhWQ/pR+bjJ14l/6eiFP0GcjQ=`)
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

	key, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Errorf("failed to generate private key")
		return
	}

	sig, err := req.SignBallot(key)
	if err != nil {
		t.Errorf("failed to sign ballot")
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
