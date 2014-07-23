package cryptoballot

import (
	"testing"
)

var (
	goodElection = []byte(`election12345

Thu, 04 Feb 2010 21:00:57 -0800

Fri, 05 Feb 2010 20:00:00 -0800

title=Election for President of the World
description=We will be electing a new world president for life to run things for a while.

1dd307cc3cf9a3bd233bbb240ab52ef1ff2b1f0a564c00ecd24c0c9a26ae8b3a3aaf5eb46d6e1a64ebb02829f9941621afaf79616d0facf997f8707b15185192

MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvj3bB5oFB/5uugOq2RqBup8jLfo3JzA5zpMIUcXDBhOjUl1XqeVRPFuJUohydK28SFqaz1VUokq1VnN7SuqBFEd+hFuO3dRTdEFg/so//6UtsTsVQ51xo5ejFfQdBtcu+Kje3mvFbiHvpGtU+HDbOKRBdAwwAV7HfgL1c8N6S+Qcv7tfoEa6EvigTBIfLOlESmLgi57LdYo5mM6Cbqj7r4YxBb4dwjPex9dmKETO8+TZdl1u2i8hlR5jcrIVDHNLcke3WemBTBaS9HXwt5CWjMwgx07Eb3K0LU0Wcy8thfmDuY0GgAZBXqxmqeKgf8OXNsj0ez9lR7z0Y5qjzLA1PpWB26MYef0kuNo1gaovBwbr1lTsxD/Yzs01f/hb4z+TAGknN1UCcBLKqhDbNHW0MsGZ0Ath2K6Fgko5IrSpAb7ktOpcYR2dEijj+tFjbiHGB2PcPQqPTGacvk3sKkdIs2+PaVsKUad+lcgR4iMbZdZYVm1yZ4J7Ky9vJMAEQcdTNeZRgQVntQHDV7XPPBe7CZdtMRjCk0hX7ruLE3JQjF50eEAMdxridmHaceRz4LDvWpDvoMCZEnSofWMglK+1nO/Fj51GPxc6avpk2KnIRyzCI6sC3V2PhJgOjTagrF7DOoJofBi0/SbB+DZ5+rBfSk0qc8JV6kJIUOGgOMsVZVcCAwEAAQ==

eXjtqeDHEyPpWW3yiYxfs/s2LVQtdX07SFj4X2RY1UWafBPXecISxVue5XSLQsoPvTkbJ6v+kootJPJq56/PDCHf8Ti9fN1yW2wJX0bLPX1eLJFzkIiZMeAudJpUT38lBkuMT5mOron4mr0onG6u47rLQYQgcBfDoTlKmVqVwQbe+8WauK+N8QpLHuRumtFTCEg1+9lcEcN6s+SwEy36YvNMTO4Pk5sts1Y9RSbILzf5gjNFWNAOjDB9+yVRGuXYimNedr9JXxAfUS8jI+w1zQeDUDaCr1ZpcjF9tOpiTs2wj+/chiyDeNmc5v1gC+jaPWsVUQvwFfu3FAsumA3+one4MKZh2zf9KalcFc+FWbfJzeUEQcdEmilP0dKdKV6BfOzJDnaq699eoxTBue8uwpzMZADIh7n2IZgdS0nmUDbQefk8xnoR7vtozipZlTu8WbvAMew9mGqsA6QsmZAx9ItDwmpjUBBEXbvMQZCtiCWDVbwdyAmaN6gzBd08X6kPPwLyIbMO1W2asXpjY8otlJDA17utDB0FNouv+5DgfF4c2clPE6TX00sLevt1f3jCR7E8n125A3qrzP3T9GPfJsYDQ1C0ERle4yRoPEmebKpfRC4oNxjndpc0Yem2GqoLT6qwlNQ2j5It05mgm7qdad4atjyJN2mnnlqmS/m+cFY=`)
)

// Basic test of parsing a good election
func TestElectionParsing(t *testing.T) {
	election, err := NewElection(goodElection)
	if err != nil {
		t.Error(err)
	}

	err = election.VerifySignature()
	if err != nil {
		t.Error(err)
	}

	if string(goodElection) != election.String() {
		t.Errorf("Election round-trip from string and back again failed.")
	}
}
