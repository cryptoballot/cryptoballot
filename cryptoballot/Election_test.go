package cryptoballot

import (
	"testing"
)

var (
	goodElection = []byte(`ELECTION12345

Thu, 04 Feb 2010 21:00:57 -0800

Fri, 05 Feb 2010 20:00:00 -0800

title=Election for President of the World
description=We will be electing a new world president for life to run things for a while.

1dd307cc3cf9a3bd233bbb240ab52ef1ff2b1f0a564c00ecd24c0c9a26ae8b3a3aaf5eb46d6e1a64ebb02829f9941621afaf79616d0facf997f8707b15185192

MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvj3bB5oFB/5uugOq2RqBup8jLfo3JzA5zpMIUcXDBhOjUl1XqeVRPFuJUohydK28SFqaz1VUokq1VnN7SuqBFEd+hFuO3dRTdEFg/so//6UtsTsVQ51xo5ejFfQdBtcu+Kje3mvFbiHvpGtU+HDbOKRBdAwwAV7HfgL1c8N6S+Qcv7tfoEa6EvigTBIfLOlESmLgi57LdYo5mM6Cbqj7r4YxBb4dwjPex9dmKETO8+TZdl1u2i8hlR5jcrIVDHNLcke3WemBTBaS9HXwt5CWjMwgx07Eb3K0LU0Wcy8thfmDuY0GgAZBXqxmqeKgf8OXNsj0ez9lR7z0Y5qjzLA1PpWB26MYef0kuNo1gaovBwbr1lTsxD/Yzs01f/hb4z+TAGknN1UCcBLKqhDbNHW0MsGZ0Ath2K6Fgko5IrSpAb7ktOpcYR2dEijj+tFjbiHGB2PcPQqPTGacvk3sKkdIs2+PaVsKUad+lcgR4iMbZdZYVm1yZ4J7Ky9vJMAEQcdTNeZRgQVntQHDV7XPPBe7CZdtMRjCk0hX7ruLE3JQjF50eEAMdxridmHaceRz4LDvWpDvoMCZEnSofWMglK+1nO/Fj51GPxc6avpk2KnIRyzCI6sC3V2PhJgOjTagrF7DOoJofBi0/SbB+DZ5+rBfSk0qc8JV6kJIUOGgOMsVZVcCAwEAAQ==

XYHfnuxq9b8adrPeZms3tfUJjggppdkDF5jPgJPChsURa9ggnzT++uy94j1LEiWh8NbTn9eK5kafyknYfOIhXpFn9po2ecNboiWTvUpJzNWGw+IqMlXU76aNQko1/ZJ+TVasMvmnX4vMGXW+5WcwSxIORKqSv50RAqONVbh92ftBg8oSsJbI/opBq0EQjzIfKyFlkToV5w69FqTf3mUFknDxpCFFjNFlzAgvE0d1YtdaLGpEEPfxFEuaRI7QpehXoCAwCjBnnJfUN9EAEAyNPLBtpZ2J5griw2yA+wDjREogRH0pGL/hKgq/GjD7Il1nxUfk1uFL8jdykQtfapdsIGtiMNllX8me0TeKNXFoFhPB6qXhKWnMJ/YPjvX9b0UtOUW8nd3cs7/R/R9Bz6bB9rxWh1X5F7l92V8AeptGHnFjl0ZYCMKn9WMCyydrdLYbTo/AAbJKvCT3u3MuJdv3OQXmZgtmjKvEmnZPnl77X55qZUSmYpNwzRxVb6IplB9KSlChs11MkgVv4g3XqBDyCClifSgCUZn3EMzwyS6sdraBdEKI5J0MKx4Z/k/y2dIUHB8dS1CjXrjLW1kNmwlaOHAVOA0piHZ+aOOIraPbpin96wb+ezIDSvHBc1KIrQtYhEQkvo3DGET+cbq1k2pbuwGu3f5onge4Y5ofurCHe2w=`)
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
