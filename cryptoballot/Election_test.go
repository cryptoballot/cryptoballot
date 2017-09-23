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

MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvj3bB5oFB/5uugOq2RqBup8jLfo3JzA5zpMIUcXDBhOjUl1XqeVRPFuJUohydK28SFqaz1VUokq1VnN7SuqBFEd+hFuO3dRTdEFg/so//6UtsTsVQ51xo5ejFfQdBtcu+Kje3mvFbiHvpGtU+HDbOKRBdAwwAV7HfgL1c8N6S+Qcv7tfoEa6EvigTBIfLOlESmLgi57LdYo5mM6Cbqj7r4YxBb4dwjPex9dmKETO8+TZdl1u2i8hlR5jcrIVDHNLcke3WemBTBaS9HXwt5CWjMwgx07Eb3K0LU0Wcy8thfmDuY0GgAZBXqxmqeKgf8OXNsj0ez9lR7z0Y5qjzLA1PpWB26MYef0kuNo1gaovBwbr1lTsxD/Yzs01f/hb4z+TAGknN1UCcBLKqhDbNHW0MsGZ0Ath2K6Fgko5IrSpAb7ktOpcYR2dEijj+tFjbiHGB2PcPQqPTGacvk3sKkdIs2+PaVsKUad+lcgR4iMbZdZYVm1yZ4J7Ky9vJMAEQcdTNeZRgQVntQHDV7XPPBe7CZdtMRjCk0hX7ruLE3JQjF50eEAMdxridmHaceRz4LDvWpDvoMCZEnSofWMglK+1nO/Fj51GPxc6avpk2KnIRyzCI6sC3V2PhJgOjTagrF7DOoJofBi0/SbB+DZ5+rBfSk0qc8JV6kJIUOGgOMsVZVcCAwEAAQ==

WDy7EUvvY2guSXtW+GdmXRGuGeR8wGvDarir+591CCoY0F68XKaEBHhpMxL1m8lAYA22oZ9b+/dkXaiw4NBzOeEM31yNnsRBBFY33Pn7vim5DKYOq73/KVlJaI2YBBJPt6MAHGbnWvPPgZhXiMBX7YBq8mYRVHTcN5+g73OFEJjyXyEAPItkR9CB8k+4IRlsP1GuAc/IshibEhoLShqy1tEe4RdB7mPz/8aLGlylyqKoR9SSr/mr9TNlXklc8gH2hbSeSXXXL9Pv5TzulRLf9ScYwWUucPNtjKFhyfQqgqvCpWWN4XVpDIitd1l9ItiiKzgRKtoIXlx/Qq48sJAQUgpC8q6kQIZlW2ZX7YI6oF1/TNy9LRFVvsb3t/RhxKeJRDSR7H0fmn8Hd/pL0hVKlA3FjwywADJJxFHKyCitxwFJJgaAgDuiWWYFu4/mbeNcHor4PRQ5J67c22qpiBaP3KeryGb9o1bMMmKD4yGtojGsMssCzJkA2CCHGGs6g7OuFoEAQai7sggIKr0ggsIF4L6vWzAbFmwtUnCdUSzAtMIoDI+dROVxNY5PF9yy440W1K3sdssVNJtkoLQ5WIRYDq2cszLcOF6R/dQ9rKiBFHXQkjnSEZGaW/jxpWIw76dn8zKR+7ca2XheqsVh+YGVDvtIMo99YHnbcV+MoKh1awU=`)
)

// Basic test of parsing a good election
func TestElectionParsing(t *testing.T) {
	election, err := NewElection(goodElection)
	if err != nil {
		t.Error(err)
		return
	}

	err = election.VerifySignature()
	if err != nil {
		t.Error(err)
		return
	}

	if string(goodElection) != election.String() {
		t.Errorf("Election round-trip from string and back again failed.")
		return
	}

	withoutSigString := election.StringWithoutSignature()

	election2, err := NewElection([]byte(withoutSigString))
	if err != nil {
		t.Error(err)
		return
	}

	if election2.String() != election.StringWithoutSignature() {
		t.Error("election without signature round trip failed")
		return
	}

	// Remove tags and test
	election.TagSet = nil
	election2.TagSet = nil

	withoutTags1String := election.String()
	withoutTags2String := election.String()

	withoutTags1, err := NewElection([]byte(withoutTags1String))
	if err != nil {
		t.Error(err)
		return
	}
	withoutTags2, err := NewElection([]byte(withoutTags2String))
	if err != nil {
		t.Error(err)
		return
	}

	if withoutTags1.String() != withoutTags1String {
		t.Error("election without tags round trip failed")
	}
	if withoutTags2.String() != withoutTags2String {
		t.Error("election without tags round trip failed")
	}

}
