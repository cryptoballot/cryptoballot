package cryptoballot

import (
	"reflect"
	"testing"
)

var (
	PEMBlocks = []byte(`-----BEGIN PUBLIC KEY-----
name: Patrick Hayes
perms: election-admin, superuser

MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvj3bB5oFB/5uugOq2RqB
up8jLfo3JzA5zpMIUcXDBhOjUl1XqeVRPFuJUohydK28SFqaz1VUokq1VnN7SuqB
FEd+hFuO3dRTdEFg/so//6UtsTsVQ51xo5ejFfQdBtcu+Kje3mvFbiHvpGtU+HDb
OKRBdAwwAV7HfgL1c8N6S+Qcv7tfoEa6EvigTBIfLOlESmLgi57LdYo5mM6Cbqj7
r4YxBb4dwjPex9dmKETO8+TZdl1u2i8hlR5jcrIVDHNLcke3WemBTBaS9HXwt5CW
jMwgx07Eb3K0LU0Wcy8thfmDuY0GgAZBXqxmqeKgf8OXNsj0ez9lR7z0Y5qjzLA1
PpWB26MYef0kuNo1gaovBwbr1lTsxD/Yzs01f/hb4z+TAGknN1UCcBLKqhDbNHW0
MsGZ0Ath2K6Fgko5IrSpAb7ktOpcYR2dEijj+tFjbiHGB2PcPQqPTGacvk3sKkdI
s2+PaVsKUad+lcgR4iMbZdZYVm1yZ4J7Ky9vJMAEQcdTNeZRgQVntQHDV7XPPBe7
CZdtMRjCk0hX7ruLE3JQjF50eEAMdxridmHaceRz4LDvWpDvoMCZEnSofWMglK+1
nO/Fj51GPxc6avpk2KnIRyzCI6sC3V2PhJgOjTagrF7DOoJofBi0/SbB+DZ5+rBf
Sk0qc8JV6kJIUOGgOMsVZVcCAwEAAQ==
-----END PUBLIC KEY-----

-----BEGIN PUBLIC KEY-----
name: Jeffery McGuven
perms: election-admin

MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAssh3X76dUrufBKn4bBzS
v4RNVIIJJLR74uIBYQflfEy4v8KMmUtg85bwDePBV539HXd6rsT89lC/UBErGtc4
swcn6+503zdv4FOtJQ5ROc7RiEGr9pCB0H+zszhM24vuPjHPCvdAUw1ZU6eF/bma
07fW5Al97hrMXbVflN/m5zsG0cywsjBEbYXIF/R8fZti9u4KA0YgN2g7yM3wKnUv
lwcbgtYKN7lqjZQAwzMKa1/+nXzaGqzcSFlGsyyMkEMQP5eslhtqtkSrLpRIzH89
1NV/Q7UlnDiM50drA1xwwCHN7BFPFQ71qTNn0xtNlc5ESvNupUrxlKJsza5B4RGc
2naJE8rFLkod1IHYYk9eakXcMJY5EGd6XBsL94I24dyw+o7I2R3J7uHXv+MufjQt
rH7yTWe5DbL7B8ocNb3kHXU0q2YJF9P1tuZTqH6APU43Al05SbyfLMD8HYarRSMH
+wnaCqQ+v7uOrV9pnOqhkeMCnz/b2Kh3iPSntRzmIqxQh4rmbB5ySbfRKfddIyY4
VpVoDhBv0pvolJJLovEg+eymD72UeJ9OUUpfzIkQ6DIujnJFhq5pBTrvGKVvJHrD
aXvvivS3JMvbICKnNHO+KwGJwQByMBjvRoQE+opxOA1WLWvst3Tx2ESBXcalEpnr
H/AuAyMAFgIhe5Mqc98Y5gECAwEAAQ==
-----END PUBLIC KEY-----`)
)

func TestUserSet(t *testing.T) {

	userset, err := NewUserSet(PEMBlocks)
	if err != nil {
		t.Error(err)
		return
	}

	if len(userset) != 2 {
		t.Error("Wrong number of users loaded. Expecting 2")
		return
	}

	// Check to string and back
	checkuserset, err := NewUserSet([]byte(userset.String()))
	if err != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(checkuserset, userset) {
		t.Errorf("Failed roundtrip to string and back")
		return
	}

	user := userset[0]
	if user.Properties["name"] != "Patrick Hayes" {
		t.Errorf("name for first user not correct")
		return
	}
	if !user.HasPerm("election-admin") {
		t.Errorf("Patrick Hayes user does not have election-admin permission")
		return
	}
	if !user.HasPerm("superuser") {
		t.Errorf("Patrick Hayes user does not have superuser permission")
		return
	}
	if user.HasPerm("fakeperm") {
		t.Errorf("Patrick Hayes user reports has permission that does not exist")
		return
	}

	// Check the GetUser method
	checkuser := userset.GetUser(user.PublicKey)
	if !reflect.DeepEqual(*checkuser, user) {
		t.Errorf("Failed to extract proper user from userset")
		return
	}

	// Check to string and back
	checkuser, err = NewUser([]byte(user.String()))
	if err != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(*checkuser, user) {
		t.Errorf("Failed round-trip to string and back")
		return
	}

	// Make sure the second user exists
	user2 := userset[1]
	if user2.Properties["name"] != "Jeffery McGuven" {
		t.Errorf("name for second user not correct")
		return
	}

	// Test removal
	userset.Remove(user.PublicKey)
	checkuser = userset.GetUser(user.PublicKey)
	if checkuser != nil {
		t.Errorf("User not removed correctly")
		return
	}
	// The second user should now be in position 0
	if !reflect.DeepEqual(userset[0], user2) {
		t.Errorf("Second user not moved to position 0 on removal of user 1")
		return
	}
}
