package cryptoballot

import (
	"testing"
)

// Basic test of parsing a good tagsets
func TestGoodTags(t *testing.T) {

	tag, err := NewTag([]byte("key=value"))
	if err != nil {
		t.Error(err)
	}
	if string(tag.Key) != "key" {
		t.Error("bad key")
	}
	if string(tag.Value) != "value" {
		t.Error("bad value")
	}
}

func TestBadTags(t *testing.T) {

	_, err := NewTag([]byte("value"))
	if err == nil {
		t.Error("Invalid tag produced no error")
	}

	_, err = NewTag([]byte("=value"))
	if err == nil {
		t.Error("Invalid tag produced no error")
	}

	_, err = NewTag([]byte("ljahsdflkjhasdflkjhasdflkjhasdflkjhasdflkjhasdflkjhasdfasdfkljlksdjflkasdfadsfadsfadf=value"))
	if err == nil {
		t.Error("Invalid tag produced no error")
	}

	_, err = NewTag([]byte("key=lkjasdflkjasdflkjasdfljasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdlfkjasdlfkjjlkdlskfjaslkdfjasdlkfjasdlfkjlkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdflkjasdfasdlfkjasdflkjasdflkj"))
	if err == nil {
		t.Error("Invalid tag produced no error")
	}

	_, err = NewTagSet([]byte("=value"))
	if err == nil {
		t.Error("Invalid tagset produced no error")
	}
}
