package cryptoballot

import (
	"bytes"
	"github.com/phayes/errors"
)

const (
	MaxTagKeySize   = 64
	MaxTagValueSize = 256
)

type Tag struct {
	Key   []byte
	Value []byte
}

type TagSet []Tag

var (
	ErrTagKeyTooBig    = errors.Newf("Tag key too long. Maximum tag key size is $i characters", MaxTagKeySize)
	ErrTagValTooBig    = errors.Newf("Tag value too long. Maximum tag value size is $i characters", MaxTagValueSize)
	ErrTagMalformed    = errors.New("Malformed tag")
	ErrTagKeyMalformed = errors.New("Malformed tag key") //@@TODO: Actually put some limits around allowed-charcters for keys
	ErrTagKeyNotFound  = errors.New("Missing tag key")
	ErrTagValNotFound  = errors.New("Missing tag value")
)

func NewTag(rawTag []byte) (Tag, error) {
	parts := bytes.SplitN(rawTag, []byte("="), 2)
	if len(parts) != 2 {
		return Tag{}, ErrTagMalformed
	}
	if len(parts[0]) == 0 {
		return Tag{}, ErrTagKeyNotFound
	}
	if len(parts[0]) > MaxTagKeySize {
		return Tag{}, ErrTagKeyTooBig
	}
	if len(parts[1]) == 0 {
		return Tag{}, ErrTagValNotFound
	}
	if len(parts[1]) > MaxTagValueSize {
		return Tag{}, ErrTagValTooBig
	}

	return Tag{
		parts[0],
		parts[1],
	}, nil
}

// Implements Stringer
func (tag Tag) String() string {
	return string(tag.Key) + "=" + string(tag.Value)
}

func NewTagSet(rawTagSet []byte) (TagSet, error) {
	parts := bytes.Split(rawTagSet, []byte("\n"))
	tagSet := TagSet(make([]Tag, len(parts)))
	for i, rawTag := range parts {
		tag, err := NewTag(rawTag)
		if err != nil {
			return TagSet{}, err
		}
		tagSet[i] = tag
	}
	return tagSet, nil
}

func (tagSet *TagSet) Keys() []string {
	output := make([]string, len(*tagSet), len(*tagSet))
	for i, tag := range *tagSet {
		output[i] = string(tag.Key)
	}
	return output
}

func (tagSet *TagSet) Values() []string {
	output := make([]string, len(*tagSet), len(*tagSet))
	for i, tag := range *tagSet {
		output[i] = string(tag.Value)
	}
	return output
}

func (tagSet *TagSet) Map() map[string]string {
	output := make(map[string]string, len(*tagSet))
	for _, tag := range *tagSet {
		output[string(tag.Key)] = string(tag.Value)
	}
	return output
}

// Implements Stringer
func (tagSet TagSet) String() string {
	var output string
	for i, tag := range tagSet {
		output += tag.String()
		if i != len(tagSet)-1 {
			output += "\n"
		}
	}
	return output
}
