package cryptoballot

import (
	"bytes"
	"errors"
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

func NewTag(rawTag []byte) (Tag, error) {
	parts := bytes.SplitN(rawTag, []byte("="), 2)
	if len(parts) != 2 {
		return Tag{}, errors.New("Malformed tag")
	}
	if len(parts[0]) == 0 {
		return Tag{}, errors.New("Mising tag key")
	}
	if len(parts[0]) > MaxTagKeySize {
		return Tag{}, errors.New("Tag key too long")
	}
	if len(parts[1]) == 0 {
		return Tag{}, errors.New("Missing tag value")
	}
	if len(parts[1]) > MaxTagValueSize {
		return Tag{}, errors.New("Tag value too long")
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
