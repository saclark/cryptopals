package set2

import (
	"bytes"
	"testing"
)

// Implement PKCS#7 padding
// See: https://www.cryptopals.com/sets/2/challenges/9
func TestChallenge9(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	want := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	got := PKCS7Pad(input, 20)

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%x'got : '%x'", want, got)
	}
}
