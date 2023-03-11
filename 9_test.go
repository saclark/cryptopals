package cryptopals

import (
	"bytes"
	"testing"

	"github.com/saclark/cryptopals-go/pkcs7"
)

// Implement PKCS#7 padding
// See: https://www.cryptopals.com/sets/2/challenges/9
func TestChallenge9(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	want := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	got := pkcs7.Pad(input, 20)

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%x'got : '%x'", want, got)
	}
}
