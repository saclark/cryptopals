package cryptopals

import (
	"encoding/base64"
	"testing"
)

// Convert hex to base64
// See: https://www.cryptopals.com/sets/1/challenges/1
func TestChallenge1(t *testing.T) {
	input := hexMustDecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	got := base64.StdEncoding.EncodeToString(input)
	if want != got {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}
