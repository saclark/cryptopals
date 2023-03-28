package set1

import (
	"bytes"
	"testing"

	"github.com/saclark/cryptopals-go/internal/testutil"
)

// Single-byte XOR cipher
// See: https://www.cryptopals.com/sets/1/challenges/3
func TestChallenge3(t *testing.T) {
	input := testutil.MustHexDecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	want := []byte("Cooking MC's like a pound of bacon")

	got := CrackSingleByteXOR(input)

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}
