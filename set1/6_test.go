package set1

import (
	"bytes"
	"testing"

	"github.com/saclark/cryptopals-go/internal/testutil"
)

// Break repeating-key XOR
// See: https://www.cryptopals.com/sets/1/challenges/6
func TestChallenge6(t *testing.T) {
	ciphertext := testutil.MustBase64DecodeFile("data/6.txt")
	want := []byte("Terminator X: Bring the noise")

	got := RecoverRepeatingKeyXORKey(ciphertext)

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}
