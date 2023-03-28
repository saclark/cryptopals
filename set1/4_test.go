package set1

import (
	"bytes"
	"testing"

	"github.com/saclark/cryptopals-go/internal/testutil"
)

// Detect single-character XOR
// See: https://www.cryptopals.com/sets/1/challenges/4
func TestChallenge4(t *testing.T) {
	want := []byte("Now that the party is jumping\n")
	lines := testutil.MustHexDecodeFileLines("data/4.txt")

	got, err := DetectAndCrackSingleByteXOREncryptedLine(lines)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}
