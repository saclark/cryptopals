package set1

import (
	"bytes"
	"testing"
)

// Detect single-character XOR
// See: https://www.cryptopals.com/sets/1/challenges/4
func TestChallenge4(t *testing.T) {
	filepath := "data/4.txt"
	want := []byte("Now that the party is jumping\n")

	got, err := DetectAndCrackSingleByteXOREncryptedLine(filepath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}
