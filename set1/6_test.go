package set1

import (
	"bytes"
	"testing"
)

// Break repeating-key XOR
// See: https://www.cryptopals.com/sets/1/challenges/6
func TestChallenge6(t *testing.T) {
	filepath := "data/6.txt"
	want := []byte("Terminator X: Bring the noise")

	got, err := RecoverRepeatingKeyXORFileKey(filepath)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}
