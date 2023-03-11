package cryptopals

import (
	"os"
	"testing"

	"github.com/saclark/cryptopals-go/attack"
)

// Break repeating-key XOR
// See: https://www.cryptopals.com/sets/1/challenges/6
func TestChallenge6(t *testing.T) {
	inputFile := "data/6.txt"
	want := "Terminator X: Bring the noise"

	b, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatal(err)
	}
	b = base64MustDecodeString(string(b))

	key, _ := attack.DetectRepeatingXORKey(b, 2, 40)

	got := string(key)
	if want != got {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}
