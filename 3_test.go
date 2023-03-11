package cryptopals

import (
	"testing"

	"github.com/saclark/cryptopals-go/attack"
	"github.com/saclark/cryptopals-go/xor"
)

// Single-byte XOR cipher
// See: https://www.cryptopals.com/sets/1/challenges/3
func TestChallenge3(t *testing.T) {
	input := hexMustDecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	want := "Cooking MC's like a pound of bacon"

	plaintext := make([]byte, len(input))
	key, _ := attack.DetectRepeatingByteXORKey(input)
	xor.BytesRepeatingByte(plaintext, input, key)

	got := string(plaintext)
	if want != got {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}
