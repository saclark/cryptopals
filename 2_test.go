package cryptopals

import (
	"encoding/hex"
	"testing"

	"github.com/saclark/cryptopals-go/xor"
)

// Fixed XOR
// See: https://www.cryptopals.com/sets/1/challenges/2
func TestChallenge2(t *testing.T) {
	inputA := hexMustDecodeString("1c0111001f010100061a024b53535009181c")
	inputB := hexMustDecodeString("686974207468652062756c6c277320657965")
	want := "746865206b696420646f6e277420706c6179"

	xoredBytes := make([]byte, len(inputA))
	xor.BytesFixed(xoredBytes, inputA, inputB)

	got := hex.EncodeToString(xoredBytes)
	if want != got {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}
