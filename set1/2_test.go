package set1

import (
	"bytes"
	"testing"
)

// Fixed XOR
// See: https://www.cryptopals.com/sets/1/challenges/2
func TestChallenge2(t *testing.T) {
	x := hexMustDecodeString("1c0111001f010100061a024b53535009181c")
	y := hexMustDecodeString("686974207468652062756c6c277320657965")
	want := hexMustDecodeString("746865206b696420646f6e277420706c6179")

	got := FixedXOR(x, y)

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}
