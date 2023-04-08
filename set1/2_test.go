package set1

import (
	"bytes"
	"testing"

	"github.com/saclark/cryptopals/internal/testutil"
)

// Fixed XOR
// See: https://www.cryptopals.com/sets/1/challenges/2
func TestChallenge2(t *testing.T) {
	x := testutil.MustHexDecodeString("1c0111001f010100061a024b53535009181c")
	y := testutil.MustHexDecodeString("686974207468652062756c6c277320657965")
	want := testutil.MustHexDecodeString("746865206b696420646f6e277420706c6179")

	got := FixedXOR(x, y)

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}
