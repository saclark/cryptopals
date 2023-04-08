package set1

import (
	"bytes"
	"testing"

	"github.com/saclark/cryptopals/internal/testutil"
)

// Implement repeating-key XOR
// See: https://www.cryptopals.com/sets/1/challenges/5
func TestChallenge5(t *testing.T) {
	input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")
	want := testutil.MustHexDecodeString("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

	got := RepeatingKeyXOR(input, key)

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%x'got : '%x'", want, got)
	}
}
