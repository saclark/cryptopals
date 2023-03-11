package cryptopals

import (
	"encoding/hex"
	"testing"

	"github.com/saclark/cryptopals-go/xor"
)

// Implement repeating-key XOR
// See: https://www.cryptopals.com/sets/1/challenges/5
func TestChallenge5(t *testing.T) {
	input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	ciphertext := make([]byte, len(input))
	xor.BytesRepeating(ciphertext, input, key)

	got := hex.EncodeToString(ciphertext)
	if want != got {
		t.Errorf("want: '%s'got : '%s'", want, got)
	}
}
