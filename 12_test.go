package cryptopals

import (
	"bytes"
	"testing"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/exploit"
	"github.com/saclark/cryptopals-go/exploitable"
)

// Byte-at-a-time ECB decryption (Simple)
// See: https://www.cryptopals.com/sets/2/challenges/12
func TestChallenge12(t *testing.T) {
	want := base64MustDecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	encrypt, err := exploitable.NewECBByteAtATimeOracle(want)
	if err != nil {
		t.Fatalf("creating oracle: %v", err)
	}

	got, err := exploit.CrackECBByteAtATimeOracle(aes.BlockSize, encrypt)
	if err != nil {
		t.Fatalf("decrypting unknown plaintext: %v", err)
	}

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}
