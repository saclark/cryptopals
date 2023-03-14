package set2

import (
	"bytes"
	"testing"

	"github.com/saclark/cryptopals-go/aes"
)

// Byte-at-a-time ECB decryption (Simple)
// See: https://www.cryptopals.com/sets/2/challenges/12
func TestChallenge12(t *testing.T) {
	want := base64MustDecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	oracleEncrypt, err := NewECBByteAtATimeOracle(want)
	if err != nil {
		t.Fatalf("creating oracle: %v", err)
	}

	got, err := CrackECBByteAtATimeOracle(aes.BlockSize, oracleEncrypt)
	if err != nil {
		t.Fatalf("cracking ECB byte-at-a-time oracle: %v", err)
	}

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}
