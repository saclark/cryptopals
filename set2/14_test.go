package set2

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestChallenge14(t *testing.T) {
	want := base64MustDecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	for i := 0; i < 20; i++ {
		oracleEncrypt, err := NewInputSandwichingECBOracle(want)
		if err != nil {
			t.Fatalf("creating oracle: %v", err)
		}

		got, err := CrackInputSandwichingECBOracle(aes.BlockSize, oracleEncrypt)
		if err != nil {
			t.Errorf("cracking ECB byte-at-a-time oracle: %v", err)
			continue
		}

		if !bytes.Equal(want, got) {
			t.Fatalf("want: '%x', got: '%x'", want, got)
		}
	}
}
