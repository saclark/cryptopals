package set2

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/saclark/cryptopals/cipher"
	"github.com/saclark/cryptopals/internal/testutil"
	"github.com/saclark/cryptopals/pkcs7"
)

func TestChallenge14(t *testing.T) {
	want := testutil.MustBase64DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	for i := 0; i < 20; i++ {
		oracleEncrypt := NewInputSandwichingECBOracle(want)

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

// NewInputSandwichingECBOracle creates an encryption oracle that will prepend
// to it's input the same random count of the same random bytes, as well as
// append to it's input targetPlaintext. It will then encrypt that using AES in
// ECB mode under the same key upon each invocation. An attacker should be able
// to recover targetPlaintext from this oracle.
func NewInputSandwichingECBOracle(targetPlaintext []byte) func([]byte) ([]byte, error) {
	key := testutil.MustRandomBytes(aes.BlockSize)
	n := testutil.MustRandomInt(aes.BlockSize * 2)
	randPrefix := testutil.MustRandomBytes(n)
	return func(input []byte) ([]byte, error) {
		var plaintext []byte
		plaintext = append(plaintext, randPrefix...)
		plaintext = append(plaintext, input...)
		plaintext = append(plaintext, targetPlaintext...)
		plaintext = pkcs7.Pad(plaintext, aes.BlockSize)
		return cipher.ECBEncrypt(plaintext, key)
	}
}
