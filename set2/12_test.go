package set2

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/saclark/cryptopals/cipher"
	"github.com/saclark/cryptopals/internal/testutil"
	"github.com/saclark/cryptopals/pkcs7"
)

// Byte-at-a-time ECB decryption (Simple)
// See: https://www.cryptopals.com/sets/2/challenges/12
func TestChallenge12(t *testing.T) {
	want := testutil.MustBase64DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	oracleEncrypt := NewInputAppendingECBOracle(want)

	got, err := CrackInputAppendingECBOracle(aes.BlockSize, oracleEncrypt)
	if err != nil {
		t.Fatalf("cracking ECB byte-at-a-time oracle: %v", err)
	}

	if !bytes.Equal(want, got) {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}

// NewInputAppendingECBOracle creates an encryption oracle that will append
// targetPlaintext to it's input and then encrypt that using AES in ECB mode
// under the same key upon each invocation. An attacker should be able to
// recover targetPlaintext from this oracle.
func NewInputAppendingECBOracle(targetPlaintext []byte) func([]byte) ([]byte, error) {
	key := testutil.MustRandomBytes(aes.BlockSize)
	return func(input []byte) ([]byte, error) {
		plaintext := make([]byte, len(input))
		copy(plaintext, input)
		plaintext = append(plaintext, targetPlaintext...)
		plaintext = pkcs7.Pad(plaintext, aes.BlockSize)
		return cipher.ECBEncrypt(plaintext, key)
	}
}
