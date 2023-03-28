package set3

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestChallenge20(t *testing.T) {
	const filepath = "data/20.txt"
	wantPlaintexts, err := base64DecodeFileLines(filepath)
	if err != nil {
		t.Fatalf("decoding data file: %v", err)
	}

	ciphertexts, err := encryptAllWithFixedNonce(wantPlaintexts, make([]byte, aes.BlockSize))
	if err != nil {
		t.Fatalf("encrypting plaintexts: %v", err)
	}

	gotPlaintexts := CrackFixedNonceCTRCiphertextsStatistically(ciphertexts)

	for i, want := range wantPlaintexts {
		got := gotPlaintexts[i]
		if !bytes.Equal(want, got) {
			t.Errorf("want: '%x', got: '%x'", want, got)
		}
	}
}
