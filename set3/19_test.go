package set3

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestChallenge19(t *testing.T) {
	wantPlaintexts := make([][]byte, len(challenge19Base64Plaintexts))
	for i, base64 := range challenge19Base64Plaintexts {
		wantPlaintexts[i] = base64MustDecodeString(base64)
	}
	ciphertexts, err := encryptAllWithFixedNonce(wantPlaintexts, make([]byte, aes.BlockSize))
	if err != nil {
		t.Fatalf("encrypting plaintexts: %v", err)
	}

	gotPlaintexts := CrackFixedNonceCTRWithSubstitution(ciphertexts)

	for i, want := range wantPlaintexts {
		got := gotPlaintexts[i]
		if !bytes.Equal(want, got) {
			t.Errorf("want: '%x', got: '%x'", want, got)
		}
	}
}
