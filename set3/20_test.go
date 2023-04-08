package set3

import (
	"bytes"
	"testing"

	"github.com/saclark/cryptopals/internal/testutil"
)

func TestChallenge20(t *testing.T) {
	wantPlaintexts := testutil.MustBase64DecodeFileLines("data/20.txt")
	ciphertexts := encryptAllWithFixedNonce(wantPlaintexts)

	gotPlaintexts := CrackFixedNonceCTRCiphertextsStatistically(ciphertexts)

	for i, want := range wantPlaintexts {
		got := gotPlaintexts[i]
		if !bytes.Equal(want, got) {
			t.Errorf("want: '%x', got: '%x'", want, got)
		}
	}
}
