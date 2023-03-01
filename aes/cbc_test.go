package aes

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func hexMustDecodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestEncryptThenDecryptCBC(t *testing.T) {
	tt := []struct {
		plaintext  []byte
		key        []byte
		iv         []byte
		ciphertext []byte
	}{
		{
			plaintext:  []byte("YELLOW SUBMARINE"),
			key:        []byte("0123456789012345"),
			iv:         []byte("0000000000000000"),
			ciphertext: hexMustDecodeString("caf52a46ed2dc49fbafa378facfbcff0"),
		},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%v,%v,%v", tc.plaintext, tc.key, tc.iv), func(t *testing.T) {
			encrypted, err := EncryptCBC(tc.plaintext, tc.key, tc.iv)
			if err != nil {
				t.Fatalf("err encrypting: %v", err)
			}
			if !bytes.Equal(tc.ciphertext, encrypted) {
				t.Fatalf("want encrypted bytes: '%x', got encrypted bytes: '%x'", tc.ciphertext, encrypted)
			}

			decrypted, err := DecryptCBC(encrypted, tc.key, tc.iv)
			if err != nil {
				t.Fatalf("err decrypting: %v", err)
			}
			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Fatalf("want decrypted bytes: '%x', got decrypted bytes: '%x'", tc.plaintext, decrypted)
			}
		})
	}
}
