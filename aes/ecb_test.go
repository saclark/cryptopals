package aes

import (
	"bytes"
	"fmt"
	"testing"
)

func TestEncryptThenDecryptECB(t *testing.T) {
	tt := []struct {
		plaintext  []byte
		key        []byte
		ciphertext []byte
	}{
		{
			plaintext:  []byte("YELLOW SUBMARINE"),
			key:        []byte("0123456789012345"),
			ciphertext: hexMustDecodeString("5626f1d6a7a3ee12fdd59cc6448242fe"),
		},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%v,%v", tc.plaintext, tc.key), func(t *testing.T) {
			encrypted, err := EncryptECB(tc.plaintext, tc.key)
			if err != nil {
				t.Fatalf("err encrypting: %v", err)
			}
			if !bytes.Equal(tc.ciphertext, encrypted) {
				t.Fatalf("want encrypted bytes: '%x', got encrypted bytes: '%x'", tc.ciphertext, encrypted)
			}

			decrypted, err := DecryptECB(encrypted, tc.key)
			if err != nil {
				t.Fatalf("err decrypting: %v", err)
			}
			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Fatalf("want decrypted bytes: '%x', got decrypted bytes: '%x'", tc.plaintext, decrypted)
			}
		})
	}
}
