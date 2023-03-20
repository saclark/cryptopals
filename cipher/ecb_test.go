package cipher

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestECBEncryptThenDecrypt(t *testing.T) {
	tt := []struct {
		plaintext  []byte
		key        []byte
		ciphertext []byte
	}{
		{
			plaintext:  []byte{},
			key:        []byte("0123456789012345"),
			ciphertext: []byte{},
		},
		{
			plaintext:  []byte("YELLOW SUBMARINE"),
			key:        []byte("0123456789012345"),
			ciphertext: hexMustDecodeString("5626f1d6a7a3ee12fdd59cc6448242fe"),
		},
		{
			plaintext:  []byte("0000000000000000111111111111111100000000000000001111111111111111"),
			key:        []byte("0123456789012345"),
			ciphertext: hexMustDecodeString("e6393574e9270c4f885233cad8e87e8500efcba137118fcfdf1d268b0d6cfae1e6393574e9270c4f885233cad8e87e8500efcba137118fcfdf1d268b0d6cfae1"),
		},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%v,%v", tc.plaintext, tc.key), func(t *testing.T) {
			block, err := aes.NewCipher(tc.key)
			if err != nil {
				t.Fatalf("creating cipher: %v", err)
			}

			ecb := NewECB(block)

			encrypted := make([]byte, len(tc.ciphertext))
			decrypted := make([]byte, len(tc.plaintext))

			ecb.Encrypt(encrypted, tc.plaintext)
			if !bytes.Equal(tc.ciphertext, encrypted) {
				t.Fatalf("want encrypted bytes: '%x', got encrypted bytes: '%x'", tc.ciphertext, encrypted)
			}

			ecb.Decrypt(decrypted, encrypted)
			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Fatalf("want decrypted bytes: '%x', got decrypted bytes: '%x'", tc.plaintext, decrypted)
			}
		})
	}
}

func TestECBEncrypt_DstLengthMayExceedSrcLength(t *testing.T) {
	plaintext := []byte("YELLOW SUBMARINE")
	key := []byte("0123456789012345")
	ciphertext := hexMustDecodeString("5626f1d6a7a3ee12fdd59cc6448242fe000000")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("creating cipher: %v", err)
	}

	ecb := NewECB(block)

	encrypted := make([]byte, len(ciphertext))
	ecb.Encrypt(encrypted, plaintext)
	if !bytes.Equal(ciphertext, encrypted) {
		t.Fatalf("want encrypted bytes: '%x', got encrypted bytes: '%x'", ciphertext, encrypted)
	}
}

func TestECBDecrypt_DstLengthMayExceedSrcLength(t *testing.T) {
	plaintext := []byte("YELLOW SUBMARINE\x00\x00\x00\x00\x00\x00")
	key := []byte("0123456789012345")
	ciphertext := hexMustDecodeString("5626f1d6a7a3ee12fdd59cc6448242fe")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("creating cipher: %v", err)
	}

	ecb := NewECB(block)

	decrypted := make([]byte, len(plaintext))
	ecb.Decrypt(decrypted, ciphertext)
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("want decrypted bytes: '%x', got decrypted bytes: '%x'", plaintext, decrypted)
	}
}

func hexMustDecodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
