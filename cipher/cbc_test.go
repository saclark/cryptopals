package cipher

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"
)

func TestCBCEncryptThenDecrypt(t *testing.T) {
	tt := []struct {
		plaintext  []byte
		key        []byte
		iv         []byte
		ciphertext []byte
	}{
		{
			plaintext:  []byte{},
			key:        []byte("0123456789012345"),
			iv:         []byte("someinitialvalue"),
			ciphertext: []byte{},
		},
		{
			plaintext:  []byte("YELLOW SUBMARINE"),
			key:        []byte("0123456789012345"),
			iv:         []byte("someinitialvalue"),
			ciphertext: hexMustDecodeString("625571765ac245cdc6c30d5acbd8d85b"),
		},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%v,%v,%v", tc.plaintext, tc.key, tc.iv), func(t *testing.T) {
			block, err := aes.NewCipher(tc.key)
			if err != nil {
				t.Fatalf("creating cipher: %v", err)
			}

			cbc := NewCBC(block, tc.iv)

			encrypted := make([]byte, len(tc.ciphertext))
			decrypted := make([]byte, len(tc.plaintext))

			cbc.Encrypt(encrypted, tc.plaintext)
			if !bytes.Equal(tc.ciphertext, encrypted) {
				t.Fatalf("want encrypted bytes: '%x', got encrypted bytes: '%x'", tc.ciphertext, encrypted)
			}

			cbc.Decrypt(decrypted, encrypted)
			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Fatalf("want decrypted bytes: '%x', got decrypted bytes: '%x'", tc.plaintext, decrypted)
			}
		})
	}
}

func TestCBCEncrypt_DstLengthMayExceedSrcLength(t *testing.T) {
	plaintext := []byte("YELLOW SUBMARINE")
	key := []byte("0123456789012345")
	iv := []byte("someinitialvalue")
	ciphertext := hexMustDecodeString("625571765ac245cdc6c30d5acbd8d85b000000")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("creating cipher: %v", err)
	}

	cbc := NewCBC(block, iv)

	encrypted := make([]byte, len(ciphertext))
	cbc.Encrypt(encrypted, plaintext)
	if !bytes.Equal(ciphertext, encrypted) {
		t.Fatalf("want encrypted bytes: '%x', got encrypted bytes: '%x'", ciphertext, encrypted)
	}
}

func TestCBCDecrypt_DstLengthMayExceedSrcLength(t *testing.T) {
	plaintext := []byte("YELLOW SUBMARINE\x00\x00\x00\x00\x00\x00")
	key := []byte("0123456789012345")
	iv := []byte("someinitialvalue")
	ciphertext := hexMustDecodeString("625571765ac245cdc6c30d5acbd8d85b")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("creating cipher: %v", err)
	}

	cbc := NewCBC(block, iv)

	decrypted := make([]byte, len(plaintext))
	cbc.Decrypt(decrypted, ciphertext)
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("want decrypted bytes: '%x', got decrypted bytes: '%x'", plaintext, decrypted)
	}
}
