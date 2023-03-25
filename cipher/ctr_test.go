package cipher

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"
)

func TestCTREncryptThenDecrypt(t *testing.T) {
	zeros := make([]byte, 8)
	tt := []struct {
		plaintext  []byte
		key        []byte
		iv         []byte
		ciphertext []byte
	}{
		{
			plaintext:  []byte{},
			key:        []byte("0123456789012345"),
			iv:         append([]byte("nonce123"), zeros...),
			ciphertext: []byte{},
		},
		{
			plaintext:  []byte("A"),
			key:        []byte("0123456789012345"),
			iv:         append([]byte("nonce123"), zeros...),
			ciphertext: hexMustDecodeString("68"),
		},
		{
			plaintext:  []byte("YELLOW SUBMARINE"),
			key:        []byte("0123456789012345"),
			iv:         append([]byte("nonce123"), zeros...),
			ciphertext: hexMustDecodeString("70e76763df28eabe70b763cd4ae50f1a"),
		},
		{
			plaintext:  []byte("YELLOW SUBMARINE 1234"),
			key:        []byte("0123456789012345"),
			iv:         append([]byte("nonce123"), zeros...),
			ciphertext: hexMustDecodeString("70e76763df28eabe70b763cd4ae50f1a9a33581b61"),
		},
	}

	for _, tc := range tt {
		t.Run(fmt.Sprintf("%v,%v,%v", tc.plaintext, tc.key, tc.iv), func(t *testing.T) {
			block, err := aes.NewCipher(tc.key)
			if err != nil {
				t.Fatalf("creating cipher: %v", err)
			}

			encrypted := make([]byte, len(tc.ciphertext))
			decrypted := make([]byte, len(tc.plaintext))

			ctr := NewCTR(block, tc.iv)
			ctr.Crypt(encrypted, tc.plaintext)
			if !bytes.Equal(tc.ciphertext, encrypted) {
				t.Fatalf("want encrypted bytes: '%x', got encrypted bytes: '%x'", tc.ciphertext, encrypted)
			}

			ctr = NewCTR(block, tc.iv)
			ctr.Crypt(decrypted, encrypted)
			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Fatalf("want decrypted bytes: '%x', got decrypted bytes: '%x'", tc.plaintext, decrypted)
			}
		})
	}
}

func TestCTRCrypt_DstLengthMayExceedSrcLength(t *testing.T) {
	plaintext := []byte("YELLOW SUBMARINE")
	key := []byte("0123456789012345")
	iv := append([]byte("nonce123"), make([]byte, 8)...)
	ciphertext := hexMustDecodeString("70e76763df28eabe70b763cd4ae50f1a000000")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("creating cipher: %v", err)
	}

	encrypted := make([]byte, len(ciphertext))
	ctr := NewCTR(block, iv)
	ctr.Crypt(encrypted, plaintext)
	if !bytes.Equal(ciphertext, encrypted) {
		t.Fatalf("want encrypted bytes: '%x', got encrypted bytes: '%x'", ciphertext, encrypted)
	}
}
