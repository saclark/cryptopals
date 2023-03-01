package aes

import (
	"crypto/aes"

	"github.com/saclark/cryptopals-go/xor"
)

// EncryptCBC encrypts a plaintext via AES in CBC mode. It does not add padding.
func EncryptCBC(plaintext, key, iv []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	k := c.BlockSize()
	if len(iv) != k {
		panic("aes.EncryptCBC: iv size not same as block size")
	}

	ciphertext := make([]byte, len(plaintext))
	xored := make([]byte, k)
	prev := iv
	for i := 0; i+k <= len(plaintext); i += k {
		pt := plaintext[i : i+k]
		ct := ciphertext[i : i+k]
		xor.BytesFixed(xored, pt, prev)
		c.Encrypt(ct, xored)
		prev = ct
	}

	return ciphertext, nil
}

// DecryptCBC decrypts a ciphertext via AES in CBC mode. It does not strip
// padding.
func DecryptCBC(ciphertext, key, iv []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	k := c.BlockSize()
	if len(iv) != k {
		panic("aes.DecryptCBC: iv size not same as block size")
	}

	plaintext := make([]byte, len(ciphertext))
	decrypted := make([]byte, k)
	prev := iv
	for i := 0; i+k <= len(ciphertext); i += k {
		ct := ciphertext[i : i+k]
		c.Decrypt(decrypted, ct)
		xor.BytesFixed(plaintext[i:i+k], decrypted, prev)
		prev = ct
	}

	return plaintext, nil
}
