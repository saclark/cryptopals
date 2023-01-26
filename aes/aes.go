package aes

import (
	"crypto/aes"
)

// DecryptAESECB decrypts a ciphertext encrypted via AES-128 in ECB mode using
// the given key.
func DecryptAESECB(ciphertext []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	k := cipher.BlockSize()
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i+k <= len(ciphertext); i = i + k {
		cipher.Decrypt(plaintext[i:i+k], ciphertext[i:i+k])
	}

	return plaintext, nil
}
