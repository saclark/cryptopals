package aes

import (
	"crypto/aes"
)

// The AES block size in bytes.
const BlockSize = 16

// DecryptECB decrypts a ciphertext encrypted via AES in ECB mode, leaving any
// plaintext padding in-tact. The key argument should be the AES key, either 16,
// 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func DecryptECB(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	k := c.BlockSize()
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i+k <= len(ciphertext); i = i + k {
		c.Decrypt(plaintext[i:i+k], ciphertext[i:i+k])
	}

	return plaintext, nil
}

// DetectECBEncryption returns a number in the range [0, 1] indicating the
// fraction of blocks of the ciphertext that are duplicated. A higher score
// indicates a higher likelihood that the ciphertext was encrypted with ECB.
func DetectECBEncryption(ciphertext []byte) float64 {
	if len(ciphertext) == 0 {
		panic("aes.DetectECBEncryption16: empty ciphertext")
	}
	if len(ciphertext)%BlockSize != 0 {
		panic("aes.DetectECBEncryption16: ciphertext size not a multiple of 16")
	}

	n := len(ciphertext) / BlockSize
	blocks := make(map[[BlockSize]byte]struct{}, n)
	var count int
	for i := 0; i < n; i++ {
		block := [BlockSize]byte(ciphertext[i*BlockSize : (i+1)*BlockSize])
		if _, ok := blocks[block]; ok {
			count++
		} else {
			blocks[block] = struct{}{}
		}
	}

	return float64((count*2*100)/n) / float64(100)
}
