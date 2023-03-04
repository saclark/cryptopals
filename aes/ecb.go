package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// The AES block size in bytes.
const BlockSize = aes.BlockSize

var ErrInputNotMultipleOfBlockSize = errors.New("aes: input not multiple of block size")

// EncryptECB encrypts a plaintext via AES in ECB mode. The key argument should
// be the AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or
// AES-256. The plaintext length must be a multiple of BlockSize.
func EncryptECB(plaintext, key []byte) ([]byte, error) {
	return cryptECB(plaintext, key, func(output, input []byte, c cipher.Block) {
		c.Encrypt(output, input)
	})
}

// DecryptECB decrypts a ciphertext encrypted via AES in ECB mode. The key
// argument should be the AES key, either 16, 24, or 32 bytes to select AES-128,
// AES-192, or AES-256. The ciphertext length must be a multiple of BlockSize.
// Padding is not removed from the returned plaintext.
func DecryptECB(ciphertext, key []byte) ([]byte, error) {
	return cryptECB(ciphertext, key, func(output, input []byte, c cipher.Block) {
		c.Decrypt(output, input)
	})
}

type ecbBlockCrypter func(output, input []byte, c cipher.Block)

func cryptECB(input, key []byte, crypt ecbBlockCrypter) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(input)%BlockSize != 0 {
		return nil, ErrInputNotMultipleOfBlockSize
	}

	output := make([]byte, len(input))
	for i := 0; i+BlockSize <= len(input); i += BlockSize {
		crypt(output[i:i+BlockSize], input[i:i+BlockSize], c)
	}

	return output, nil
}

// DetectECB returns a number in the range [0, 1] indicating the fraction of
// ciphertext blocks that are duplicated. A higher score indicates a higher
// likelihood that the ciphertext was encrypted with ECB. It panics if
// ciphertext is not a multiple of BlockSize.
func DetectECB(ciphertext []byte) float64 {
	if len(ciphertext) == 0 {
		return 0
	}

	if len(ciphertext)%BlockSize != 0 {
		panic("aes.DetectECB: ciphertext size not a multiple of block size")
	}

	n := len(ciphertext) / BlockSize
	uniques := make(map[string]struct{}, n)
	for i := 0; i+BlockSize < len(ciphertext); i += BlockSize {
		uniques[string(ciphertext[i:i+BlockSize])] = struct{}{}
	}

	return float64(n-len(uniques)) / float64(n)
}
