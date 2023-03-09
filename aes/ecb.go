package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

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
