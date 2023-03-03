package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/saclark/cryptopals-go/xor"
)

var ErrInvalidIVSize = errors.New("aes: IV length must equal block size")

// EncryptCBC encrypts a plaintext via AES in CBC mode. The key argument should
// be the AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or
// AES-256. The plaintext length must be a multiple of BlockSize and iv
// length must equal BlockSize.
func EncryptCBC(plaintext, key, iv []byte) ([]byte, error) {
	return cryptCBC(plaintext, key, iv, encryptCBCBlock)
}

func encryptCBCBlock(output, buf, input, prev []byte, c cipher.Block) []byte {
	xor.BytesFixed(buf, input, prev)
	c.Encrypt(output, buf)
	return output
}

// DecryptCBC decrypts a ciphertext via AES in CBC mode. The key argument should
// be the AES key, either 16, 24, or 32 bytes to select AES-128, AES-192, or
// AES-256. The ciphertext length must be a multiple of BlockSize and iv
// length must equal BlockSize. Padding is not removed from the returned
// plaintext.
func DecryptCBC(ciphertext, key, iv []byte) ([]byte, error) {
	return cryptCBC(ciphertext, key, iv, decryptCBCBlock)
}

func decryptCBCBlock(output, buf, input, prev []byte, c cipher.Block) []byte {
	c.Decrypt(buf, input)
	xor.BytesFixed(output, buf, prev)
	return input
}

type cbcBlockCrypter func(output, buf, input, prev []byte, c cipher.Block) []byte

func cryptCBC(input, key, iv []byte, crypt cbcBlockCrypter) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(input)%BlockSize != 0 {
		return nil, ErrInputNotMultipleOfBlockSize
	}
	if len(iv) != BlockSize {
		return nil, ErrInvalidIVSize
	}

	output := make([]byte, len(input))
	buf := make([]byte, BlockSize)
	prev := iv
	for i := 0; i+BlockSize <= len(input); i += BlockSize {
		prev = crypt(output[i:i+BlockSize], buf, input[i:i+BlockSize], prev, c)
	}

	return output, nil
}
