// # AES in ECB mode
//
// The Base64-encoded content in this file has been encrypted via AES-128 in
// ECB mode under the key
//
// 	"YELLOW SUBMARINE"
//
// (case-sensitive, without the quotes; exactly 16 characters; I like
// "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
//
// Decrypt it. You know the key, after all.
//
// Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
//
// > # Do this with code.
// > You can obviously decrypt this using the OpenSSL command-line tool, but
// > we're having you get ECB working in code for a reason. You'll need it a lot
// > later on, and not just for attacking ECB.

package set1

import (
	"crypto/aes"
	"fmt"

	"github.com/saclark/cryptopals-go/cipher"
)

func AESECBDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	ecb := cipher.NewECB(block)

	plaintext := make([]byte, len(ciphertext))
	ecb.Decrypt(plaintext, ciphertext)

	return plaintext, nil
}
